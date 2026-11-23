//! Minimal S3 calls for object-store test fixtures.
//!
//! Replaces the `minio/mc` sidecar container the fixtures used to boot just
//! to run `mc mb`. MinIO withdrew `minio/mc` from Docker Hub on
//! 2026-09-13 and closed `quay.io/minio/mc` to unauthenticated pulls, so
//! that container became unpullable — on the RustFS path too, since `mc`
//! speaks generic S3 and both backends used it.
//!
//! Creating a bucket is one `PUT /{bucket}`, so the replacement is a signed
//! request rather than another container: one less image to pull, one less
//! Docker network to join, and no dependency on a vendor's registry policy.
//!
//! Scope is deliberately "what the fixtures need". This is not an S3 client:
//! no retries, no pagination, no virtual-host addressing, no streaming
//! payloads. Reach for `aws-sdk-s3` if a test ever needs more than this.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

/// SigV4 requires *some* region even for servers that ignore it.
const REGION: &str = "us-east-1";
const SERVICE: &str = "s3";
/// SHA-256 of the empty string — the payload hash for a bodyless request.
const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn hmac_sha256(key: &[u8], msg: &str) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(msg.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// `YYYYMMDDTHHMMSSZ` / `YYYYMMDD` for the SigV4 date headers.
///
/// Hand-rolled from `SystemTime` rather than pulling in `chrono`/`time`:
/// SigV4 wants UTC with no timezone or locale handling, which is just
/// days-since-epoch run through the civil-date conversion below.
fn amz_date() -> (String, String) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // Howard Hinnant's civil_from_days, the standard integer algorithm for
    // turning a day count into a calendar date without a date library.
    let z = i64::try_from(days).expect("day count fits in i64") + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_civil = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m_civil <= 2);

    (
        format!("{y:04}{m_civil:02}{d:02}T{h:02}{m:02}{s:02}Z"),
        format!("{y:04}{m_civil:02}{d:02}"),
    )
}

/// How long a single S3 call may take before the fixture gives up.
///
/// `reqwest::Client` has no default request timeout, so without this a
/// store that accepts the connection and never replies hangs the test — and
/// a hung test does not fail, it just burns the CI job's wall clock until
/// the runner kills it with no useful output.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// HTTP client for the S3 calls below.
///
/// `no_proxy` because every endpoint here is a loopback test container: a
/// machine with `HTTP_PROXY` set — a corporate laptop, some CI images —
/// would otherwise route `127.0.0.1` through the proxy and fail or hang on
/// something that has nothing to do with the test.
fn client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .no_proxy()
            .build()
            .expect("reqwest client builds")
    })
}

/// The authority (`host[:port]`) of `endpoint`, or `Err` if the endpoint
/// carries a path prefix.
///
/// SigV4 signs both the `Host` header and the canonical URI, and this module
/// builds the canonical URI as `/{bucket}`. An endpoint like
/// `http://127.0.0.1:9000/s3` would therefore send `PUT /s3/{bucket}` while
/// signing `PUT /{bucket}` — the request would be rejected with a `403` that
/// says nothing about which signed field disagreed.
///
/// Rather than silently truncating the prefix (which produces exactly that
/// 403) or signing it (support we could not exercise, since every fixture
/// endpoint comes from `testcontainers` as a bare `host:port`), prefixed
/// endpoints are refused by name. Untested support is worse than an honest
/// refusal: one fails at the call site with an explanation, the other fails
/// inside a stranger's e2e with a status code.
fn authority(endpoint: &str) -> Result<&str, String> {
    let authority = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    match authority.split_once('/') {
        None => Ok(authority),
        Some((host, prefix)) => Err(format!(
            "endpoint `{endpoint}` has a path prefix (`/{prefix}`). This helper \
             signs the canonical URI as `/<bucket>`, so a prefixed endpoint would \
             send `/{prefix}/<bucket>` and be rejected with an opaque 403. Pass \
             `http://{host}` instead, or teach `create_bucket` to sign the prefix."
        )),
    }
}

/// Create a bucket on an S3-compatible endpoint, path-style.
///
/// Idempotent in practice: RustFS answers `200` when the bucket already
/// exists, and AWS-compatible stores answer `BucketAlreadyOwnedByYou`, which
/// is accepted here. That matches the `mc mb --ignore-existing` semantics the
/// fixtures relied on, so a fixture re-run against a warm container behaves
/// the same as against a cold one.
///
/// # Panics
/// Panics with the endpoint, status and body on any other failure — these
/// are test fixtures, and a bucket that does not exist fails every
/// assertion that follows in a much more confusing way.
pub async fn create_bucket(endpoint: &str, bucket: &str, access_key: &str, secret_key: &str) {
    let endpoint = endpoint.trim_end_matches('/');
    let host = authority(endpoint)
        .unwrap_or_else(|e| panic!("{e}"))
        .to_string();
    let (amz_datetime, date_stamp) = amz_date();

    // Canonical request. Header order must match `signed_headers`, and both
    // must be lowercase and sorted — SigV4 signs the exact bytes below.
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "PUT\n/{bucket}\n\nhost:{host}\nx-amz-content-sha256:{EMPTY_PAYLOAD_SHA256}\n\
         x-amz-date:{amz_datetime}\n\n{signed_headers}\n{EMPTY_PAYLOAD_SHA256}"
    );
    let scope = format!("{date_stamp}/{REGION}/{SERVICE}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_datetime}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );

    // The four-step derivation: date, region, service, terminator — each
    // HMAC keyed by the previous step's output.
    let signing_key = [date_stamp.as_str(), REGION, SERVICE, "aws4_request"]
        .iter()
        .fold(format!("AWS4{secret_key}").into_bytes(), |key, part| {
            hmac_sha256(&key, part)
        });
    let signature = hex(&hmac_sha256(&signing_key, &string_to_sign));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let response = client()
        .put(format!("{endpoint}/{bucket}"))
        .header("host", &host)
        .header("x-amz-date", &amz_datetime)
        .header("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256)
        .header("authorization", authorization)
        .send()
        .await
        .unwrap_or_else(|e| panic!("PUT {endpoint}/{bucket} could not be sent: {e}"));

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    // `BucketAlreadyOwnedByYou` is the AWS-compatible "you already made
    // this" answer and RustFS simply returns 200. `BucketAlreadyExists` is
    // accepted too, because some S3 implementations use it for the same
    // case — but note the semantics differ on real AWS, where it means
    // *someone else* owns the name. That distinction cannot arise here: the
    // endpoint is a throwaway container this process just started, so there
    // is no other owner. Do not copy this acceptance into non-fixture code.
    assert!(
        status.is_success()
            || body.contains("BucketAlreadyOwnedByYou")
            || body.contains("BucketAlreadyExists"),
        "creating bucket `{bucket}` on {endpoint} failed: HTTP {status}\n{body}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signing chain must match AWS's published SigV4 test vector, or
    /// every request is rejected with an opaque 403. Values are from the
    /// AWS documentation's `AWS4-HMAC-SHA256` signing-key example.
    #[test]
    fn signing_key_matches_the_aws_published_vector() {
        let key = ["20150830", "us-east-1", "iam", "aws4_request"]
            .iter()
            .fold(
                b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_vec(),
                |k, part| hmac_sha256(&k, part),
            );
        assert_eq!(
            hex(&key),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    /// `amz_date` must produce the two formats SigV4 requires, and they must
    /// agree — the date stamp is the datetime's first eight characters. A
    /// mismatch produces a signature that verifies against nothing.
    #[test]
    fn amz_date_formats_agree_and_are_well_formed() {
        let (datetime, stamp) = amz_date();
        assert_eq!(datetime.len(), 16, "{datetime}");
        assert_eq!(stamp.len(), 8, "{stamp}");
        assert!(
            datetime.ends_with('Z') && datetime[8..9].eq("T"),
            "{datetime}"
        );
        assert_eq!(&datetime[..8], stamp);
        // Sanity-check the civil-date conversion against a known-good floor
        // rather than asserting a fixed date, which would expire.
        assert!(
            stamp.as_str() >= "20260101",
            "clock or conversion is wrong: {stamp}"
        );
    }

    /// A wrong `Host` fails as an opaque 403, so the cases that could
    /// produce one are pinned here rather than discovered in an e2e.
    #[test]
    fn authority_is_host_and_port_only() {
        for (endpoint, want) in [
            ("http://127.0.0.1:9000", "127.0.0.1:9000"),
            ("https://127.0.0.1:9000", "127.0.0.1:9000"),
            // Hostnames, not just addresses (testcontainers hands back both).
            ("http://rustfs:9000", "rustfs:9000"),
            // No scheme at all.
            ("127.0.0.1:9000", "127.0.0.1:9000"),
        ] {
            assert_eq!(authority(endpoint), Ok(want), "endpoint {endpoint}");
        }
    }

    /// A path prefix must be refused, not truncated.
    ///
    /// Truncating looks like it works and then fails as a 403 that names
    /// nothing, because the canonical URI is signed as `/<bucket>` while the
    /// request goes to `/<prefix>/<bucket>`. An earlier version of this
    /// helper silently truncated, and its test asserted that truncation was
    /// correct — a test documenting support that did not exist.
    #[test]
    fn path_prefixed_endpoints_are_refused() {
        for endpoint in ["http://127.0.0.1:9000/s3", "http://minio.example.com/a/b/c"] {
            let err = authority(endpoint).expect_err("prefixed endpoint must be refused");
            assert!(err.contains("path prefix"), "unhelpful message: {err}");
            assert!(
                err.contains(endpoint),
                "message must name the endpoint: {err}"
            );
        }
    }

    /// The empty-payload constant is load-bearing: it appears twice in the
    /// canonical request and once as a header, and a wrong value fails only
    /// at the server with a 403.
    #[test]
    fn empty_payload_hash_is_sha256_of_nothing() {
        assert_eq!(hex(&Sha256::digest(b"")), EMPTY_PAYLOAD_SHA256);
    }
}
