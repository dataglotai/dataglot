import { useEffect, useState } from "react";

import { type ControlPlaneView, getControlPlane } from "./api";

/** Slow poll — control-plane state only changes on DDL, so this is a gentle
 *  refresh, not a live feed. */
const POLL_MS = 5000;

/** A titled section with a count; renders a muted "none" when empty. */
function Section({
  title,
  count,
  children,
}: {
  title: string;
  count: number;
  children: React.ReactNode;
}) {
  return (
    <div style={{ marginBottom: 22 }}>
      <div className="section-h">
        {title} ({count})
      </div>
      {count === 0 ? (
        <p className="muted">none</p>
      ) : (
        <div className="tbl-wrap">{children}</div>
      )}
    </div>
  );
}

/** The Control Plane tab: a read-only view of what the running server
 *  has persisted in its meta store — catalogs, secrets (names only), users,
 *  roles, grants, policies, and derived products. Mutations happen via SQL DDL,
 *  not here. When no `catalog_service` is configured the endpoint 404s and this
 *  renders a "not configured" note. */
export function ControlPlane() {
  const [view, setView] = useState<ControlPlaneView | null>(null);
  const [notConfigured, setNotConfigured] = useState(false);

  useEffect(() => {
    let stop = false;
    const ctrl = new AbortController();
    const tick = async () => {
      if (stop) return;
      try {
        const v = await getControlPlane(ctrl.signal);
        setView(v);
        setNotConfigured(false);
      } catch {
        // No route / read failure. Only flip to the "not configured" state on
        // the first miss; otherwise keep the last good snapshot on screen.
        setView((prev) => {
          if (prev === null) setNotConfigured(true);
          return prev;
        });
      }
    };
    void tick();
    const id = setInterval(() => void tick(), POLL_MS);
    return () => {
      stop = true;
      ctrl.abort();
      clearInterval(id);
    };
  }, []);

  if (notConfigured) {
    return (
      <div className="empty">
        <p>No control plane configured.</p>
        <p className="muted">
          Runtime catalogs, secrets, users, roles, grants, and policies are
          stored in the meta store, enabled by setting <code>catalog_service</code>{" "}
          (an embedded <code>path</code> or a Postgres <code>dsn</code>). Without
          it, catalogs come from static boot config only.
        </p>
      </div>
    );
  }

  if (!view) {
    return (
      <div className="empty">
        <p className="muted">Loading control plane…</p>
      </div>
    );
  }

  return (
    <div>
      <Section title="Catalogs" count={view.catalogs.length}>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Kind</th>
              <th>Endpoint</th>
            </tr>
          </thead>
          <tbody>
            {view.catalogs.map((c) => (
              <tr key={c.name}>
                <td className="mono">{c.name}</td>
                <td>
                  <span className="chip">{c.kind}</span>
                </td>
                <td className="mono">{c.endpoint || <span className="muted">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Secrets" count={view.secrets.length}>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            {view.secrets.map((name) => (
              <tr key={name}>
                <td className="mono">{name}</td>
                <td>
                  <span className="chip">encrypted</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Users" count={view.users.length}>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Role</th>
            </tr>
          </thead>
          <tbody>
            {view.users.map((u) => (
              <tr key={u.name}>
                <td className="mono">{u.name}</td>
                <td>
                  {u.is_superuser ? (
                    <span className="chip">superuser</span>
                  ) : (
                    <span className="muted">user</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Roles" count={view.roles.length}>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Members</th>
            </tr>
          </thead>
          <tbody>
            {view.roles.map((r) => (
              <tr key={r.name}>
                <td className="mono">{r.name}</td>
                <td className="mono">
                  {r.members.length ? r.members.join(", ") : <span className="muted">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Grants" count={view.grants.length}>
        <table>
          <thead>
            <tr>
              <th>Grantee</th>
              <th>Privilege</th>
              <th>On</th>
            </tr>
          </thead>
          <tbody>
            {view.grants.map((g, i) => (
              <tr key={`${g.grantee_kind}:${g.grantee}:${g.privilege}:${g.object}:${i}`}>
                <td>
                  <span className="chip">{g.grantee_kind}</span>{" "}
                  <span className="mono">{g.grantee}</span>
                </td>
                <td className="mono">{g.privilege}</td>
                <td className="mono">{g.object}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Policies" count={view.policies.length}>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Kind</th>
            </tr>
          </thead>
          <tbody>
            {view.policies.map((p) => (
              <tr key={p.name}>
                <td className="mono">{p.name}</td>
                <td>
                  <span className="chip">{p.kind}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Derived products" count={view.derived_products.length}>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Target</th>
            </tr>
          </thead>
          <tbody>
            {view.derived_products.map((p) => (
              <tr key={p.name}>
                <td className="mono">{p.name}</td>
                <td className="mono">
                  {p.catalog || p.schema ? (
                    `${p.catalog ?? "—"}.${p.schema ?? "—"}`
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </div>
  );
}
