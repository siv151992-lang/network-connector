import { Link } from "react-router-dom";
import { ago, canAdmin } from "../api";
import { useDevices } from "../hooks";
import { useNetwork } from "../state";
import { Badge, Button, Card, ErrorBox, OnlineDot, PageHeader, Spinner, statusTone } from "../ui";

function Stat({ label, value, tone }: { label: string; value: number | string; tone?: string }) {
  return (
    <Card>
      <div className="text-sm text-slate-500">{label}</div>
      <div className={`mt-1 text-3xl font-semibold ${tone ?? ""}`} data-testid={`stat-${label.toLowerCase().replace(/\s+/g, "-")}`}>
        {value}
      </div>
    </Card>
  );
}

export default function Overview() {
  const { current } = useNetwork();
  const q = useDevices();
  const devices = q.data ?? [];
  const pending = devices.filter((d) => d.status === "pending");
  const online = devices.filter((d) => d.online && d.status === "approved");

  return (
    <>
      <PageHeader
        title={current?.name ?? "Overview"}
        subtitle={current ? `${current.ipv4_cidr} · ${current.ipv6_cidr} · your role: ${current.role}` : undefined}
        actions={<Link to="/devices/add"><Button>Add device</Button></Link>}
      />
      <ErrorBox error={q.error} />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Devices" value={devices.length} />
        <Stat label="Online" value={online.length} tone="text-emerald-600" />
        <Stat label="Pending approval" value={pending.length} tone={pending.length ? "text-amber-600" : ""} />
        <Stat label="Approval required" value={current?.device_approval_required ? "Yes" : "No"} />
      </div>

      {pending.length > 0 && canAdmin(current?.role) && (
        <Card className="mt-6" title="Waiting for approval">
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">
            {pending.map((d) => (
              <li key={d.id} className="flex items-center justify-between py-2 text-sm">
                <span>{d.name} <span className="text-slate-500">({d.os || "unknown OS"}, {d.ipv4})</span></span>
                <Link className="text-indigo-600" to={`/devices/${d.id}`}>Review →</Link>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card className="mt-6" title="Recently active">
        {q.isLoading ? (
          <Spinner />
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">
            {[...devices]
              .sort((a, b) => (b.last_seen_at ?? "").localeCompare(a.last_seen_at ?? ""))
              .slice(0, 8)
              .map((d) => (
                <li key={d.id} className="grid grid-cols-[minmax(0,1fr)_6rem_5rem_5rem] items-center gap-3 py-2 text-sm sm:grid-cols-[minmax(0,1fr)_8rem_6rem_5rem_5rem]">
                  <Link to={`/devices/${d.id}`} className="truncate font-medium hover:underline">{d.name}</Link>
                  <span className="hidden font-mono text-xs text-slate-500 sm:block">{d.ipv4}</span>
                  <span><Badge tone={statusTone[d.status]}>{d.status}</Badge></span>
                  <OnlineDot online={d.online} />
                  <span className="text-right text-xs text-slate-500">{ago(d.last_seen_at)}</span>
                </li>
              ))}
            {devices.length === 0 && <li className="py-2 text-sm text-slate-500">No devices yet. <Link className="text-indigo-600" to="/devices/add">Add your first device</Link>.</li>}
          </ul>
        )}
      </Card>
    </>
  );
}
