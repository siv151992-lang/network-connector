import { useState } from "react";
import { Link } from "react-router-dom";
import { ago, api, canAdmin, DeviceStatus } from "../api";
import { useAction, useDevices } from "../hooks";
import { useAuth, useNetwork } from "../state";
import { Badge, Button, Empty, ErrorBox, Input, OnlineDot, PageHeader, Select, Spinner, statusTone, Table, Td } from "../ui";

export default function Devices() {
  const { current } = useNetwork();
  const { user } = useAuth();
  const q = useDevices();
  const [filter, setFilter] = useState<"" | DeviceStatus>("");
  const [search, setSearch] = useState("");
  const act = useAction(({ id, a }: { id: string; a: "approve" | "reject" | "revoke" }) => api.deviceAction(current!.id, id, a), [["devices"]]);
  const admin = canAdmin(current?.role);

  const rows = (q.data ?? []).filter(
    (d) => (!filter || d.status === filter) && (d.name + d.hostname + d.ipv4 + d.tags.join(" ")).toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <>
      <PageHeader
        title="Devices"
        subtitle={admin ? "All devices in this network" : "Your devices in this network"}
        actions={<Link to="/devices/add"><Button>Add device</Button></Link>}
      />
      <div className="mb-4 flex flex-wrap gap-3">
        <Input placeholder="Search name, IP or tag…" value={search} onChange={(e) => setSearch(e.target.value)} className="max-w-xs" />
        <Select value={filter} onChange={(e) => setFilter(e.target.value as DeviceStatus | "")} className="max-w-[12rem]" aria-label="Status filter">
          <option value="">All statuses</option>
          <option value="approved">Approved</option>
          <option value="pending">Pending</option>
          <option value="rejected">Rejected</option>
          <option value="revoked">Revoked</option>
        </Select>
      </div>
      <ErrorBox error={q.error ?? act.error} />
      {q.isLoading ? (
        <Spinner />
      ) : rows.length === 0 ? (
        <Empty>No devices match.</Empty>
      ) : (
        <div className="rounded-xl bg-white shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
          <Table head={["Device", "Addresses", "OS", "Status", "Connection", "Last seen", ""]}>
            {rows.map((d) => (
              <tr key={d.id} data-testid={`device-row-${d.name}`}>
                <Td>
                  <Link to={`/devices/${d.id}`} className="font-medium hover:underline">{d.name}</Link>
                  <div className="text-xs text-slate-500">
                    {d.user_id === user?.id ? "you" : ""} {d.tags.map((t) => <Badge key={t} tone="indigo">{t}</Badge>)}
                  </div>
                </Td>
                <Td className="font-mono text-xs">{d.ipv4}<br /><span className="text-slate-500">{d.ipv6}</span></Td>
                <Td>{d.os || "—"}</Td>
                <Td><Badge tone={statusTone[d.status]}>{d.status}</Badge></Td>
                <Td><OnlineDot online={d.online} /></Td>
                <Td className="text-xs text-slate-500">{ago(d.last_seen_at)}</Td>
                <Td className="text-right">
                  {admin && (d.status === "pending" || d.status === "rejected") && (
                    <Button disabled={act.isPending} onClick={() => act.mutate({ id: d.id, a: "approve" })}>Approve</Button>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
        </div>
      )}
    </>
  );
}
