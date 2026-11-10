import { ago } from "../api";
import { useDevices } from "../hooks";
import { Badge, Card, ErrorBox, OnlineDot, PageHeader, Spinner, Table, Td } from "../ui";

/** Live connectivity view: presence comes from devices' control streams. */
export default function Status() {
  const q = useDevices();
  const devices = (q.data ?? []).filter((d) => d.status === "approved");
  const online = devices.filter((d) => d.online).length;
  const expiringSoon = devices.filter((d) => d.key_expires_at && new Date(d.key_expires_at).getTime() - Date.now() < 14 * 86400_000);

  return (
    <>
      <PageHeader title="Network status" subtitle={`${online} of ${devices.length} approved devices online · refreshes every 10 s`} />
      <ErrorBox error={q.error} />
      {expiringSoon.length > 0 && (
        <Card className="mb-6" title="Keys expiring within 14 days">
          <ul className="text-sm">
            {expiringSoon.map((d) => (
              <li key={d.id}>{d.name}: {new Date(d.key_expires_at!).toLocaleDateString()}</li>
            ))}
          </ul>
        </Card>
      )}
      <Card>
        {q.isLoading ? (
          <Spinner />
        ) : (
          <Table head={["Device", "Connection", "Last seen", "Reported endpoints", "Key"]}>
            {devices.map((d) => (
              <tr key={d.id}>
                <Td className="font-medium">{d.name}</Td>
                <Td><OnlineDot online={d.online} /></Td>
                <Td className="text-xs text-slate-500">{ago(d.last_seen_at)}</Td>
                <Td className="font-mono text-xs">{d.endpoints.join(", ") || "—"}</Td>
                <Td>{d.key_expires_at && new Date(d.key_expires_at) < new Date() ? <Badge tone="rose">expired</Badge> : <Badge tone="green">valid</Badge>}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
