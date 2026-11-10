import { useInfiniteQuery } from "@tanstack/react-query";
import { api, canViewAll } from "../api";
import { useNetwork } from "../state";
import { Button, Card, Empty, ErrorBox, PageHeader, Spinner, Table, Td } from "../ui";

export default function Audit() {
  const { current } = useNetwork();
  const nid = current?.id ?? "";
  const q = useInfiniteQuery({
    queryKey: ["audit", nid],
    queryFn: ({ pageParam }) => api.audit(nid, pageParam || undefined),
    initialPageParam: 0,
    getNextPageParam: (last) => (last.entries.length === 50 ? last.next_before : undefined),
    enabled: !!nid && canViewAll(current?.role),
  });
  if (!canViewAll(current?.role)) return <Empty>Only admins and auditors can view the audit log.</Empty>;
  const entries = q.data?.pages.flatMap((p) => p.entries) ?? [];
  return (
    <>
      <PageHeader title="Audit log" subtitle="Every security-relevant change in this network." />
      <ErrorBox error={q.error} />
      <Card>
        {q.isLoading ? <Spinner /> : (
          <Table head={["Time", "Action", "Target", "Actor", "IP", "Details"]}>
            {entries.map((e) => (
              <tr key={e.id}>
                <Td className="whitespace-nowrap text-xs">{new Date(e.created_at).toLocaleString()}</Td>
                <Td className="font-mono text-xs">{e.action}</Td>
                <Td className="text-xs">{e.target_type} <span className="font-mono text-slate-500">{e.target_id.slice(0, 8)}</span></Td>
                <Td className="font-mono text-xs text-slate-500">{(e.actor_user_id ?? e.actor_device_id ?? "").slice(0, 8)}</Td>
                <Td className="font-mono text-xs">{e.ip ?? ""}</Td>
                <Td className="max-w-xs truncate font-mono text-xs text-slate-500" title={JSON.stringify(e.metadata)}>{JSON.stringify(e.metadata)}</Td>
              </tr>
            ))}
          </Table>
        )}
        {q.hasNextPage && <Button className="mt-4" variant="secondary" onClick={() => q.fetchNextPage()} disabled={q.isFetchingNextPage}>Load more</Button>}
      </Card>
    </>
  );
}
