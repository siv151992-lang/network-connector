import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ago, api, canAdmin } from "../api";
import { useAction } from "../hooks";
import { useAuth, useNetwork } from "../state";
import { Badge, Button, Card, CopyButton, ErrorBox, Field, Input, OnlineDot, PageHeader, Spinner, statusTone } from "../ui";

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="grid grid-cols-3 gap-2 py-2 text-sm">
      <dt className="text-slate-500">{k}</dt>
      <dd className="col-span-2 break-all">{v}</dd>
    </div>
  );
}

export default function DeviceDetail() {
  const { id = "" } = useParams();
  const { current } = useNetwork();
  const { user } = useAuth();
  const nav = useNavigate();
  const nid = current?.id ?? "";
  const q = useQuery({ queryKey: ["device", nid, id], queryFn: () => api.device(nid, id), enabled: !!nid, refetchInterval: 10_000 });
  const d = q.data?.device;
  const admin = canAdmin(current?.role);
  const owner = d?.user_id === user?.id;
  const [name, setName] = useState("");
  const [tags, setTags] = useState<string | null>(null);

  const keys = [["device", nid, id], ["devices"]];
  const action = useAction((a: "approve" | "reject" | "revoke") => api.deviceAction(nid, id, a), keys);
  const update = useAction((b: { name?: string; tags?: string[] }) => api.updateDevice(nid, id, b), keys);
  const remove = useAction(() => api.deleteDevice(nid, id), [["devices"]]);

  if (q.isLoading) return <Spinner />;
  if (!d) return <ErrorBox error={q.error ?? new Error("Device not found")} />;

  const confirmDo = (msg: string, f: () => void) => window.confirm(msg) && f();

  return (
    <>
      <PageHeader
        title={d.name}
        subtitle={d.hostname}
        actions={
          <div className="flex flex-wrap gap-2">
            {admin && (d.status === "pending" || d.status === "rejected") && <Button onClick={() => action.mutate("approve")}>Approve</Button>}
            {admin && d.status === "pending" && <Button variant="secondary" onClick={() => action.mutate("reject")}>Reject</Button>}
            {(admin || owner) && d.status !== "revoked" && (
              <Button variant="danger" onClick={() => confirmDo(`Revoke ${d.name}? It is disconnected immediately and must re-enroll.`, () => action.mutate("revoke"))}>
                Revoke
              </Button>
            )}
            {(admin || owner) && (
              <Button
                variant="ghost"
                onClick={() => confirmDo(`Delete ${d.name}? Its addresses are released.`, () => remove.mutate(undefined, { onSuccess: () => nav("/devices") }))}
              >
                Delete
              </Button>
            )}
          </div>
        }
      />
      <ErrorBox error={action.error ?? update.error ?? remove.error} />
      <div className="mt-4 grid gap-6 lg:grid-cols-2">
        <Card title="Details">
          <dl className="divide-y divide-slate-100 dark:divide-slate-800">
            <Row k="Status" v={<Badge tone={statusTone[d.status]}>{d.status}</Badge>} />
            <Row k="Connection" v={<OnlineDot online={d.online} />} />
            <Row k="Last seen" v={ago(d.last_seen_at)} />
            <Row k="IPv4" v={<span className="font-mono">{d.ipv4}</span>} />
            <Row k="IPv6" v={<span className="font-mono">{d.ipv6}</span>} />
            <Row k="OS" v={`${d.os} ${d.os_version}`.trim() || "—"} />
            <Row k="Client" v={d.client_version || "—"} />
            <Row k="Endpoints" v={d.endpoints.length ? <span className="font-mono text-xs">{d.endpoints.join(", ")}</span> : "—"} />
            <Row k="Key expires" v={d.key_expires_at ? new Date(d.key_expires_at).toLocaleDateString() : "never"} />
            <Row k="Ephemeral" v={d.ephemeral ? "yes (removed on logout)" : "no"} />
            <Row k="WireGuard key" v={<span className="flex items-center gap-2"><span className="font-mono text-xs">{d.node_key}</span><CopyButton text={d.node_key} /></span>} />
          </dl>
        </Card>
        <div className="space-y-6">
          {(admin || owner) && (
            <Card title="Rename">
              <form
                className="flex gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (name) update.mutate({ name }, { onSuccess: () => setName("") });
                }}
              >
                <Input placeholder={d.name} value={name} onChange={(e) => setName(e.target.value.toLowerCase())} aria-label="New name" />
                <Button type="submit" disabled={!name}>Save</Button>
              </form>
              <p className="mt-2 text-xs text-slate-500">Lowercase letters, digits and dashes (used in DNS).</p>
            </Card>
          )}
          {admin && (
            <Card title="Tags">
              <form
                className="space-y-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  const list = (tags ?? "").split(",").map((t) => t.trim()).filter(Boolean);
                  update.mutate({ tags: list }, { onSuccess: () => setTags(null) });
                }}
              >
                <Field label="Comma-separated, e.g. tag:server, tag:web" hint="Tags identify the device in access rules (instead of its owner).">
                  <Input value={tags ?? d.tags.join(", ")} onChange={(e) => setTags(e.target.value)} />
                </Field>
                <Button type="submit" disabled={tags === null}>Save tags</Button>
              </form>
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
