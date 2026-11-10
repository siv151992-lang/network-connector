import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, canAdmin, canViewAll } from "../api";
import { useAction, useDevices } from "../hooks";
import { useNetwork } from "../state";
import { Badge, Button, Card, ErrorBox, Field, Input, PageHeader, Select, Spinner, TextArea } from "../ui";

const EXAMPLE = `{
  "groups": { "group:admins": ["you@example.com"] },
  "acls": [
    { "action": "accept", "src": ["group:admins"], "dst": ["*:*"] },
    { "action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"] },
    { "action": "accept", "src": ["autogroup:member"], "dst": ["tag:web:80,443"], "proto": "tcp" }
  ]
}`;

export default function Access() {
  const { current } = useNetwork();
  const nid = current?.id ?? "";
  const admin = canAdmin(current?.role);
  const q = useQuery({ queryKey: ["acl", nid], queryFn: () => api.acl(nid), enabled: !!nid });
  const [text, setText] = useState("");
  const [parseErr, setParseErr] = useState("");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (q.data) setText(JSON.stringify(q.data.policy, null, 2));
  }, [q.data]);

  const save = useAction(
    () => {
      const policy = JSON.parse(text);
      return api.putAcl(nid, q.data!.version, policy);
    },
    [["acl", nid]],
  );

  const parsed = () => {
    try {
      setParseErr("");
      return JSON.parse(text);
    } catch (e) {
      setParseErr(`JSON syntax error: ${(e as Error).message}`);
      return undefined;
    }
  };

  if (q.isLoading) return <Spinner />;
  return (
    <>
      <PageHeader
        title="Access control"
        subtitle="Default-deny rules: anything not accepted is dropped, enforced on each receiving device."
        actions={q.data && <Badge tone={q.data.is_default ? "amber" : "green"}>{q.data.is_default ? "default policy (allow all)" : `version ${q.data.version}`}</Badge>}
      />
      <ErrorBox error={q.error} />
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2" title="Policy" actions={admin && <Button variant="ghost" onClick={() => setText(EXAMPLE)}>Load example</Button>}>
          <TextArea rows={22} value={text} onChange={(e) => { setText(e.target.value); setSaved(false); }} readOnly={!admin} aria-label="Policy JSON" spellCheck={false} />
          {parseErr && <p className="mt-2 text-sm text-rose-600">{parseErr}</p>}
          <div className="mt-3"><ErrorBox error={save.error} /></div>
          {admin && (
            <div className="mt-3 flex items-center gap-3">
              <Button
                disabled={save.isPending}
                onClick={() => parsed() !== undefined && save.mutate(undefined, { onSuccess: () => setSaved(true) })}
              >
                Save policy
              </Button>
              {saved && <span className="text-sm text-emerald-600" data-testid="acl-saved">Saved. Devices receive it within seconds.</span>}
            </div>
          )}
          <p className="mt-4 text-xs text-slate-500">
            Selectors: <code>*</code>, user email, <code>group:x</code>, <code>tag:x</code>, <code>autogroup:member</code>, <code>autogroup:tagged</code>,{" "}
            <code>autogroup:self</code> (dst), host aliases, IPs/CIDRs. Destinations are <code>selector:ports</code> (<code>*</code>, <code>22</code>, <code>80,443</code>, <code>8000-8100</code>).
          </p>
        </Card>
        {canViewAll(current?.role) && <Tester nid={nid} draft={parsed} />}
      </div>
    </>
  );
}

function Tester({ nid, draft }: { nid: string; draft: () => unknown }) {
  const devices = useDevices();
  const approved = (devices.data ?? []).filter((d) => d.status === "approved");
  const [f, setF] = useState({ src: "", dst: "", proto: "tcp", port: 22 });
  const [useDraft, setUseDraft] = useState(true);
  const test = useAction(() => {
    const policy = useDraft ? draft() : undefined;
    return api.testAcl(nid, { ...f, policy });
  }, []);
  return (
    <Card title="Test access">
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); test.mutate(undefined); }}>
        {(["src", "dst"] as const).map((k) => (
          <Field key={k} label={k === "src" ? "From" : "To"}>
            <Select value={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })} required aria-label={k === "src" ? "From device" : "To device"}>
              <option value="">Choose a device…</option>
              {approved.map((d) => <option key={d.id} value={d.name}>{d.name} ({d.ipv4})</option>)}
            </Select>
          </Field>
        ))}
        <div className="grid grid-cols-2 gap-2">
          <Field label="Protocol">
            <Select value={f.proto} onChange={(e) => setF({ ...f, proto: e.target.value })}>
              <option>tcp</option><option>udp</option><option>icmp</option>
            </Select>
          </Field>
          <Field label="Port"><Input type="number" min={0} max={65535} value={f.port} disabled={f.proto === "icmp"} onChange={(e) => setF({ ...f, port: Number(e.target.value) })} /></Field>
        </div>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={useDraft} onChange={(e) => setUseDraft(e.target.checked)} /> Test the editor contents (unsaved)</label>
        <Button type="submit" disabled={test.isPending}>Test</Button>
        <ErrorBox error={test.error} />
        {test.data && (
          <div data-testid="acl-test-result" className={`rounded-lg p-3 text-sm font-medium ${test.data.allowed ? "bg-emerald-50 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300" : "bg-rose-50 text-rose-800 dark:bg-rose-950/40 dark:text-rose-300"}`}>
            {test.data.allowed ? "Allowed" : "Blocked"}
          </div>
        )}
      </form>
    </Card>
  );
}
