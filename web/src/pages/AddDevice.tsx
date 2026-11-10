import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, canAdmin } from "../api";
import { useAction } from "../hooks";
import { useNetwork } from "../state";
import { Badge, Button, Card, CopyButton, ErrorBox, Field, Input, PageHeader, Select, Table, Td } from "../ui";

export default function AddDevice() {
  const { current } = useNetwork();
  const nid = current?.id ?? "";
  const admin = canAdmin(current?.role);
  const keys = useQuery({ queryKey: ["authkeys", nid], queryFn: () => api.authKeys(nid), enabled: !!nid && admin });
  const [opts, setOpts] = useState({ description: "", reusable: false, ephemeral: false, preauthorized: true, tags: "", expires_in_hours: 24 });
  const [created, setCreated] = useState("");
  const create = useAction(
    () =>
      api.createAuthKey(nid, {
        ...opts,
        tags: opts.tags.split(",").map((t) => t.trim()).filter(Boolean),
      }),
    [["authkeys", nid]],
  );
  const revoke = useAction((kid: string) => api.revokeAuthKey(nid, kid), [["authkeys", nid]]);
  const server = window.location.origin;
  const cmd = `sudo WIREMESH_AUTH_KEY=${created || "<auth key>"} wiremesh up --server ${server}`;

  return (
    <>
      <PageHeader title="Add a device" subtitle="Create an auth key, then run the client on the device." />
      {!admin ? (
        <Card>
          <p className="text-sm">Ask a network admin for an auth key, then run on the device:</p>
          <pre className="mt-3 overflow-x-auto rounded-lg bg-slate-900 p-3 text-xs text-slate-100">{cmd}</pre>
        </Card>
      ) : (
        <div className="grid gap-6 lg:grid-cols-2">
          <Card title="1. Create an auth key">
            <form
              className="space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                create.mutate(undefined, { onSuccess: (r) => setCreated(r.key) });
              }}
            >
              <Field label="Description"><Input value={opts.description} onChange={(e) => setOpts({ ...opts, description: e.target.value })} placeholder="e.g. office laptop" /></Field>
              <Field label="Tags (optional)" hint="e.g. tag:server: devices get these tags instead of your identity">
                <Input value={opts.tags} onChange={(e) => setOpts({ ...opts, tags: e.target.value })} />
              </Field>
              <Field label="Expires in">
                <Select value={opts.expires_in_hours} onChange={(e) => setOpts({ ...opts, expires_in_hours: Number(e.target.value) })}>
                  <option value={1}>1 hour</option>
                  <option value={24}>1 day</option>
                  <option value={168}>7 days</option>
                  <option value={2160}>90 days</option>
                </Select>
              </Field>
              {(["preauthorized", "reusable", "ephemeral"] as const).map((k) => (
                <label key={k} className="flex items-start gap-2 text-sm">
                  <input type="checkbox" className="mt-1" checked={opts[k]} onChange={(e) => setOpts({ ...opts, [k]: e.target.checked })} />
                  <span>
                    <span className="font-medium capitalize">{k}</span>
                    <span className="block text-xs text-slate-500">
                      {k === "preauthorized" && "Devices skip admin approval."}
                      {k === "reusable" && "Can enroll many devices (otherwise single-use)."}
                      {k === "ephemeral" && "Device is deleted when it logs out (CI runners, containers)."}
                    </span>
                  </span>
                </label>
              ))}
              <ErrorBox error={create.error} />
              <Button type="submit" disabled={create.isPending}>Generate key</Button>
            </form>
          </Card>

          <Card title="2. Run on the device">
            {created ? (
              <div className="space-y-3">
                <div className="rounded-lg bg-amber-50 p-3 text-sm text-amber-900 ring-1 ring-amber-200 dark:bg-amber-950/40 dark:text-amber-200 dark:ring-amber-900">
                  Copy this key now. It is shown only once.
                </div>
                <div className="flex items-center gap-2">
                  <code className="flex-1 break-all rounded bg-slate-100 p-2 text-xs dark:bg-slate-800" data-testid="new-auth-key">{created}</code>
                  <CopyButton text={created} />
                </div>
              </div>
            ) : (
              <p className="text-sm text-slate-500">Generate a key first.</p>
            )}
            <p className="mt-4 text-sm font-medium">Linux</p>
            <pre className="mt-1 overflow-x-auto rounded-lg bg-slate-900 p-3 text-xs text-slate-100">{cmd}</pre>
            <p className="mt-2 text-xs text-slate-500">Private keys are generated on the device and never leave it.</p>
          </Card>

          <Card title="Auth keys" className="lg:col-span-2">
            <ErrorBox error={keys.error ?? revoke.error} />
            <Table head={["Key", "Description", "Options", "Uses", "Expires", ""]}>
              {(keys.data?.auth_keys ?? []).map((k) => {
                const dead = !!k.revoked_at || new Date(k.expires_at) < new Date();
                return (
                  <tr key={k.id} className={dead ? "opacity-50" : ""}>
                    <Td className="font-mono text-xs">{k.prefix}…</Td>
                    <Td>{k.description || "—"}</Td>
                    <Td className="space-x-1">
                      {k.preauthorized && <Badge tone="green">pre-approved</Badge>}
                      {k.reusable && <Badge>reusable</Badge>}
                      {k.ephemeral && <Badge>ephemeral</Badge>}
                      {k.tags.map((t) => <Badge key={t} tone="indigo">{t}</Badge>)}
                    </Td>
                    <Td>{k.uses}</Td>
                    <Td className="text-xs">{k.revoked_at ? "revoked" : new Date(k.expires_at).toLocaleString()}</Td>
                    <Td className="text-right">{!dead && <Button variant="ghost" onClick={() => revoke.mutate(k.id)}>Revoke</Button>}</Td>
                  </tr>
                );
              })}
            </Table>
            {keys.data && keys.data.auth_keys.length === 0 && <p className="text-sm text-slate-500">No keys yet.</p>}
          </Card>
        </div>
      )}
    </>
  );
}
