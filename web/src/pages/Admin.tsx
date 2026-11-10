import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ago, api } from "../api";
import { useAction } from "../hooks";
import { useAuth } from "../state";
import { Badge, Button, Card, Empty, ErrorBox, Field, Input, PageHeader, Select, Table, Td } from "../ui";

export default function Admin() {
  const { user } = useAuth();
  const q = useQuery({ queryKey: ["admin-users"], queryFn: api.adminUsers, enabled: user?.system_role === "admin" });
  const [f, setF] = useState({ email: "", password: "", display_name: "", system_role: "user" });
  const k = [["admin-users"]];
  const create = useAction(() => api.adminCreateUser(f), k);
  const update = useAction(({ id, b }: { id: string; b: { disabled?: boolean; system_role?: string } }) => api.adminUpdateUser(id, b), k);
  if (user?.system_role !== "admin") return <Empty>System administrators only.</Empty>;

  return (
    <>
      <PageHeader title="Admin" subtitle={`${q.data?.total ?? 0} user accounts on this server`} />
      <ErrorBox error={q.error ?? update.error} />
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2" title="Users">
          <Table head={["User", "Role", "2FA", "Last login", "Status", ""]}>
            {(q.data?.users ?? []).map((u) => (
              <tr key={u.id} className={u.disabled_at ? "opacity-60" : ""}>
                <Td><div className="font-medium">{u.display_name || u.email}</div><div className="text-xs text-slate-500">{u.email}</div></Td>
                <Td>
                  {u.id === user.id ? <Badge tone="indigo">{u.system_role}</Badge> : (
                    <Select value={u.system_role} onChange={(e) => update.mutate({ id: u.id, b: { system_role: e.target.value } })} aria-label={`System role of ${u.email}`}>
                      <option>user</option><option>admin</option>
                    </Select>
                  )}
                </Td>
                <Td>{u.totp_enabled ? <Badge tone="green">on</Badge> : <Badge>off</Badge>}</Td>
                <Td className="text-xs">{ago(u.last_login_at)}</Td>
                <Td>{u.disabled_at ? <Badge tone="rose">disabled</Badge> : <Badge tone="green">active</Badge>}</Td>
                <Td className="text-right">
                  {u.id !== user.id && (
                    <Button variant="ghost" onClick={() => update.mutate({ id: u.id, b: { disabled: !u.disabled_at } })}>
                      {u.disabled_at ? "Enable" : "Disable"}
                    </Button>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
        </Card>
        <Card title="Create user">
          <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); create.mutate(undefined, { onSuccess: () => setF({ email: "", password: "", display_name: "", system_role: "user" }) }); }}>
            <Field label="Email"><Input type="email" required value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></Field>
            <Field label="Name"><Input value={f.display_name} onChange={(e) => setF({ ...f, display_name: e.target.value })} /></Field>
            <Field label="Initial password" hint="At least 10 characters; share it securely."><Input type="password" autoComplete="new-password" required value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></Field>
            <Field label="System role">
              <Select value={f.system_role} onChange={(e) => setF({ ...f, system_role: e.target.value })}><option>user</option><option>admin</option></Select>
            </Field>
            <ErrorBox error={create.error} />
            <Button type="submit" disabled={create.isPending}>Create</Button>
          </form>
        </Card>
      </div>
    </>
  );
}
