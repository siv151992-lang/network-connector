import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, canAdmin, Role } from "../api";
import { useAction } from "../hooks";
import { useAuth, useNetwork } from "../state";
import { Badge, Button, Card, ErrorBox, Field, Input, PageHeader, Select, Table, Td } from "../ui";

const roles: Role[] = ["owner", "admin", "member", "auditor"];
const roleHelp: Record<Role, string> = {
  owner: "full control, including deleting the network",
  admin: "manage devices, members, keys and policy",
  member: "add and manage own devices",
  auditor: "read-only: all devices and the audit log",
};

export default function Members() {
  const { current } = useNetwork();
  const { user } = useAuth();
  const nid = current?.id ?? "";
  const admin = canAdmin(current?.role);
  const q = useQuery({ queryKey: ["members", nid], queryFn: () => api.members(nid), enabled: !!nid });
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("member");
  const k = [["members", nid]];
  const add = useAction(() => api.addMember(nid, email, role), k);
  const setR = useAction(({ uid, r }: { uid: string; r: Role }) => api.setRole(nid, uid, r), k);
  const remove = useAction((uid: string) => api.removeMember(nid, uid), [...k, ["devices"]]);

  return (
    <>
      <PageHeader title="Users & roles" subtitle={`Who can use ${current?.name ?? "this network"} and what they may do.`} />
      <ErrorBox error={q.error ?? setR.error ?? remove.error} />
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2" title="Members">
          <Table head={["User", "Role", ""]}>
            {(q.data?.members ?? []).map((m) => (
              <tr key={m.user_id}>
                <Td>
                  <div className="font-medium">{m.display_name || m.email}</div>
                  <div className="text-xs text-slate-500">{m.email}{m.user_id === user?.id && " (you)"}</div>
                </Td>
                <Td>
                  {admin && m.user_id !== user?.id ? (
                    <Select value={m.role} onChange={(e) => setR.mutate({ uid: m.user_id, r: e.target.value as Role })} aria-label={`Role of ${m.email}`}>
                      {roles.map((r) => <option key={r}>{r}</option>)}
                    </Select>
                  ) : (
                    <Badge tone="indigo">{m.role}</Badge>
                  )}
                </Td>
                <Td className="text-right">
                  {(admin || m.user_id === user?.id) && (
                    <Button
                      variant="ghost"
                      onClick={() => window.confirm(m.user_id === user?.id ? "Leave this network? Your devices in it are deleted." : `Remove ${m.email}? Their devices in this network are deleted.`) && remove.mutate(m.user_id)}
                    >
                      {m.user_id === user?.id ? "Leave" : "Remove"}
                    </Button>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
        </Card>
        <div className="space-y-6">
          {admin && (
            <Card title="Add member">
              <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); add.mutate(undefined, { onSuccess: () => setEmail("") }); }}>
                <Field label="Email" hint="The person needs an account first (ask your system admin)."><Input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
                <Field label="Role">
                  <Select value={role} onChange={(e) => setRole(e.target.value as Role)}>
                    {roles.map((r) => <option key={r}>{r}</option>)}
                  </Select>
                </Field>
                <ErrorBox error={add.error} />
                <Button type="submit" disabled={add.isPending}>Add</Button>
              </form>
            </Card>
          )}
          <Card title="Roles">
            <ul className="space-y-2 text-sm">
              {roles.map((r) => <li key={r}><Badge tone="indigo">{r}</Badge> <span className="text-slate-500">{roleHelp[r]}</span></li>)}
            </ul>
          </Card>
        </div>
      </div>
    </>
  );
}
