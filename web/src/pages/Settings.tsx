import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import QRCode from "qrcode";
import { ago, api } from "../api";
import { useAction } from "../hooks";
import { useAuth, useNetwork } from "../state";
import { Badge, Button, Card, ErrorBox, Field, Input, PageHeader, Table, Td } from "../ui";

export default function Settings() {
  return (
    <>
      <PageHeader title="Settings" />
      <div className="grid gap-6 lg:grid-cols-2">
        <Profile />
        <Password />
        <TwoFactor />
        <NetworkSettings />
        <Sessions />
      </div>
    </>
  );
}

function Profile() {
  const { user, refresh } = useAuth();
  const [name, setName] = useState(user?.display_name ?? "");
  const save = useAction(() => api.updateMe(name), []);
  return (
    <Card title="Profile">
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined, { onSuccess: () => void refresh() }); }}>
        <Field label="Email"><Input value={user?.email ?? ""} disabled /></Field>
        <Field label="Display name"><Input value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <ErrorBox error={save.error} />
        <Button type="submit">Save</Button>
      </form>
    </Card>
  );
}

function Password() {
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const change = useAction(() => api.changePassword(cur, next), [["sessions"]]);
  return (
    <Card title="Password">
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); change.mutate(undefined, { onSuccess: () => { setCur(""); setNext(""); } }); }}>
        <Field label="Current password"><Input type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} required /></Field>
        <Field label="New password" hint="At least 10 characters. Your other sessions will be signed out.">
          <Input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required />
        </Field>
        <ErrorBox error={change.error} />
        {change.isSuccess && <p className="text-sm text-emerald-600">Password changed.</p>}
        <Button type="submit">Change password</Button>
      </form>
    </Card>
  );
}

function TwoFactor() {
  const { user, refresh } = useAuth();
  const [pw, setPw] = useState("");
  const [code, setCode] = useState("");
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [qr, setQr] = useState("");
  useEffect(() => {
    if (setup) QRCode.toDataURL(setup.otpauth_uri, { margin: 1, width: 180 }).then(setQr, () => setQr(""));
  }, [setup]);
  const start = useAction(() => api.totpSetup(pw), []);
  const enable = useAction(() => api.totpEnable(code), []);
  const disable = useAction(() => api.totpDisable(pw, code), []);
  const done = () => { setPw(""); setCode(""); setSetup(null); void refresh(); };

  return (
    <Card title="Two-factor authentication" actions={<Badge tone={user?.totp_enabled ? "green" : "amber"}>{user?.totp_enabled ? "on" : "off"}</Badge>}>
      {user?.totp_enabled ? (
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); disable.mutate(undefined, { onSuccess: done }); }}>
          <Field label="Password"><Input type="password" value={pw} onChange={(e) => setPw(e.target.value)} required /></Field>
          <Field label="Current code"><Input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} required /></Field>
          <ErrorBox error={disable.error} />
          <Button variant="danger" type="submit">Turn off</Button>
        </form>
      ) : !setup ? (
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); start.mutate(undefined, { onSuccess: (r) => setSetup(r) }); }}>
          <p className="text-sm text-slate-500">Protect your account with an authenticator app (Google Authenticator, 1Password, Aegis…).</p>
          <Field label="Confirm your password"><Input type="password" value={pw} onChange={(e) => setPw(e.target.value)} required /></Field>
          <ErrorBox error={start.error} />
          <Button type="submit">Set up</Button>
        </form>
      ) : (
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); enable.mutate(undefined, { onSuccess: done }); }}>
          <p className="text-sm">Scan with your app, or enter the secret manually:</p>
          {qr && <img src={qr} alt="TOTP QR code" className="rounded bg-white p-2" />}
          <code className="block break-all rounded bg-slate-100 p-2 text-xs dark:bg-slate-800">{setup.secret}</code>
          <Field label="Code from the app"><Input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} required /></Field>
          <ErrorBox error={enable.error} />
          <Button type="submit">Turn on</Button>
        </form>
      )}
    </Card>
  );
}

function NetworkSettings() {
  const { current } = useNetwork();
  const nav = useNavigate();
  const [name, setName] = useState(current?.name ?? "");
  const [approval, setApproval] = useState(current?.device_approval_required ?? true);
  const [expiry, setExpiry] = useState(current?.key_expiry_days ?? 180);
  useEffect(() => {
    if (current) { setName(current.name); setApproval(current.device_approval_required); setExpiry(current.key_expiry_days); }
  }, [current]);
  const save = useAction(() => api.updateNetwork(current!.id, { name, device_approval_required: approval, key_expiry_days: expiry }), [["networks"]]);
  const del = useAction(() => api.deleteNetwork(current!.id), [["networks"]]);
  if (!current) return null;
  const admin = current.role === "owner" || current.role === "admin";
  return (
    <Card title={`Network: ${current.name}`} actions={<Button variant="ghost" onClick={() => nav("/networks/new")}>New network</Button>}>
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined); }}>
        <Field label="Name"><Input value={name} onChange={(e) => setName(e.target.value)} disabled={!admin} /></Field>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={approval} disabled={!admin} onChange={(e) => setApproval(e.target.checked)} /> New devices need admin approval</label>
        <Field label="Device key expiry (days, 0 = never)"><Input type="number" min={0} max={3650} value={expiry} disabled={!admin} onChange={(e) => setExpiry(Number(e.target.value))} /></Field>
        <ErrorBox error={save.error ?? del.error} />
        {admin && <Button type="submit">Save</Button>}
        {current.role === "owner" && (
          <Button type="button" variant="danger" className="ml-2" onClick={() => window.confirm(`Delete ${current.name} and all its devices? This cannot be undone.`) && del.mutate(undefined, { onSuccess: () => nav("/") })}>
            Delete network
          </Button>
        )}
      </form>
    </Card>
  );
}

function Sessions() {
  const q = useQuery({ queryKey: ["sessions"], queryFn: api.sessions });
  const revoke = useAction((id: string) => api.revokeSession(id), [["sessions"]]);
  return (
    <Card title="Active sessions" className="lg:col-span-2">
      <ErrorBox error={q.error ?? revoke.error} />
      <Table head={["Browser", "IP", "Last active", ""]}>
        {(q.data?.sessions ?? []).map((s) => (
          <tr key={s.id}>
            <Td className="max-w-md truncate text-xs" >{s.user_agent || "unknown"} {s.current && <Badge tone="green">this browser</Badge>}</Td>
            <Td className="font-mono text-xs">{s.ip ?? ""}</Td>
            <Td className="text-xs">{ago(s.last_seen_at)}</Td>
            <Td className="text-right">{!s.current && <Button variant="ghost" onClick={() => revoke.mutate(s.id)}>Sign out</Button>}</Td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}
