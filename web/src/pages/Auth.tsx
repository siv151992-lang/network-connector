import { FormEvent, ReactNode, useEffect, useRef, useState } from "react";
import { Link, Navigate, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { api, ApiError, setCsrf } from "../api";
import { useAuth } from "../state";
import { Button, ErrorBox, Field, Input } from "../ui";

function Shell({ title, children, footer }: { title: string; children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="grid min-h-screen place-items-center p-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center justify-center gap-2 text-xl font-semibold">
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-indigo-600 text-white">W</span> WireMesh
        </div>
        <div className="rounded-xl bg-white p-6 shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
          <h1 className="mb-4 text-lg font-semibold">{title}</h1>
          {children}
        </div>
        {footer && <div className="mt-4 text-center text-sm text-slate-500">{footer}</div>}
      </div>
    </div>
  );
}

export function Login() {
  const { user, signedIn } = useAuth();
  const nav = useNavigate();
  const loc = useLocation() as { state?: { from?: string } };
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfa, setMfa] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  if (user) return <Navigate to={loc.state?.from ?? "/"} replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      if (!mfa) {
        const r = await api.login(email, password);
        if (r.mfa_required) {
          setCsrf(r.csrf_token); // partial session: only the MFA step is allowed
          setMfa(true);
          return;
        }
        signedIn(r.user, r.csrf_token);
      } else {
        const r = await api.loginMFA(code);
        signedIn(r.user, r.csrf_token);
      }
      nav(loc.state?.from ?? "/", { replace: true });
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Shell
      title={mfa ? "Two-factor authentication" : "Sign in"}
      footer={
        <>
          <Link className="text-indigo-600" to="/forgot-password">Forgot password?</Link> · <Link className="text-indigo-600" to="/register">Create account</Link>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-4">
        {!mfa ? (
          <>
            <Field label="Email"><Input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
            <Field label="Password"><Input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
          </>
        ) : (
          <Field label="6-digit code from your authenticator app">
            <Input inputMode="numeric" autoComplete="one-time-code" autoFocus required value={code} onChange={(e) => setCode(e.target.value)} />
          </Field>
        )}
        <ErrorBox error={err} />
        <Button type="submit" disabled={busy} className="w-full">{mfa ? "Verify" : "Sign in"}</Button>
      </form>
    </Shell>
  );
}

export function Register() {
  const [form, setForm] = useState({ email: "", password: "", name: "" });
  const [err, setErr] = useState<unknown>(null);
  const [done, setDone] = useState("");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    try {
      const r = await api.register(form.email, form.password, form.name);
      setDone(r.user ? "Account created. You can sign in now." : "Check your inbox for a link to verify your email address.");
    } catch (e) {
      setErr(e);
    }
  };
  const fields = err instanceof ApiError ? err.fields : undefined;
  return (
    <Shell title="Create account" footer={<Link className="text-indigo-600" to="/login">Back to sign in</Link>}>
      {done ? (
        <p className="text-sm">{done}</p>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <Field label="Name"><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
          <Field label="Email" error={fields?.email}><Input type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></Field>
          <Field label="Password" error={fields?.password} hint="At least 10 characters">
            <Input type="password" autoComplete="new-password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          </Field>
          {!fields && <ErrorBox error={err} />}
          <Button type="submit" className="w-full">Create account</Button>
        </form>
      )}
    </Shell>
  );
}

/** Opened from the email link; the token is POSTed (never consumed by a GET). */
export function VerifyEmail() {
  const [params] = useSearchParams();
  const [state, setState] = useState<"working" | "ok" | Error>("working");
  const once = useRef(false);
  useEffect(() => {
    if (once.current) return;
    once.current = true;
    api.verifyEmail(params.get("token") ?? "").then(() => setState("ok"), (e) => setState(e));
  }, [params]);
  return (
    <Shell title="Verify email" footer={<Link className="text-indigo-600" to="/login">Go to sign in</Link>}>
      {state === "working" ? <p className="text-sm">Verifying…</p> : state === "ok" ? <p className="text-sm">Your email is verified. You can sign in.</p> : <ErrorBox error={state} />}
    </Shell>
  );
}

export function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  return (
    <Shell title="Reset password" footer={<Link className="text-indigo-600" to="/login">Back to sign in</Link>}>
      {sent ? (
        <p className="text-sm">If an account exists for that address, a reset link is on its way.</p>
      ) : (
        <form
          className="space-y-4"
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              await api.forgot(email);
              setSent(true);
            } catch (e) {
              setErr(e);
            }
          }}
        >
          <Field label="Email"><Input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
          <ErrorBox error={err} />
          <Button type="submit" className="w-full">Send reset link</Button>
        </form>
      )}
    </Shell>
  );
}

export function ResetPassword() {
  const [params] = useSearchParams();
  const [pw, setPw] = useState("");
  const [done, setDone] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  return (
    <Shell title="Choose a new password" footer={<Link className="text-indigo-600" to="/login">Back to sign in</Link>}>
      {done ? (
        <p className="text-sm">Password changed. All sessions were signed out; sign in with the new password.</p>
      ) : (
        <form
          className="space-y-4"
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              await api.reset(params.get("token") ?? "", pw);
              setDone(true);
            } catch (e) {
              setErr(e);
            }
          }}
        >
          <Field label="New password" hint="At least 10 characters">
            <Input type="password" autoComplete="new-password" required value={pw} onChange={(e) => setPw(e.target.value)} />
          </Field>
          <ErrorBox error={err} />
          <Button type="submit" className="w-full">Set password</Button>
        </form>
      )}
    </Shell>
  );
}
