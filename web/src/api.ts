// Typed client for the WireMesh control-server API (same origin).
// Session auth is an HttpOnly cookie; mutations also send X-CSRF-Token.

export interface User {
  id: string;
  email: string;
  display_name: string;
  system_role: "admin" | "user";
  email_verified_at?: string;
  totp_enabled: boolean;
  last_login_at?: string;
  disabled_at?: string;
  created_at: string;
}

export type Role = "owner" | "admin" | "member" | "auditor";

export interface Network {
  id: string;
  name: string;
  slug: string;
  ipv4_cidr: string;
  ipv6_cidr: string;
  device_approval_required: boolean;
  key_expiry_days: number;
  created_at: string;
}
export interface NetworkWithRole extends Network {
  role: Role;
}

export type DeviceStatus = "pending" | "approved" | "rejected" | "revoked";

export interface Device {
  id: string;
  network_id: string;
  user_id: string;
  name: string;
  hostname: string;
  os: string;
  os_version: string;
  client_version: string;
  node_key: string;
  ipv4: string;
  ipv6: string;
  status: DeviceStatus;
  ephemeral: boolean;
  tags: string[];
  endpoints: string[];
  key_expires_at?: string;
  last_seen_at?: string;
  approved_at?: string;
  created_at: string;
  online: boolean;
}

export interface Member {
  user_id: string;
  email: string;
  display_name: string;
  role: Role;
  created_at: string;
}

export interface AuthKey {
  id: string;
  prefix: string;
  description: string;
  reusable: boolean;
  ephemeral: boolean;
  preauthorized: boolean;
  tags: string[];
  uses: number;
  expires_at: string;
  revoked_at?: string;
  created_at: string;
}

export interface Session {
  id: string;
  ip?: string;
  user_agent: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  current: boolean;
}

export interface AuditEntry {
  id: number;
  actor_user_id?: string;
  actor_device_id?: string;
  action: string;
  target_type: string;
  target_id: string;
  ip?: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface ACL {
  policy: unknown;
  version: number;
  is_default: boolean;
  updated_at?: string;
}

/** ApiError mirrors the server's {"error": {...}} envelope. */
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public fields?: Record<string, string>,
  ) {
    super(message);
  }
}

let csrfToken = "";
export const setCsrf = (t: string) => {
  csrfToken = t;
};

/** Called on 401 for authenticated requests (set by the auth provider). */
let onUnauthorized: () => void = () => {};
export const setUnauthorizedHandler = (f: () => void) => {
  onUnauthorized = f;
};

export async function request<T>(method: string, path: string, body?: unknown, opts: { quiet401?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch("/api/v1" + path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const e = data?.error ?? {};
    if (res.status === 401 && !opts.quiet401) onUnauthorized();
    throw new ApiError(res.status, e.code ?? "error", e.message ?? res.statusText, e.fields);
  }
  return data as T;
}

const get = <T>(p: string) => request<T>("GET", p);
const post = <T>(p: string, b: unknown = {}) => request<T>("POST", p, b);
const patch = <T>(p: string, b: unknown) => request<T>("PATCH", p, b);
const put = <T>(p: string, b: unknown) => request<T>("PUT", p, b);
const del = (p: string) => request<void>("DELETE", p);

export const api = {
  // auth
  me: () => request<{ user: User; csrf_token: string }>("GET", "/auth/me", undefined, { quiet401: true }),
  login: (email: string, password: string) =>
    request<{ user: User; csrf_token: string; mfa_required: boolean }>("POST", "/auth/login", { email, password }, { quiet401: true }),
  loginMFA: (code: string) => request<{ user: User; csrf_token: string }>("POST", "/auth/login/mfa", { code }, { quiet401: true }),
  logout: () => post<void>("/auth/logout"),
  setup: () => get<{ setup_required: boolean }>("/auth/setup"),
  register: (email: string, password: string, display_name: string) =>
    post<{ status?: string; user?: User }>("/auth/register", { email, password, display_name }),
  verifyEmail: (token: string) => post<{ status: string }>("/auth/verify-email", { token }),
  forgot: (email: string) => post<{ status: string }>("/auth/password/forgot", { email }),
  reset: (token: string, new_password: string) => post<{ status: string }>("/auth/password/reset", { token, new_password }),
  changePassword: (current_password: string, new_password: string) =>
    post<{ other_sessions_revoked: number }>("/auth/password/change", { current_password, new_password }),
  updateMe: (display_name: string) => patch<{ user: User }>("/auth/me", { display_name }),
  sessions: () => get<{ sessions: Session[] }>("/auth/sessions"),
  revokeSession: (id: string) => del(`/auth/sessions/${id}`),
  totpSetup: (password: string) => post<{ secret: string; otpauth_uri: string }>("/auth/mfa/totp/setup", { password }),
  totpEnable: (code: string) => post<{ status: string }>("/auth/mfa/totp/enable", { code }),
  totpDisable: (password: string, code: string) => post<{ status: string }>("/auth/mfa/totp/disable", { password, code }),

  // networks
  networks: () => get<{ networks: NetworkWithRole[] }>("/networks"),
  createNetwork: (name: string) => post<{ network: Network }>("/networks", { name }),
  updateNetwork: (nid: string, b: Partial<Pick<Network, "name" | "device_approval_required" | "key_expiry_days">>) =>
    patch<{ network: Network }>(`/networks/${nid}`, b),
  deleteNetwork: (nid: string) => del(`/networks/${nid}`),
  members: (nid: string) => get<{ members: Member[] }>(`/networks/${nid}/members`),
  addMember: (nid: string, email: string, role: Role) => post(`/networks/${nid}/members`, { email, role }),
  setRole: (nid: string, uid: string, role: Role) => patch(`/networks/${nid}/members/${uid}`, { role }),
  removeMember: (nid: string, uid: string) => del(`/networks/${nid}/members/${uid}`),

  // devices
  devices: (nid: string) => get<{ devices: Device[] }>(`/networks/${nid}/devices`),
  device: (nid: string, did: string) => get<{ device: Device }>(`/networks/${nid}/devices/${did}`),
  updateDevice: (nid: string, did: string, b: { name?: string; tags?: string[] }) => patch<{ device: Device }>(`/networks/${nid}/devices/${did}`, b),
  deviceAction: (nid: string, did: string, action: "approve" | "reject" | "revoke") =>
    post<{ device: Device }>(`/networks/${nid}/devices/${did}/${action}`),
  deleteDevice: (nid: string, did: string) => del(`/networks/${nid}/devices/${did}`),
  authKeys: (nid: string) => get<{ auth_keys: AuthKey[] }>(`/networks/${nid}/auth-keys`),
  createAuthKey: (
    nid: string,
    b: { description: string; reusable: boolean; ephemeral: boolean; preauthorized: boolean; tags: string[]; expires_in_hours: number },
  ) => post<{ auth_key: AuthKey; key: string }>(`/networks/${nid}/auth-keys`, b),
  revokeAuthKey: (nid: string, kid: string) => del(`/networks/${nid}/auth-keys/${kid}`),

  // access control + audit
  acl: (nid: string) => get<ACL>(`/networks/${nid}/acl`),
  putAcl: (nid: string, version: number, policy: unknown) => put<ACL>(`/networks/${nid}/acl`, { version, policy }),
  testAcl: (nid: string, b: { src: string; dst: string; proto: string; port: number; policy?: unknown }) =>
    post<{ allowed: boolean }>(`/networks/${nid}/acl/test`, b),
  audit: (nid: string, before?: number) =>
    get<{ entries: AuditEntry[]; next_before?: number }>(`/networks/${nid}/audit-logs?limit=50${before ? `&before=${before}` : ""}`),

  // system admin
  adminUsers: () => get<{ users: User[]; total: number }>("/admin/users?limit=500"),
  adminCreateUser: (b: { email: string; password: string; display_name: string; system_role: string }) =>
    post<{ user: User }>("/admin/users", b),
  adminUpdateUser: (uid: string, b: { disabled?: boolean; system_role?: string }) => patch<{ user: User }>(`/admin/users/${uid}`, b),
};

export const canAdmin = (r?: Role) => r === "owner" || r === "admin";
export const canViewAll = (r?: Role) => canAdmin(r) || r === "auditor";

/** Human-friendly relative time ("3m ago"). */
export function ago(iso?: string, now = Date.now()): string {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));
