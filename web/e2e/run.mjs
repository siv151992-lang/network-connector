// End-to-end test: real control server + PostgreSQL + built dashboard in Chromium.
//
//   WIREMESH_TEST_DATABASE_URL=postgres://postgres@localhost:5432/postgres npm run e2e
//
// Devices are simulated at the protocol level (registration over REST and a
// real WebSocket control stream), so "online" status is genuine presence.
import { spawn, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import WebSocket from "ws";

// Playwright is resolved like require() (works with a global install via
// NODE_PATH, or `npm i -D playwright` + `npx playwright install chromium`).
const { chromium } = createRequire(import.meta.url)("playwright");

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const art = process.env.E2E_ARTIFACTS ?? path.join(here, ".artifacts");
mkdirSync(art, { recursive: true });

const ADMIN_DB = process.env.WIREMESH_TEST_DATABASE_URL;
if (!ADMIN_DB) throw new Error("set WIREMESH_TEST_DATABASE_URL");
const dbName = `wm_web_e2e_${process.pid}`;
const API_PORT = 18095, WEB_PORT = 4173;
const API = `http://127.0.0.1:${API_PORT}`, WEB = `http://127.0.0.1:${WEB_PORT}`;
const PASS = "dashboard test pass";
const procs = [];

const sh = (cmd, args, opts = {}) => execFileSync(cmd, args, { stdio: ["ignore", "pipe", "inherit"], ...opts }).toString();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let step = 0;
const ok = (m) => console.log(`  ✓ ${++step}. ${m}`);

async function waitHttp(url) {
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(url)).ok) return; } catch {}
    await sleep(200);
  }
  throw new Error(`timeout waiting for ${url}`);
}

function cleanup() {
  for (const p of procs) try { p.kill("SIGTERM"); } catch {}
  try { sh("psql", [ADMIN_DB, "-qc", `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`]); } catch {}
}
process.on("exit", cleanup);
process.on("SIGINT", () => process.exit(1));

// --- start backend + preview -------------------------------------------------
const bin = path.join(art, "wiremesh-server");
sh("go", ["build", "-o", bin, "./cmd/wiremesh-server"], { cwd: root });
sh("psql", [ADMIN_DB, "-qc", `CREATE DATABASE ${dbName}`]);
const dbURL = new URL(ADMIN_DB); dbURL.pathname = "/" + dbName;
const env = {
  ...process.env,
  WIREMESH_DATABASE_URL: dbURL.toString(), WIREMESH_HTTP_ADDR: `127.0.0.1:${API_PORT}`,
  WIREMESH_PUBLIC_URL: WEB, WIREMESH_SECRET_KEY: randomBytes(32).toString("base64"),
  WIREMESH_LOG_FORMAT: "text", WIREMESH_AUTH_RATE_LIMIT_PER_MIN: "600", WIREMESH_RATE_LIMIT_RPS: "200", WIREMESH_RATE_LIMIT_BURST: "400",
};
sh(bin, ["create-admin", "--email", "admin@example.com", "--name", "Ada Admin"], { env: { ...env, WIREMESH_ADMIN_PASSWORD: PASS } });
procs.push(spawn(bin, ["serve"], { env, stdio: "ignore" }));
await waitHttp(`${API}/healthz`);
procs.push(spawn("npx", ["vite", "preview", "--host", "127.0.0.1", "--port", String(WEB_PORT), "--strictPort"], {
  cwd: path.join(here, ".."), env: { ...process.env, WIREMESH_API: API }, stdio: "ignore",
}));
await waitHttp(WEB);
console.log("backend + dashboard up");

// --- simulated devices ---------------------------------------------------------
const wgKey = () => randomBytes(32).toString("base64");
async function enroll(authKey, hostname) {
  const r = await fetch(`${API}/api/v1/device/register`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ auth_key: authKey, node_key: wgKey(), disco_key: wgKey(), hostname, os: "linux" }),
  });
  if (r.status !== 201) throw new Error(`enroll ${hostname}: ${r.status} ${await r.text()}`);
  return (await r.json()).credential;
}
function connectStream(cred) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${API_PORT}/api/v1/device/stream`, { headers: { Authorization: `Bearer ${cred}` } });
    ws.once("message", () => resolve(ws)); // first network map arrived
    ws.once("error", reject);
    ws.once("unexpected-response", (_req, res) => reject(new Error(`stream refused: ${res.statusCode}`)));
  });
}

// --- browser flow ------------------------------------------------------------------
const browser = await chromium.launch();
const ctx = await browser.newContext({ deviceScaleFactor: 2, viewport: { width: 1360, height: 860 } });
const page = await ctx.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));
page.on("console", (m) => /Content Security Policy|Refused to/.test(m.text()) && errors.push("CSP: " + m.text()));
const shot = (name) => page.screenshot({ path: path.join(art, `${name}.png`), fullPage: true });
const expectText = async (text, timeout = 15000) => page.getByText(text, { exact: false }).first().waitFor({ timeout });

try {
  await page.goto(WEB);
  await page.waitForURL("**/login");
  await page.getByLabel("Email").fill("admin@example.com");
  await page.getByLabel("Password").fill("wrong password!!");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expectText("invalid email or password");
  ok("wrong password shows the server's error");
  await shot("01-login");

  await page.getByLabel("Password").fill(PASS);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL("**/networks/new");
  ok("signed in; first-run redirects to network creation");

  await page.getByLabel("Network name").fill("Home Lab");
  await page.getByRole("button", { name: "Create network" }).click();
  await page.waitForURL("**/devices/add");
  ok("network created");

  // Auth key that needs approval (uncheck pre-authorized), reusable.
  await page.getByLabel("Description").fill("e2e devices");
  await page.getByRole("checkbox", { name: /Preauthorized/i }).uncheck();
  await page.getByRole("checkbox", { name: /Reusable/i }).check();
  await page.getByRole("button", { name: "Generate key" }).click();
  const key = (await page.getByTestId("new-auth-key").textContent()).trim();
  if (!key.startsWith("wmk_")) throw new Error("no auth key shown");
  await expectText("e2e devices");
  ok("auth key generated and listed (shown once)");
  await shot("02-add-device");

  const credA = await enroll(key, "laptop");
  const credB = await enroll(key, "build-server");
  await page.getByRole("link", { name: "Overview" }).click();
  await page.getByTestId("stat-pending-approval").filter({ hasText: "2" }).waitFor();
  ok("overview shows 2 devices pending approval");

  await page.getByRole("link", { name: "Devices", exact: true }).click();
  for (const name of ["laptop", "build-server"]) {
    await page.getByTestId(`device-row-${name}`).getByRole("button", { name: "Approve" }).click();
    await page.getByTestId(`device-row-${name}`).getByText("approved").waitFor();
  }
  ok("both devices approved from the devices table");

  const wsA = await connectStream(credA);
  await page.reload();
  await page.getByTestId("device-row-laptop").getByText("Online").waitFor();
  await page.getByTestId("device-row-build-server").getByText("Offline").waitFor();
  ok("live presence: laptop Online (real control stream), build-server Offline");
  await shot("03-devices");

  // Device details: tag the server.
  await page.getByRole("link", { name: "build-server" }).click();
  await page.getByLabel(/Comma-separated/).fill("tag:server");
  await page.getByRole("button", { name: "Save tags" }).click();
  await expectText("tag:server");
  ok("device tagged from its detail page");
  await shot("04-device-detail");

  // Access control: deny-all, then the tester shows "Blocked".
  await page.getByRole("link", { name: "Access control" }).click();
  await page.getByLabel("Policy JSON").fill('{"acls":[{"action":"accept","src":["tag:server"],"dst":["*:22"],"proto":"tcp"}]}');
  await page.getByRole("button", { name: "Save policy" }).click();
  await page.getByTestId("acl-saved").waitFor();
  await expectText("version 1");
  const choose = async (label, name) => page.getByLabel(label).selectOption(name);
  await choose("From device", "build-server"); await choose("To device", "laptop");
  await page.getByRole("button", { name: "Test", exact: true }).click();
  await page.getByTestId("acl-test-result").filter({ hasText: "Allowed" }).waitFor();
  await choose("From device", "laptop"); await choose("To device", "build-server");
  await page.getByRole("button", { name: "Test", exact: true }).click();
  await page.getByTestId("acl-test-result").filter({ hasText: "Blocked" }).waitFor();
  ok("policy saved (v1); tester: server→laptop:22 allowed, laptop→server blocked");
  await page.getByLabel("Policy JSON").fill('{"acls":[{"action":"accept","src":["nope"],"dst":["*:*"]}]}');
  await page.getByRole("button", { name: "Save policy" }).click();
  await expectText("unknown selector");
  ok("invalid policy rejected with the server's validation message");
  await shot("05-access");

  // Admin: create a user; Members: add them.
  await page.getByRole("link", { name: "Admin" }).click();
  await page.getByLabel("Email").fill("bob@example.com");
  await page.getByLabel("Name").fill("Bob");
  await page.getByLabel("Initial password").fill("bob password 123");
  await page.getByRole("button", { name: "Create" }).click();
  await expectText("bob@example.com");
  await page.getByRole("link", { name: "Users & roles" }).click();
  await page.getByLabel("Email").fill("bob@example.com");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await page.getByLabel("Role of bob@example.com").waitFor();
  ok("admin created a user and added them to the network");
  await shot("06-members");

  // Audit log records the actions.
  await page.getByRole("link", { name: "Audit log" }).click();
  for (const a of ["device.approve", "acl.update", "member.add", "device.tags"]) await expectText(a);
  ok("audit log lists approve/tags/acl/member events");

  // Device-code login: a headless device shows a code; approve it on /activate.
  const startRes = await fetch(`${API}/api/v1/device/login/start`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ node_key: wgKey(), disco_key: wgKey(), hostname: "headless-pi", os: "linux" }),
  });
  const { code, verify_url, poll_token } = await startRes.json();
  await page.goto(WEB + new URL(verify_url).pathname + new URL(verify_url).search);
  await expectText("headless-pi");
  await page.getByRole("button", { name: "Approve device" }).click();
  await page.getByTestId("activated").waitFor();
  const polled = await (await fetch(`${API}/api/v1/device/login/poll`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ poll_token }),
  })).json();
  if (polled.status !== "approved" || !polled.credential?.startsWith("wmd_")) throw new Error("device did not receive its credential");
  ok(`activate page: code ${code} approved; device received its credential`);
  await shot("09-activate");

  // Revoke the laptop: its real stream is closed with a revoke message.
  const revoked = new Promise((r) => wsA.on("message", (m) => String(m).includes('"revoked"') && r()));
  await page.getByRole("link", { name: "Devices", exact: true }).click();
  await page.getByRole("link", { name: "laptop" }).click();
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Revoke" }).click();
  await expectText("revoked");
  await Promise.race([revoked, sleep(5000).then(() => { throw new Error("device was not told it is revoked"); })]);
  await page.reload();
  await expectText("Offline");
  ok("revoking in the UI disconnects the device immediately (it receives 'revoked')");

  // Settings: dark mode + 2FA setup shows a QR code.
  await page.getByRole("link", { name: "Settings" }).click();
  await page.getByLabel("Confirm your password").fill(PASS);
  await page.getByRole("button", { name: "Set up" }).click();
  await page.getByAltText("TOTP QR code").waitFor();
  ok("two-factor setup renders the QR code");
  await page.getByRole("button", { name: "Toggle dark mode" }).click();
  if (!(await page.evaluate(() => document.documentElement.classList.contains("dark")))) throw new Error("dark mode not applied");
  await page.getByRole("link", { name: "Overview" }).click();
  await shot("07-overview-dark");
  ok("dark mode toggles");

  // Mobile layout renders.
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Open menu" }).click();
  await page.getByRole("link", { name: "Network status" }).click();
  await expectText("approved devices online");
  await shot("08-mobile-status");
  ok("mobile layout: menu and network status work at 390px");

  await page.getByRole("button", { name: "Sign out" }).click();
  await page.waitForURL("**/login");
  ok("sign out returns to login");

  if (errors.length) throw new Error("page errors: " + errors.join("; "));
  console.log(`\nALL ${step} CHECKS PASSED · screenshots in ${art}`);
  wsA.close();
  void credB;
} catch (e) {
  await shot("failure").catch(() => {});
  console.error("\n✗ FAILED:", e.message);
  process.exitCode = 1;
} finally {
  await browser.close();
}
// Child processes keep the event loop alive; exit explicitly.
cleanup();
process.exit(process.exitCode ?? 0);
