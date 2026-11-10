import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useAuth, useNetwork } from "./state";
import { Button, cx, Select } from "./ui";

const nav = [
  { to: "/", label: "Overview", end: true },
  { to: "/devices", label: "Devices" },
  { to: "/devices/add", label: "Add device" },
  { to: "/activate", label: "Activate device" },
  { to: "/status", label: "Network status" },
  { to: "/access", label: "Access control" },
  { to: "/members", label: "Users & roles" },
  { to: "/audit", label: "Audit log" },
  { to: "/settings", label: "Settings" },
];

function ThemeToggle() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));
  return (
    <Button
      variant="ghost"
      aria-label="Toggle dark mode"
      onClick={() => {
        const d = !dark;
        setDark(d);
        document.documentElement.classList.toggle("dark", d);
        try {
          localStorage.setItem("theme", d ? "dark" : "light");
        } catch {
          /* not persisted */
        }
      }}
    >
      {dark ? "☀ Light" : "☾ Dark"}
    </Button>
  );
}

export default function Layout() {
  const { user, signOut } = useAuth();
  const { networks, current, select } = useNetwork();
  const [open, setOpen] = useState(false);
  const links = user?.system_role === "admin" ? [...nav, { to: "/admin", label: "Admin" }] : nav;

  return (
    <div className="min-h-screen md:flex">
      <aside
        className={cx(
          "fixed inset-y-0 left-0 z-20 w-64 transform transition-transform border-r border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900 md:static md:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="mb-6 flex items-center gap-2 text-lg font-semibold">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-indigo-600 text-white">W</span> WireMesh
        </div>
        {networks.length > 0 && (
          <label className="mb-4 block">
            <span className="mb-1 block text-xs font-medium uppercase text-slate-500">Network</span>
            <Select value={current?.id} onChange={(e) => select(e.target.value)} aria-label="Network">
              {networks.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.name}
                </option>
              ))}
            </Select>
          </label>
        )}
        <nav className="space-y-1">
          {links.map((l) => (
            <NavLink
              key={l.to}
              to={l.to}
              end={l.end || l.to === "/devices"}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                cx(
                  "block rounded-lg px-3 py-2 text-sm",
                  isActive ? "bg-indigo-50 font-medium text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300" : "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800",
                )
              }
            >
              {l.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      {open && <div className="fixed inset-0 z-10 bg-black/30 md:hidden" onClick={() => setOpen(false)} />}

      <div className="flex-1">
        <header className="flex items-center justify-between gap-3 border-b border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-900">
          <Button variant="ghost" className="md:hidden" onClick={() => setOpen(true)} aria-label="Open menu">
            ☰
          </Button>
          <div className="ml-auto flex items-center gap-2">
            <ThemeToggle />
            <span className="hidden text-sm text-slate-500 sm:inline" data-testid="current-user">
              {user?.email}
            </span>
            <Button variant="secondary" onClick={() => void signOut()}>
              Sign out
            </Button>
          </div>
        </header>
        <main className="mx-auto max-w-6xl p-4 md:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
