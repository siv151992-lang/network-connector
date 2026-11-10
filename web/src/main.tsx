import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import "./index.css";
import { ApiError } from "./api";
import { AuthProvider, NetworkProvider, useAuth, useNetwork } from "./state";
import Layout from "./Layout";
import { Spinner } from "./ui";
import { ForgotPassword, Login, Register, ResetPassword, VerifyEmail } from "./pages/Auth";
import Overview from "./pages/Overview";
import Devices from "./pages/Devices";
import DeviceDetail from "./pages/DeviceDetail";
import AddDevice from "./pages/AddDevice";
import Status from "./pages/Status";
import Access from "./pages/Access";
import Members from "./pages/Members";
import Audit from "./pages/Audit";
import Settings from "./pages/Settings";
import Admin from "./pages/Admin";
import NewNetwork from "./pages/NewNetwork";
import Activate from "./pages/Activate";

const qc = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (n, e) => !(e instanceof ApiError && e.status < 500) && n < 2,
      refetchOnWindowFocus: true,
    },
  },
});

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const loc = useLocation();
  if (loading) return <div className="grid min-h-screen place-items-center"><Spinner /></div>;
  if (!user) return <Navigate to="/login" replace state={{ from: loc.pathname }} />;
  return <NetworkProvider><RequireNetwork>{children}</RequireNetwork></NetworkProvider>;
}

/** First-run: a user with no network is sent to create one. */
function RequireNetwork({ children }: { children: React.ReactNode }) {
  const { networks, loading } = useNetwork();
  const loc = useLocation();
  if (loading) return <div className="grid min-h-screen place-items-center"><Spinner /></div>;
  if (networks.length === 0 && loc.pathname !== "/networks/new" && loc.pathname !== "/settings" && loc.pathname !== "/admin")
    return <Navigate to="/networks/new" replace />;
  return <>{children}</>;
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/verify-email" element={<VerifyEmail />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route element={<RequireAuth><Layout /></RequireAuth>}>
        <Route index element={<Overview />} />
        <Route path="devices" element={<Devices />} />
        <Route path="devices/add" element={<AddDevice />} />
        <Route path="devices/:id" element={<DeviceDetail />} />
        <Route path="status" element={<Status />} />
        <Route path="access" element={<Access />} />
        <Route path="members" element={<Members />} />
        <Route path="audit" element={<Audit />} />
        <Route path="settings" element={<Settings />} />
        <Route path="admin" element={<Admin />} />
        <Route path="networks/new" element={<NewNetwork />} />
        <Route path="activate" element={<Activate />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <AuthProvider>
          <App />
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
