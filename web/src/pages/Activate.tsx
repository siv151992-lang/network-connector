import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { request } from "../api";
import { useAction } from "../hooks";
import { useNetwork } from "../state";
import { Button, Card, ErrorBox, Field, Input, PageHeader, Select } from "../ui";

interface PendingLogin { hostname: string; os: string; created_at: string; expires_at: string }

/** Approve a headless device that shows a login code (`wiremesh up`). */
export default function Activate() {
  const [params] = useSearchParams();
  const { networks, current } = useNetwork();
  const [code, setCode] = useState(params.get("code") ?? "");
  const [lookup, setLookup] = useState(params.get("code") ?? "");
  const [nid, setNid] = useState("");
  useEffect(() => setNid((n) => n || current?.id || ""), [current]);
  const q = useQuery({
    queryKey: ["login", lookup],
    queryFn: () => request<{ login: PendingLogin }>("GET", `/device/login/${encodeURIComponent(lookup)}`),
    enabled: lookup.length >= 8,
    retry: false,
  });
  const approve = useAction(() => request<{ device: { name: string; status: string } }>("POST", "/device/login/approve", { code: lookup, network_id: nid }), [["devices"]]);
  const usable = networks.filter((n) => n.role !== "auditor");

  return (
    <>
      <PageHeader title="Activate a device" subtitle="Enter the code shown by `wiremesh up` on the device." />
      <Card className="max-w-lg">
        {approve.data ? (
          <p className="text-sm" data-testid="activated">
            <strong>{approve.data.device.name}</strong> was added ({approve.data.device.status}). It connects within a few seconds.
          </p>
        ) : (
          <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (q.data) approve.mutate(undefined); else setLookup(code); }}>
            <Field label="Code"><Input value={code} onChange={(e) => setCode(e.target.value.toUpperCase())} placeholder="BCDF-GHJK" autoFocus /></Field>
            {q.data && (
              <>
                <div className="rounded-lg bg-slate-50 p-3 text-sm ring-1 ring-slate-200 dark:bg-slate-800 dark:ring-slate-700">
                  Device <strong>{q.data.login.hostname || "unnamed"}</strong> ({q.data.login.os || "unknown OS"}) wants to join.
                  Only approve it if you started this login yourself.
                </div>
                <Field label="Add to network">
                  <Select value={nid} onChange={(e) => setNid(e.target.value)}>
                    {usable.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
                  </Select>
                </Field>
              </>
            )}
            <ErrorBox error={q.error ?? approve.error} />
            <Button type="submit" disabled={approve.isPending}>{q.data ? "Approve device" : "Continue"}</Button>
          </form>
        )}
      </Card>
    </>
  );
}
