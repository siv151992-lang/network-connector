import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../api";
import { useAction } from "../hooks";
import { useNetwork } from "../state";
import { Button, Card, ErrorBox, Field, Input, PageHeader } from "../ui";

export default function NewNetwork() {
  const { networks, select } = useNetwork();
  const nav = useNavigate();
  const [name, setName] = useState("");
  const qc = useQueryClient();
  // Refetch the network list *before* navigating, so the first-run guard
  // doesn't see the stale empty list and bounce back here.
  const create = useAction(async () => {
    const r = await api.createNetwork(name);
    await qc.refetchQueries({ queryKey: ["networks"] });
    return r;
  }, []);
  return (
    <>
      <PageHeader title={networks.length ? "New network" : "Welcome to WireMesh"} subtitle="A network is a private address space for your devices." />
      <Card className="max-w-lg">
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); create.mutate(undefined, { onSuccess: (r) => { select(r.network.id); nav("/devices/add"); } }); }}>
          <Field label="Network name"><Input required value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Home" /></Field>
          <ErrorBox error={create.error} />
          <Button type="submit" disabled={create.isPending}>Create network</Button>
        </form>
      </Card>
    </>
  );
}
