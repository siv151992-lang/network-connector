import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useNetwork } from "./state";

/** Devices of the current network, refreshed every 10 s for live presence. */
export function useDevices() {
  const { current } = useNetwork();
  return useQuery({
    queryKey: ["devices", current?.id],
    queryFn: () => api.devices(current!.id),
    enabled: !!current,
    refetchInterval: 10_000,
    select: (d) => d.devices,
  });
}

/** Mutation helper that refreshes the given query keys on success. */
export function useAction<A, R>(fn: (a: A) => Promise<R>, invalidate: unknown[][]) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => invalidate.forEach((k) => qc.invalidateQueries({ queryKey: k })),
  });
}
