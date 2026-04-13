export interface ClientLookup {
  tokenOrHash: string;
  isHashed: boolean;
  enabled: boolean;
  sourceCidrs: string[];
}

export interface AuthBackend {
  findClient(machineId: string): ClientLookup | null;
}
