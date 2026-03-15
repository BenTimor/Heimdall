export interface ClientLookup {
  tokenOrHash: string;
  isHashed: boolean;
  enabled: boolean;
}

export interface AuthBackend {
  findClient(machineId: string): ClientLookup | null;
}
