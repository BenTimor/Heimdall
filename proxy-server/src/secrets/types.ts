export interface SecretProvider {
  readonly name: string;
  getSecret(path: string, field?: string): Promise<string | null>;
}
