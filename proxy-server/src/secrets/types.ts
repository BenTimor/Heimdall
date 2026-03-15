export interface SecretProvider {
  readonly name: string;
  getSecret(path: string, field?: string): Promise<string | null>;
  setSecret?(path: string, value: string, field?: string): Promise<void>;
}
