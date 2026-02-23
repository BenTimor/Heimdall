import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import type { SecretProvider } from "./types.js";
import { createLogger } from "../utils/logger.js";

const logger = createLogger({ name: "aws-provider" });

export class AwsProvider implements SecretProvider {
  readonly name = "aws";
  private client: SecretsManagerClient;

  constructor(region: string) {
    this.client = new SecretsManagerClient({ region });
  }

  async getSecret(path: string, field?: string): Promise<string | null> {
    try {
      const cmd = new GetSecretValueCommand({ SecretId: path });
      const response = await this.client.send(cmd);

      const secretString = response.SecretString;
      if (!secretString) return null;

      if (field) {
        const json = JSON.parse(secretString);
        return json[field] ?? null;
      }

      return secretString;
    } catch (err) {
      logger.warn({ err, path, field }, "Failed to retrieve AWS secret");
      return null;
    }
  }
}
