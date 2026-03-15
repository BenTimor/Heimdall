import {
  SecretsManagerClient,
  GetSecretValueCommand,
  PutSecretValueCommand,
  CreateSecretCommand,
  ResourceNotFoundException,
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

  async setSecret(path: string, value: string, field?: string): Promise<void> {
    let secretString = value;

    if (field) {
      // Read existing secret, merge the field into it
      let existing: Record<string, unknown> = {};
      try {
        const cmd = new GetSecretValueCommand({ SecretId: path });
        const response = await this.client.send(cmd);
        if (response.SecretString) {
          existing = JSON.parse(response.SecretString);
        }
      } catch (err) {
        if (!(err instanceof ResourceNotFoundException)) throw err;
        // Secret doesn't exist yet — start with empty object
      }
      existing[field] = value;
      secretString = JSON.stringify(existing);
    }

    try {
      await this.client.send(
        new PutSecretValueCommand({ SecretId: path, SecretString: secretString }),
      );
    } catch (err) {
      if (err instanceof ResourceNotFoundException) {
        await this.client.send(
          new CreateSecretCommand({ Name: path, SecretString: secretString }),
        );
      } else {
        throw err;
      }
    }

    logger.info({ path, field }, "AWS secret written");
  }
}
