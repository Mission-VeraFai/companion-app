import fs from "fs";
import { Config } from "twilio/lib/twiml/VoiceResponse";

class ConfigManager {
  private static instance: ConfigManager;
  private config: any;

  private constructor() {
    const data = fs.readFileSync("companions/companions.json", "utf8");
    this.config = JSON.parse(data);
  }

  public static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  // Only these fields are exposed to callers; add fields here as needed.
  private static readonly ALLOWED_CONFIG_FIELDS: ReadonlyArray<string> = [
    "name",
    "voice",
    "language",
    "greeting",
    "prompt",
  ];

  public getConfig(fieldName: string, configValue: string) {
    //).filter((c: any) => c.name === companionName);
    try {
      if (!!this.config && this.config.length !== 0) {
        const result = this.config.filter(
          (c: any) => c[fieldName] === configValue
        );
        if (result.length !== 0) {
          // Return only the explicitly allowed fields instead of the full record.
          const matched = result[0];
          return ConfigManager.ALLOWED_CONFIG_FIELDS.reduce(
            (acc: Record<string, unknown>, key: string) => {
              if (Object.prototype.hasOwnProperty.call(matched, key)) {
                acc[key] = matched[key];
              }
              return acc;
            },
            {}
          );
        }
      }
    } catch (e) {
      console.log(e);
    }
  }
}

export default ConfigManager;
