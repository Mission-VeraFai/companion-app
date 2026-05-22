import fs from "fs";
import path from "path";
import { Config } from "twilio/lib/twiml/VoiceResponse";

// Allowlist of field names that may be used as dynamic property keys
const ALLOWED_FIELD_NAMES = new Set<string>(["name", "id", "type", "category"]);

class ConfigManager {
  private static instance: ConfigManager;
  private config: any;

  private constructor() {
    const companionsPath = path.resolve(__dirname, "companions", "companions.json");
    const data = fs.readFileSync(companionsPath, "utf8");
    this.config = JSON.parse(data);
  }

  public static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  public getConfig(fieldName: string, configValue: string, allowedFields?: string[]) {
    //).filter((c: any) => c.name === companionName);
    if (!ALLOWED_FIELD_NAMES.has(fieldName)) {
      throw new Error(`Invalid fieldName: "${fieldName}" is not an allowed config key.`);
    }
    try {
      if (!!this.config && this.config.length !== 0) {
        const result = this.config.filter(
          (c: any) => Object.prototype.hasOwnProperty.call(c, fieldName) && c[fieldName] === configValue
        );
        if (result.length !== 0) {
          const matched = result[0];
          const fields = allowedFields && allowedFields.length > 0
            ? allowedFields
            : [fieldName];
          return fields.reduce((acc: Record<string, any>, key: string) => {
            if (Object.prototype.hasOwnProperty.call(matched, key)) {
              acc[key] = matched[key];
            }
            return acc;
          }, {});
        }
      }
    } catch (e) {
      console.error(e);
      throw e;
    }
  }
}

export default ConfigManager;
