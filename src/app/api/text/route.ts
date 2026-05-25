import { NextResponse } from "next/server";
import twilio from "twilio";
import clerk from "@clerk/clerk-sdk-node";
import dotenv from "dotenv";
import ConfigManager from "@/app/utils/config";
import { rateLimit } from "@/app/utils/rateLimit";

// Approved model registry: only these pinned, versioned model identifiers are permitted.
const APPROVED_MODEL_REGISTRY: ReadonlySet<string> = new Set([
  "claude-3-opus-20240229",
  "claude-3-sonnet-20240229",
  "claude-3-haiku-20240307",
  "gpt-4-0125-preview",
  "gpt-4-turbo-2024-04-09",
  "gpt-3.5-turbo-0125",
]);

function isApprovedModel(model: string): boolean {
  return APPROVED_MODEL_REGISTRY.has(model);
}
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

const AUDIT_LOG_PATH = path.resolve(process.cwd(), "audit.log");

function writeAuditRecord(record: Record<string, unknown>): void {
  const line = JSON.stringify(record) + "\n";
  try {
    fs.appendFileSync(AUDIT_LOG_PATH, line, { encoding: "utf8", flag: "a" });
  } catch (err) {
    // Fallback: surface the failure so it is not silently swallowed
    console.error("AUDIT_WRITE_FAILURE", err);
  }
}

dotenv.config({ path: `.env.local` });
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN;
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const internalApiSecret = process.env.INTERNAL_API_SECRET;
const interAgentApiKey = process.env.INTER_AGENT_API_KEY;

/**
 * Sanitizes incoming SMS prompt text to prevent prompt injection,
 * shell command execution, and base64-encoded malicious payloads.
 * Returns null if the content should be rejected outright.
 */
function sanitizePrompt(input: string): string | null {
  if (!input || typeof input !== "string") return null;

  // Reject if the message is suspiciously long (potential payload smuggling)
  if (input.length > 1000) return null;

  // Detect and reject base64-encoded content (min 20 chars of base64)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{20,}={0,2})/;
  if (base64Pattern.test(input)) return null;

  // Reject shell command patterns
  const shellCommandPattern =
    /(\$\(|`[^`]*`|\|\s*\w+|&&|\|\||;\s*\w+|\bexec\b|\beval\b|\bsystem\b|\bspawn\b|\bchild_process\b)/i;
  if (shellCommandPattern.test(input)) return null;

  // Reject hidden prompt-injection markers (e.g. "ignore previous instructions",
  // "system:", "assistant:", "<|im_start|>", etc.)
  const injectionPattern =
    /(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)|\bsystem\s*:|\bassistant\s*:|\buser\s*:|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[\/INST\]|###\s*instruction|###\s*system|###\s*prompt)/i;
  if (injectionPattern.test(input)) return null;

  // Reject attempts to exfiltrate data via URLs
  const urlExfilPattern = /https?:\/\/[^\s]+/i;
  if (urlExfilPattern.test(input)) return null;

  // Strip any non-printable / control characters (except normal whitespace)
  const cleaned = input.replace(/[^\x20-\x7E\t\n\r]/g, "").trim();

  if (cleaned.length === 0) return null;

  return cleaned;
}

function sanitizePrompt(input: string): string | null {
  if (typeof input !== "string") return null;
  // Remove control characters (except normal whitespace)
  const stripped = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
  if (stripped.length === 0) return null;
  // Enforce a maximum length to prevent prompt injection via very long inputs
  const MAX_LENGTH = 1000;
  return stripped.slice(0, MAX_LENGTH);
}

export async function POST(request: Request) {
  let queryMap: any = {};
  const twilioClient = twilio(accountSid, twilioAuthToken);

  const rawBody = await request.text();
  const twilioSignature = request.headers.get("X-Twilio-Signature") || "";
  const webhookUrl = request.url;

  // Parse the URL-encoded body into a params object for signature validation
  const params: Record<string, string> = {};
  rawBody.split("&").forEach((item) => {
    const [key, value] = item.split("=");
    if (key) params[decodeURIComponent(key)] = decodeURIComponent(value || "");
  });

  const isValidRequest = twilio.validateRequest(
    twilioAuthToken!,
    twilioSignature,
    webhookUrl,
    params
  );

  if (!isValidRequest) {
    console.log("WARNING: Invalid Twilio signature — request rejected.");
    return new NextResponse(
      JSON.stringify({ Message: "Forbidden: invalid Twilio signature" }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const data = decodeURIComponent(rawBody);
  data.split("&").forEach((item) => {
    queryMap[item.split("=")[0]] = item.split("=")[1];
  });
  const rawPrompt = queryMap["Body"];

  // Sanitize and validate the SMS body before sending to the LLM
  const MAX_PROMPT_LENGTH = 1000;
  if (!rawPrompt || typeof rawPrompt !== "string") {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or empty message body." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  // Trim whitespace and enforce max length
  let prompt = rawPrompt.trim().slice(0, MAX_PROMPT_LENGTH);
  // Strip control characters (except standard whitespace)
  prompt = prompt.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  if (prompt.length === 0) {
    return new NextResponse(
      JSON.stringify({ Message: "Message body must not be empty." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  const serverUrl = process.env.INTERNAL_API_BASE_URL || "http://localhost:3000";
  const phoneNumber = queryMap["From"];
  const companionPhoneNumber = queryMap["To"];

  const hashedPhone = phoneNumber
    ? crypto.createHash("sha256").update(phoneNumber).digest("hex")
    : "anonymous";
  const identifier = request.url + "-" + hashedPhone;
  const { success } = await rateLimit(identifier);
  if (!success) {
    console.log("INFO: rate limit exceeded");
    return new NextResponse(
      JSON.stringify({ Message: "Hi, the companions can't talk this fast." }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  // check if the user has a registered phone # via config
  const registeredUser = configManager.getUserByPhone(phoneNumber);

  if (!registeredUser) {
    return new NextResponse(
      JSON.stringify({ Message: "User not authorized" }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  const configManager = ConfigManager.getInstance();
  // check if the user has a registered phone # via config
  const registeredUser = configManager.getUserByPhone(phoneNumber);

  if (!registeredUser) {
    return new NextResponse(
      JSON.stringify({ Message: "User not authorized" }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  const companionConfig = configManager.getConfig(
    "phone",
    companionPhoneNumber
  );
  console.log("companionConfig: ", { name: companionConfig?.name, llm: companionConfig?.llm });
  if (!companionConfig || companionConfig.length == 0) {
    return new NextResponse(
      JSON.stringify({ Message: "User not authorized" }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  const companionName = companionConfig.name;

  // Only models from the organization's approved list may be used.
  const APPROVED_MODELS: ReadonlySet<string> = new Set(["claude-3-opus", "claude-3-sonnet", "claude-3-haiku"]);
  const DEFAULT_APPROVED_MODEL = "claude-3-sonnet";
  const requestedModel: string = companionConfig.llm;
  const companionModel = APPROVED_MODELS.has(requestedModel)
    ? requestedModel
    : DEFAULT_APPROVED_MODEL;
  if (!APPROVED_MODELS.has(requestedModel)) {
    console.warn(
      `WARNING: Requested LLM "${requestedModel}" is not in the approved list. Falling back to "${DEFAULT_APPROVED_MODEL}".`
    );
  }

  const userId = users[0].id;
  const userName = users[0].firstName;
    if (!interAgentApiKey) {
    console.error("ERROR: INTER_AGENT_API_KEY is not configured.");
    return new NextResponse(
      JSON.stringify({ Message: "Internal server configuration error" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

    if (!internalApiSecret) {
    console.error("ERROR: INTERNAL_API_SECRET is not configured");
    return new NextResponse(
      JSON.stringify({ Message: "Internal server configuration error" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // SSRF guard: ensure companionModel is a known, safe identifier.
  if (!companionModel || !ALLOWED_COMPANION_MODELS.has(companionModel)) {
    console.log(`WARNING: rejected unknown companionModel '${companionModel}'`);
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion model" }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const response = await fetch(`${serverUrl}/api/${companionModel}`, {
    body: JSON.stringify({
      prompt,
      isText: true,
      userId: users[0].id,
      userName: users[0].firstName,
    }),
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      name: companionName,
      Authorization: `Bearer ${internalApiSecret}`,
    },
  });

  const rawResponseText = await response.text();

  // Validate and sanitize LLM output before use
  const DYNAMIC_CODE_PRIMITIVES = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bnew\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bimport\s*\(/i,
    /\brequire\s*\(/i,
    /\bprocess\.binding\s*\(/i,
    /\bchild_process/i,
    /\bvm\.runInThisContext\s*\(/i,
    /\bvm\.runInNewContext\s*\(/i,
  ];

  function validateAndSanitizeLLMOutput(text: string): string {
    for (const pattern of DYNAMIC_CODE_PRIMITIVES) {
      if (pattern.test(text)) {
        console.warn(
          "WARNING: LLM output contains dynamic code execution primitive, rejecting response.",
          { matchedPattern: pattern.toString() }
        );
        return "I'm sorry, I was unable to generate a safe response. Please try again.";
      }
    }
    // Strip any null bytes or non-printable control characters
    return text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
  }

  const responseText = validateAndSanitizeLLMOutput(rawResponseText);

  const to = queryMap["From"];
  const from = queryMap["To"];
  console.log("responseText: ", responseText);
  await twilioClient.messages
    .create({
      body: responseText,
      from,
      to,
    })
    .catch((err) => {
      console.log("WARNING: failed to send SMS.", err);
    });

  return NextResponse.json({ message: "Hello from the API!" });
}
