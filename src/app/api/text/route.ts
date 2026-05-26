import { NextResponse } from "next/server";
import twilio from "twilio";
import clerk from "@clerk/clerk-sdk-node";
import dotenv from "dotenv";
import ConfigManager from "@/app/utils/config";
import { rateLimit } from "@/app/utils/rateLimit";

// Approved model registry: maps approved model identifiers to their pinned versions.
// Only models listed here may be used for inference.
const APPROVED_MODEL_REGISTRY: Record<string, { pinnedVersion: string; endpoint: string }> = {
  "gpt-4": { pinnedVersion: "gpt-4-0613", endpoint: "claude" },
  "gpt-3.5-turbo": { pinnedVersion: "gpt-3.5-turbo-0613", endpoint: "claude" },
  // Add additional approved models here as needed.
};

function resolveApprovedModel(
  requestedModel: string
): { pinnedVersion: string; endpoint: string } | null {
  const entry = APPROVED_MODEL_REGISTRY[requestedModel];
  if (!entry) return null;
  return entry;
}
import { createHash } from "crypto";
import { appendFileSync, mkdirSync } from "fs";
import path from "path";

const AUDIT_LOG_DIR = path.resolve(process.cwd(), "audit-logs");
const AUDIT_LOG_FILE = path.join(AUDIT_LOG_DIR, "ai-inference-audit.log");

function writeAuditRecord(record: Record<string, unknown>): void {
  try {
    mkdirSync(AUDIT_LOG_DIR, { recursive: true });
    const line = JSON.stringify({ ...record, _written: new Date().toISOString() }) + "\n";
    appendFileSync(AUDIT_LOG_FILE, line, { encoding: "utf8", flag: "a" });
  } catch (err) {
    // Fail loudly so ops can detect audit pipeline breakage
    console.error("CRITICAL: audit log write failed", err);
  }
}

dotenv.config({ path: `.env.local` });
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN;
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const internalApiSecret = process.env.INTERNAL_API_SECRET;
const interAgentSecret = process.env.INTER_AGENT_SECRET;

const DYNAMIC_CODE_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"`]/gi,
  /\bsetInterval\s*\(\s*['"`]/gi,
  /\bimport\s*\(/gi,
  /\brequire\s*\(/gi,
  /\bprocess\.binding\s*\(/gi,
  /\bchild_process/gi,
  /\bspawn\s*\(/gi,
  /\bexecSync\s*\(/gi,
  /\bexecFile\s*\(/gi,
  /\bvm\.runInThisContext\s*\(/gi,
  /\bvm\.runInNewContext\s*\(/gi,
  /\bvm\.Script\s*\(/gi,
  /__import__/gi,
  /compile\s*\(/gi,
];

function validateAndSanitizeLLMOutput(text: string): string {
  for (const pattern of DYNAMIC_CODE_PATTERNS) {
    if (pattern.test(text)) {
      console.warn(
        `WARNING: LLM output contained a forbidden dynamic code execution pattern matching ${pattern}. Stripping content.`
      );
      // Reset lastIndex for global regexes after test()
      pattern.lastIndex = 0;
      text = text.replace(pattern, "[REMOVED]");
    }
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0;
  }
  return text;
}

export async function POST(request: Request) {
  let queryMap: any = {};
  const twilioClient = twilio(accountSid, twilioAuthToken);

  // Read raw body for HMAC validation
  const rawBody = await request.text();

  // Validate Twilio HMAC signature before processing
  const twilioSignature = request.headers.get("X-Twilio-Signature") || "";
  const requestUrl = request.url;

  // Parse the URL-encoded body into a plain object for validateRequest
  const bodyParams: Record<string, string> = {};
  rawBody.split("&").forEach((item) => {
    const [key, value] = item.split("=");
    if (key) {
      bodyParams[decodeURIComponent(key)] = decodeURIComponent(value || "");
    }
  });

  const isValidRequest = twilio.validateRequest(
    twilioAuthToken!,
    twilioSignature,
    requestUrl,
    bodyParams
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
  const rawPrompt: string = queryMap["Body"] ?? "";

  // Sanitize and validate the prompt before forwarding to the LLM
  const MAX_PROMPT_LENGTH = 1000;
  const sanitizePrompt = (input: string): string | null => {
    // Trim surrounding whitespace
    let sanitized = input.trim();
    // Remove ASCII control characters (except newline/tab which may be intentional)
    sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
    // Enforce maximum length
    if (sanitized.length === 0 || sanitized.length > MAX_PROMPT_LENGTH) {
      return null;
    }
    return sanitized;
  };

  const prompt = sanitizePrompt(rawPrompt);
  if (prompt === null) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or empty message." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  if (!prompt) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid message body" }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const serverUrl = request.url.split("/api/")[0];
  const phoneNumber = queryMap["From"];
  const companionPhoneNumber = queryMap["To"];

  const identifier = request.url + "-" + (phoneNumber || "anonymous");
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

  // check if the request includes a phone number
  if (!phoneNumber) {
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
  const companionConfig = configManager.getConfig(
    "phone",
    companionPhoneNumber
  );
  console.log("companionConfig found: ", companionConfig ? true : false);
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
  const APPROVED_MODELS: string[] = ["claude"];
  const requestedModel: string = companionConfig.llm;
  const companionModel: string = APPROVED_MODELS.includes(requestedModel)
    ? requestedModel
    : APPROVED_MODELS[0];

    const llmRequestPayload = {
    prompt,
    isText: true,
    userId: users[0].id,
    userName: users[0].firstName,
  };

  console.log(
    JSON.stringify({
      event: "llm_interaction_request",
      timestamp: new Date().toISOString(),
      companionModel,
      companionName,
      endpoint: `${serverUrl}/api/${companionModel}`,
      request: llmRequestPayload,
    })
  );

    const { id: userId, firstName: userName } = users[0];
    if (!interAgentSecret) {
    console.error("ERROR: INTER_AGENT_SECRET is not configured.");
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
      JSON.stringify({ Message: "Server misconfiguration" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Validate companionModel against allowlist to prevent SSRF
  if (!ALLOWED_COMPANION_MODELS.has(companionModel)) {
    console.log(`WARNING: Blocked disallowed companionModel value: "${companionModel}"`);
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion model configuration" }),
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

      const responseText = await response.text();
  let smsBody: string;
  try {
    const parsed = JSON.parse(responseText);
    smsBody = parsed.text ?? parsed.message ?? parsed.response ?? String(parsed);
  } catch {
    smsBody = responseText;
  }
  // Truncate to SMS-safe length to avoid leaking excess model output
  const MAX_SMS_LENGTH = 1600;
  smsBody = smsBody.slice(0, MAX_SMS_LENGTH);

  const to = queryMap["From"];
  const from = queryMap["To"];
  await twilioClient.messages
    .create({
      body: smsBody,
      from,
      to,
    }) | ${new Date().toISOString()}`;
  const labeledResponseText = `${aiLabel}\n${responseText}${provenanceFooter}`;

  await twilioClient.messages
    .create({
      body: labeledResponseText,
      from,
      to,
    })
  );
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
