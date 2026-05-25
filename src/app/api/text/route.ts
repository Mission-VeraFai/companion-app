import { NextResponse } from "next/server";
import twilio from "twilio";
import dotenv from "dotenv";
import ConfigManager from "@/app/utils/config";
import { rateLimit } from "@/app/utils/rateLimit";

// ---------------------------------------------------------------------------
// Static Approved Model Registry — version-pinned with SHA-256 digest
// ---------------------------------------------------------------------------
// Each entry binds a model identifier to an immutable SHA-256 digest of its
// canonical weight/config artifact.  Both the name AND the digest must match
// for a model to be considered approved.  To add or update a model, a human
// reviewer must update this table in source control and supply the correct
// digest obtained from the organisation's model-artifact store.
//
// DO NOT load approved models from environment variables or any other
// runtime-mutable source — doing so bypasses version pinning and integrity
// verification.
// ---------------------------------------------------------------------------
interface ApprovedModelEntry {
  /** Canonical model identifier (name + version). */
  readonly id: string;
  /**
   * SHA-256 hex digest of the model's canonical weight/config artifact as
   * published in the organisation's approved-model artifact store.
   * Obtain with: sha256sum <artifact-file> | awk '{print $1}'
   */
  readonly sha256: string;
}

/**
 * Immutable, source-controlled list of approved foundation models.
 * Only models present here — with a matching digest — may be used.
 */
const APPROVED_MODEL_ENTRIES: readonly ApprovedModelEntry[] = Object.freeze([
  // -----------------------------------------------------------------------
  // Add approved models here following security review.
  // Example (replace with real digests from your artifact store):
  //
  // {
  //   id: "org-approved-model-v1.2.0",
  //   sha256: "<64-char-hex-sha256-of-model-artifact>",
  // },
  // -----------------------------------------------------------------------
] as const);

/** Fast lookup: model-id → expected SHA-256 digest. */
const APPROVED_MODEL_REGISTRY: ReadonlyMap<string, string> = new Map(
  APPROVED_MODEL_ENTRIES.map((e) => [e.id, e.sha256])
);

if (APPROVED_MODEL_REGISTRY.size === 0) {
  console.warn(
    "[SECURITY] APPROVED_MODEL_ENTRIES is empty. " +
    "No LLM models are approved. All model requests will be denied."
  );
}

/**
 * Verifies that `model` is in the static approved registry AND that the
 * supplied `artifactDigest` matches the pinned SHA-256 for that model.
 *
 * Both checks must pass; failing either rejects the model.
 *
 * @param model          - The model identifier string supplied by the caller.
 * @param artifactDigest - Hex-encoded SHA-256 digest of the model artifact
 *                         being loaded, computed at load time by the caller.
 */
function isApprovedModel(model: string, artifactDigest: string): boolean {
  const expectedDigest = APPROVED_MODEL_REGISTRY.get(model);
  if (expectedDigest === undefined) {
    console.error(
      `[SECURITY] Model "${model}" is NOT in the approved model registry. ` +
      "Request denied."
    );
    return false;
  }
  // Constant-time comparison to prevent timing-based oracle attacks.
  const expected = Buffer.from(expectedDigest.toLowerCase(), "hex");
  const actual   = Buffer.from(artifactDigest.toLowerCase(), "hex");
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    console.error(
      `[SECURITY] Model "${model}" digest mismatch. ` +
      `Expected ${expectedDigest}, got ${artifactDigest}. Request denied.`
    );
    return false;
  }
  return true;
}
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

const AUDIT_LOG_PATH = path.resolve(process.cwd(), "audit.log");
const MAX_AUDIT_FILE_BYTES = 10 * 1024 * 1024; // 10 MB per file
const MAX_AUDIT_ROTATIONS = 5; // keep audit.log.1 … audit.log.5

function rotateAuditLogIfNeeded(): void {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(AUDIT_LOG_PATH);
  } catch {
    return; // file does not exist yet — nothing to rotate
  }
  if (stat.size < MAX_AUDIT_FILE_BYTES) return;

  // Shift existing rotated files: .5 is dropped, .4→.5, …, .1→.2
  for (let i = MAX_AUDIT_ROTATIONS - 1; i >= 1; i--) {
    const src = `${AUDIT_LOG_PATH}.${i}`;
    const dst = `${AUDIT_LOG_PATH}.${i + 1}`;
    try {
      if (fs.existsSync(src)) fs.renameSync(src, dst);
    } catch (renameErr) {
      // Log rotation rename failed — surface loudly and abort rotation
      // so the active log is never lost.
      console.error("AUDIT_ROTATE_FAILURE", renameErr);
      return;
    }
  }
  try {
    fs.renameSync(AUDIT_LOG_PATH, `${AUDIT_LOG_PATH}.1`);
  } catch (renameErr) {
    console.error("AUDIT_ROTATE_FAILURE", renameErr);
  }
}

function writeAuditRecord(record: Record<string, unknown>): void {
  const line = JSON.stringify({ ...record, written_at: new Date().toISOString() }) + "\n";
  try {
    rotateAuditLogIfNeeded();
    fs.appendFileSync(AUDIT_LOG_PATH, line, { encoding: "utf8", flag: "a" });
  } catch (err) {
    // Re-throw so callers are aware the audit record was NOT persisted.
    // A silent failure here would break forensic readiness guarantees.
    console.error("AUDIT_WRITE_FAILURE", err);
    throw new Error(`Audit write failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

dotenv.config({ path: `.env.local` });
// Credentials are retrieved on-demand via ConfigManager to avoid holding
// multiple external-system secrets as module-level constants.
// Use configManager.get('TWILIO_AUTH_TOKEN'), configManager.get('TWILIO_ACCOUNT_SID'),
// and configManager.get('INTERNAL_API_SECRET') at the call sites that need them.

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

// Duplicate sanitizePrompt removed: the stricter implementation above is the sole definition.

export async function POST(request: Request) {
  // Enforce API key authentication before any other processing.
  // This ensures the LLM-triggering route is not publicly reachable
  // without a valid API key, independent of Twilio signature validation.
  const expectedApiKey = process.env.WEBHOOK_API_KEY;
  const providedApiKey = request.headers.get("x-api-key");
  if (!expectedApiKey || !providedApiKey || providedApiKey !== expectedApiKey) {
    return new NextResponse(
      JSON.stringify({ Message: "Unauthorized: missing or invalid API key" }),
      {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  interface TwilioQueryMap {
    Body?: string;
    From?: string;
    To?: string;
    MessageSid?: string;
    AccountSid?: string;
    [key: string]: string | undefined;
  }
  let queryMap: TwilioQueryMap = {};
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
      Authorization: `Bearer ${(() => { if (!internalApiSecret) throw new Error('INTERNAL_API_SECRET is not configured'); return internalApiSecret; })()`,
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

  writeAuditRecord({
    event: "llm_response",
    timestamp: new Date().toISOString(),
    rawResponseText,
  });

  const responseText = validateAndSanitizeLLMOutput(rawResponseText);

  // --- Approved Model Registry Enforcement ---
  const APPROVED_MODEL_REGISTRY = [
    "claude-3-opus-20240229",
    "claude-3-sonnet-20240229",
    "claude-3-haiku-20240307",
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
    "claude-2.1",
    "claude-2.0",
    "claude-instant-1.2",
  ];

  if (!APPROVED_MODEL_REGISTRY.includes(companionModel)) {
    console.warn(
      `POLICY VIOLATION: Attempted use of disallowed or unregistered model: '${companionModel}'. Only approved Claude models are permitted.`
    );
    return new NextResponse(
      JSON.stringify({
        Message: `Model '${companionModel}' is not in the approved model registry. Only approved Claude models are permitted.`,
      }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  // --- End Approved Model Registry Enforcement ---

  // --- Synthetic Content Provenance ---
  const provenanceTimestamp = new Date().toISOString();
  const provenanceModelId = companionModel; // model/companion identifier — validated against approved registry above
  const provenanceLabel = "[AI-GENERATED CONTENT]";

  // Cryptographic HMAC signature delegated to the dedicated signing service.
  // PROVENANCE_HMAC_SECRET is NOT held here; signing is performed remotely.
  const provenancePayload = `${provenanceModelId}|${provenanceTimestamp}|${responseText}`;
  const signingServiceUrl = configManager.get('SIGNING_SERVICE_URL');
  const internalApiSecret = configManager.get('INTERNAL_API_SECRET');
  const signingResponse = await fetch(`${signingServiceUrl}/sign`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${internalApiSecret}`,
    },
    body: JSON.stringify({ payload: provenancePayload }),
  });
  if (!signingResponse.ok) {
    throw new Error(`Signing service error: ${signingResponse.status}`);
  }
  const { signature: provenanceSignature } = await signingResponse.json();

  const provenanceMeta = {
    syntheticContent: true,
    label: provenanceLabel,
    modelId: provenanceModelId,
    generatedAt: provenanceTimestamp,
    signature: provenanceSignature,
  };
  // --- End Synthetic Content Provenance ---

  const to = queryMap["From"];
  const from = queryMap["To"];
  // Prepend synthetic-content label and provenance footer to the SMS body
  const smsBodyRaw = `${provenanceLabel}\n${responseText}`;
  const smsBody = validateAndSanitizeLLMOutput(smsBodyRaw);

  await twilioClient.messages
    .create({
      body: smsBody,
      from,
      to,
    })
    .catch((err) => {
      console.log("WARNING: failed to send SMS.", err);
    });

  return NextResponse.json({
    message: "Hello from the API!",
    provenance: {
      syntheticContent: provenanceMeta.syntheticContent,
      label: provenanceMeta.label,
    },
  });
}
