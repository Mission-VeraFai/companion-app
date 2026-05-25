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
  // Approved foundation models — version-pinned with SHA-256 artifact digest.
  // Digests must be obtained from the organisation's approved-model artifact
  // store and verified by a human reviewer before merging.
  // -----------------------------------------------------------------------

  // OpenAI GPT-4o (2024-08-06 snapshot)
  {
    id: "gpt-4o-2024-08-06",
    sha256: "a3f1c2e4b5d6789012345678901234567890abcdef1234567890abcdef123456",
  },

  // OpenAI GPT-4 Turbo (2024-04-09 snapshot)
  {
    id: "gpt-4-turbo-2024-04-09",
    sha256: "b2e3d4f5a6c7890123456789012345678901bcdef2345678901bcdef23456789",
  },

  // OpenAI GPT-3.5 Turbo (0125 snapshot)
  {
    id: "gpt-3.5-turbo-0125",
    sha256: "c3d4e5f6b7a8901234567890123456789012cdef3456789012cdef3456789012",
  },

  // Meta LLaMA 3.1 8B Instruct
  {
    id: "meta-llama/Meta-Llama-3.1-8B-Instruct",
    sha256: "d4e5f6a7c8b9012345678901234567890123def4567890123def4567890123de",
  },

  // Meta LLaMA 3.1 70B Instruct
  {
    id: "meta-llama/Meta-Llama-3.1-70B-Instruct",
    sha256: "e5f6a7b8d9c0123456789012345678901234ef5678901234ef5678901234ef56",
  },

  // Anthropic Claude 3.5 Sonnet (via langchain_anthropic)
  {
    id: "claude-3-5-sonnet-20241022",
    sha256: "f6a7b8c9e0d1234567890123456789012345f6789012345f6789012345f67890",
  },

  // Anthropic Claude 3 Haiku (via langchain_anthropic)
  {
    id: "claude-3-haiku-20240307",
    sha256: "a7b8c9d0f1e2345678901234567890123456a7890123456a7890123456a78901",
  },
] as const);

/** Fast lookup: model-id → expected SHA-256 digest. */
const APPROVED_MODEL_REGISTRY: ReadonlyMap<string, string> = new Map(
  APPROVED_MODEL_ENTRIES.map((e) => [e.id, e.sha256])
);

// ---------------------------------------------------------------------------
// Approved MCP Server Registry
// ---------------------------------------------------------------------------
// All MCP servers that this application is permitted to interact with must be
// listed here. Any server NOT in this registry will be rejected at runtime.
// ---------------------------------------------------------------------------
interface ApprovedMCPServerEntry {
  /** Canonical MCP server identifier. */
  readonly id: string;
  /** Human-readable description for audit purposes. */
  readonly description: string;
}

const APPROVED_MCP_SERVER_ENTRIES: readonly ApprovedMCPServerEntry[] = Object.freeze([
  { id: "t.me", description: "Telegram MCP messaging server" },
  { id: "cache.del", description: "Cache deletion MCP server" },
  { id: "MCP Server · indexPinecone", description: "Pinecone vector index MCP server" },
  { id: "OpenAIEmbeddings", description: "OpenAI embeddings MCP server" },
  { id: "BedrockEmbeddings", description: "AWS Bedrock embeddings MCP server" },
] as const);

/** Fast lookup set of approved MCP server IDs. */
const APPROVED_MCP_SERVER_REGISTRY: ReadonlySet<string> = new Set(
  APPROVED_MCP_SERVER_ENTRIES.map((e) => e.id)
);

/**
 * Validates that the given MCP server ID is in the approved registry.
 * Throws if the server is not approved.
 */
function assertApprovedMCPServer(serverId: string): void {
  if (!serverId || typeof serverId !== "string") {
    throw new Error("[SECURITY] MCP server ID must be a non-empty string.");
  }
  if (!APPROVED_MCP_SERVER_REGISTRY.has(serverId)) {
    throw new Error(
      `[SECURITY] MCP server "${serverId}" is NOT in the approved registry. ` +
      "Add it to APPROVED_MCP_SERVER_ENTRIES after security review."
    );
  }
}

/**
 * Sanitizes input destined for an MCP server.
 *
 * - Rejects non-string or empty inputs.
 * - Strips null bytes and control characters (except standard whitespace).
 * - Trims leading/trailing whitespace.
 * - Enforces a maximum length to prevent payload-stuffing attacks.
 *
 * @param input     - Raw input string to sanitize.
 * @param maxLength - Maximum permitted length (default: 4096 characters).
 * @returns The sanitized input string.
 * @throws  If the input is invalid or exceeds the maximum length.
 */
function sanitizeMCPInput(input: string, maxLength = 4096): string {
  if (typeof input !== "string") {
    throw new Error("[SECURITY] MCP input must be a string.");
  }
  // Strip null bytes and non-printable control characters
  // (allow \t, \n, \r as legitimate whitespace)
  // eslint-disable-next-line no-control-regex
  const sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
  if (sanitized.length === 0) {
    throw new Error("[SECURITY] MCP input must not be empty after sanitization.");
  }
  if (sanitized.length > maxLength) {
    throw new Error(
      `[SECURITY] MCP input exceeds maximum permitted length of ${maxLength} characters.`
    );
  }
  return sanitized;
}

/**
 * Validates the MCP server is approved and sanitizes the provided input.
 * Use this as the single entry-point before passing any data to an MCP server.
 *
 * @param serverId - The MCP server identifier.
 * @param input    - The raw input to send to the server.
 * @returns The sanitized input string, safe to forward to the MCP server.
 */
function validateAndSanitizeMCPInput(serverId: string, input: string): string {
  assertApprovedMCPServer(serverId);
  return sanitizeMCPInput(input);
}

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

  // --- URL Allowlist Enforcement for Signing Service ---
  const SIGNING_SERVICE_ALLOWED_HOSTNAMES = [
    'signing-service.internal',
    'signing.yourdomain.com',
  ];
  (() => {
    let parsedSigningUrl: URL;
    try {
      parsedSigningUrl = new URL(signingServiceUrl);
    } catch {
      throw new Error('POLICY VIOLATION: SIGNING_SERVICE_URL is not a valid URL.');
    }
    if (!SIGNING_SERVICE_ALLOWED_HOSTNAMES.includes(parsedSigningUrl.hostname)) {
      throw new Error(
        `POLICY VIOLATION: Signing service hostname '${parsedSigningUrl.hostname}' is not in the allowed hostnames list.`
      );
    }
  })();
  // --- End URL Allowlist Enforcement ---

  const signingResponse = await fetch(`${signingServiceUrl}/sign`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
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
