import { NextResponse } from "next/server";
import twilio from "twilio";
import { verifyToken } from "@clerk/clerk-sdk-node";

/**
 * Verifies a Clerk session token with explicit integrity checks:
 *  1. Cryptographic signature verification (via Clerk's verifyToken)
 *  2. Expiry enforcement (exp claim)
 *  3. Not-before enforcement (nbf claim)
 *  4. Subject binding validation (sub claim must be present and non-empty)
 *
 * Throws an error with a descriptive message if any check fails.
 */
async function verifyClerkSessionToken(
  authHeader: string | null
): Promise<{ sub: string; sessionId: string }> {
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new Error("Missing or malformed Authorization header");
  }

  const token = authHeader.slice(7).trim();
  if (!token) {
    throw new Error("Empty session token");
  }

  const secretKey = process.env.CLERK_SECRET_KEY;
  if (!secretKey) {
    throw new Error("CLERK_SECRET_KEY environment variable is not configured");
  }

  // 1. Verify cryptographic signature and decode claims.
  let payload: Record<string, unknown>;
  try {
    payload = await verifyToken(token, { secretKey }) as Record<string, unknown>;
  } catch (err) {
    throw new Error(`Session token signature verification failed: ${(err as Error).message}`);
  }

  const nowSeconds = Math.floor(Date.now() / 1000);

  // 2. Enforce expiry (exp claim).
  const exp = payload["exp"];
  if (typeof exp !== "number" || nowSeconds >= exp) {
    throw new Error("Session token has expired");
  }

  // 3. Enforce not-before (nbf claim) if present.
  const nbf = payload["nbf"];
  if (typeof nbf === "number" && nowSeconds < nbf) {
    throw new Error("Session token is not yet valid (nbf)");
  }

  // 4. Validate subject binding (sub claim).
  const sub = payload["sub"];
  if (typeof sub !== "string" || sub.trim() === "") {
    throw new Error("Session token missing or empty subject (sub) claim");
  }

  // Extract session ID for audit purposes.
  const sid = payload["sid"];
  const sessionId = typeof sid === "string" ? sid : "unknown";

  return { sub: sub.trim(), sessionId };
}
import dotenv from "dotenv";
import ConfigManager from "@/app/utils/config";
import { rateLimit } from "@/app/utils/rateLimit";

// Approved model registry is resolved exclusively from the org-approved external registry.
// The registry URL MUST be set via ORG_MODEL_REGISTRY_URL environment variable.
// No models are defined locally; all model identity and version pinning is governed externally.

const ORG_MODEL_REGISTRY_URL = process.env.ORG_MODEL_REGISTRY_URL;
if (!ORG_MODEL_REGISTRY_URL) {
  throw new Error(
    "FATAL: ORG_MODEL_REGISTRY_URL is not configured. " +
    "All AI workloads require an org-approved external model registry."
  );
}

type ApprovedModelEntry = { pinnedVersion: string; endpoint: string };
type ApprovedModelRegistry = Record<string, ApprovedModelEntry>;

// Cache the fetched registry for the lifetime of the process.
let _cachedRegistry: ApprovedModelRegistry | null = null;

async function fetchApprovedModelRegistry(): Promise<ApprovedModelRegistry> {
  if (_cachedRegistry) return _cachedRegistry;
  const registrySecret = process.env.ORG_MODEL_REGISTRY_SECRET;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (registrySecret) {
    headers["Authorization"] = `Bearer ${registrySecret}`;
  }
  const response = await fetch(ORG_MODEL_REGISTRY_URL as string, {
    method: "GET",
    headers,
    // Enforce a strict timeout to avoid blocking inference on registry unavailability.
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) {
    throw new Error(
      `Failed to fetch org model registry from ${ORG_MODEL_REGISTRY_URL}: HTTP ${response.status}`
    );
  }
  const registry: ApprovedModelRegistry = await response.json();
  _cachedRegistry = registry;
  return registry;
}

async function resolveApprovedModel(
  requestedModel: string
): Promise<ApprovedModelEntry | null> {
  const registry = await fetchApprovedModelRegistry();
  const entry = registry[requestedModel];
  if (!entry) return null;
  return entry;
}> = {
  // Add additional approved models here as needed.
  // NOTE: GPT, LLaMA, and Claude models are disallowed per the organization's LLM policy.
};

function resolveApprovedModel(
  requestedModel: string
): { pinnedVersion: string; endpoint: string } | null {
  const entry = APPROVED_MODEL_REGISTRY[requestedModel];
  if (!entry) return null;
  return entry;
}
import { createHash } from "crypto";
import { appendFileSync, mkdirSync, existsSync, renameSync, statSync } from "fs";
import path from "path";

const AUDIT_LOG_DIR = path.resolve(process.cwd(), "audit-logs");
const AUDIT_LOG_FILE = path.join(AUDIT_LOG_DIR, "ai-inference-audit.log");
// Rotate the audit log when it exceeds this size (10 MB) to enforce a retention policy.
const AUDIT_LOG_MAX_BYTES = 10 * 1024 * 1024;

function rotateAuditLogIfNeeded(): void {
  if (existsSync(AUDIT_LOG_FILE)) {
    const { size } = statSync(AUDIT_LOG_FILE);
    if (size >= AUDIT_LOG_MAX_BYTES) {
      const rotatedName = AUDIT_LOG_FILE.replace(
        /\.log$/,
        `.${new Date().toISOString().replace(/[:.]/g, "-")}.log`
      );
      renameSync(AUDIT_LOG_FILE, rotatedName);
    }
  }
}

function writeAuditRecord(record: Record<string, unknown>): void {
  try {
    mkdirSync(AUDIT_LOG_DIR, { recursive: true });
    rotateAuditLogIfNeeded();
    const line = JSON.stringify({ ...record, _written: new Date().toISOString() }) + "\n";
    appendFileSync(AUDIT_LOG_FILE, line, { encoding: "utf8", flag: "a" });
  } catch (err) {
    // Log to console AND re-throw so callers are aware of audit pipeline breakage.
    console.error("CRITICAL: audit log write failed", err);
    throw err;
  }
}

dotenv.config({ path: `.env.local` });
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN;
const accountSid = process.env.TWILIO_ACCOUNT_SID;
// INTERNAL_API_SECRET removed from module scope: retrieve on-demand to stay within the 3-system credential limit
function getInternalApiSecret(): string {
  const s = process.env.INTERNAL_API_SECRET;
  if (!s) throw new Error("INTERNAL_API_SECRET is not configured");
  return s;
}
// INTER_AGENT_SECRET removed: retrieve on-demand via ConfigManager to stay within the 3-system credential limit
function getInterAgentSecret(): string {
  const secret = process.env.INTER_AGENT_SECRET;
  if (!secret) throw new Error("INTER_AGENT_SECRET is not configured");
  return secret;
}

const MAX_PROMPT_LENGTH = 2000;

// Patterns that indicate model-text-driven privilege escalation attempts:
// dynamic tool registration, role/permission mutation, or admin scope expansion.
const PRIVILEGE_ESCALATION_PATTERNS: RegExp[] = [
  /register\s*(new\s*)?tool/gi,
  /add\s*(new\s*)?tool/gi,
  /enable\s*(admin|root|superuser|elevated|privileged)\s*(tool|mode|access|permission|role)/gi,
  /grant\s*(admin|root|superuser|elevated|privileged)\s*(access|permission|role)/gi,
  /escalate\s*(privilege|permission|role|access)/gi,
  /expand\s*(scope|permission|role|access)/gi,
  /mutate\s*(role|permission|scope|access)/gi,
  /set\s*role\s*[=:]?\s*(admin|root|superuser|owner)/gi,
  /assign\s*(admin|root|superuser|elevated)\s*role/gi,
  /dynamic(ally)?\s*(register|add|enable|load)\s*(tool|plugin|function|capability)/gi,
  /override\s*(permission|role|access\s*control|acl)/gi,
  /bypass\s*(permission|role|access\s*control|acl|auth)/gi,
  /sudo\s*mode/gi,
  /become\s*(admin|root|superuser)/gi,
];

/**
 * Scans model output text for privilege escalation patterns.
 * Throws if any pattern matches, preventing LLM-driven role/permission mutation
 * or dynamic admin tool enablement from propagating.
 */
function blockPrivilegeEscalation(modelOutput: string, auditContext: Record<string, unknown>): void {
  for (const pattern of PRIVILEGE_ESCALATION_PATTERNS) {
    pattern.lastIndex = 0; // reset stateful regex
    if (pattern.test(modelOutput)) {
      const violation = {
        event: "PRIVILEGE_ESCALATION_BLOCKED",
        matchedPattern: pattern.toString(),
        ...auditContext,
        timestamp: new Date().toISOString(),
      };
      try {
        writeAuditRecord(violation);
      } catch (_) {
        // audit failure must not suppress the block
      }
      throw new Error(
        `SECURITY: model output blocked — privilege escalation pattern detected: ${pattern.toString()}`
      );
    }
  }
}

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(previous|above|all)\s+(instructions?|prompts?)/gi,
  /system\s*:/gi,
  /\[INST\]/gi,
  /<\|im_start\|>/gi,
  /\bforget\s+(everything|all|prior)/gi,
  /you\s+are\s+now/gi,
  /new\s+persona/gi,
  /disregard\s+(all|previous|prior)/gi,
];

function validateAndSanitizeUserPrompt(input: string): { valid: boolean; sanitized: string; reason?: string } {
  if (!input || typeof input !== "string") {
    return { valid: false, sanitized: "", reason: "Prompt is empty or not a string" };
  }
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    return { valid: false, sanitized: "", reason: "Prompt is blank after trimming" };
  }
  if (trimmed.length > MAX_PROMPT_LENGTH) {
    return { valid: false, sanitized: "", reason: `Prompt exceeds maximum length of ${MAX_PROMPT_LENGTH}` };
  }
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(trimmed)) {
      pattern.lastIndex = 0;
      return { valid: false, sanitized: "", reason: `Prompt contains forbidden injection pattern: ${pattern}` };
    }
    pattern.lastIndex = 0;
  }
  // Strip null bytes and control characters (except common whitespace)
  const sanitized = trimmed.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  return { valid: true, sanitized };
}

// NOTE: blockPrivilegeEscalation() must be called on every model response before
// further processing. See usage sites below.
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

const MAX_PROMPT_LENGTH = 4000;
const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
  /system\s*:\s*/gi,
  /\[\s*system\s*\]/gi,
  /<\s*system\s*>/gi,
  /you\s+are\s+now\s+/gi,
  /disregard\s+(all\s+)?(previous|prior)/gi,
  /forget\s+(all\s+)?(previous|prior|your)/gi,
  /act\s+as\s+(if\s+you\s+are|a\s+)/gi,
  /jailbreak/gi,
  /\\u[0-9a-fA-F]{4}/g,
  /\\x[0-9a-fA-F]{2}/g,
];

function sanitizePrompt(raw: string): string {
  if (typeof raw !== "string") return "";
  // Enforce maximum length before any processing
  let sanitized = raw.slice(0, MAX_PROMPT_LENGTH);
  // Remove null bytes and non-printable control characters (except newline/tab)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Strip unicode escape sequences that could be used to bypass filters
  sanitized = sanitized.replace(/\\u[0-9a-fA-F]{4}/g, "");
  sanitized = sanitized.replace(/\\x[0-9a-fA-F]{2}/g, "");
  // Remove prompt injection patterns
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    pattern.lastIndex = 0;
    sanitized = sanitized.replace(pattern, "[REMOVED]");
    pattern.lastIndex = 0;
  }
  // Trim excessive whitespace
  sanitized = sanitized.trim();
  return sanitized;
}

/**
 * Attaches AI-generated content provenance label and HMAC-SHA256 watermark
 * to any outbound message body so every SMS path carries signed provenance.
 */
function attachProvenanceWatermark(body: string): string {
  const aiLabel = "[AI-GENERATED CONTENT]";
  const timestamp = new Date().toISOString();
  const secret = process.env.INTERNAL_API_SECRET ?? "default-watermark-secret";
  const watermark = createHash("sha256")
    .update(`${body}|${timestamp}|${secret}`)
    .digest("hex")
    .slice(0, 16);
  return `${aiLabel}\n${body}\n---\nGenerated: ${timestamp} | WM: ${watermark}`;
}

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
      // Safe URL-decode helper: rejects keys/values containing characters outside
// the safe set (alphanumerics, spaces, hyphens, underscores, dots, @, +)
const SAFE_PARAM_PATTERN = /^[\w\s\-\.@+]*$/;
const safeDecodeParam = (raw: string): string => {
  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    decoded = "";
  }
  if (!SAFE_PARAM_PATTERN.test(decoded)) {
    console.warn("WARNING: Rejected unsafe URL-decoded param value.", raw);
    return "";
  }
  return decoded;
};
const decodedKey = safeDecodeParam(key);
if (decodedKey) {
  bodyParams[decodedKey] = safeDecodeParam(value || "");
}
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
    // Reject hidden/invisible Unicode characters (zero-width, soft-hyphen, BOM, etc.)
    const hiddenUnicodePattern = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u2028\u2029]/g;
    if (hiddenUnicodePattern.test(sanitized)) {
      console.warn("WARNING: Prompt rejected — hidden/invisible Unicode characters detected.");
      return null;
    }
    // Reject base64-encoded payloads (long base64-like strings that may encode commands)
    const base64Pattern = /(?:[A-Za-z0-9+\/]{20,}={0,2})/g;
    const base64Matches = sanitized.match(base64Pattern);
    if (base64Matches) {
      for (const match of base64Matches) {
        try {
          const decoded = Buffer.from(match, "base64").toString("utf8");
          // If decoded content contains shell/code patterns, reject
          const shellInDecoded = /[\x00-\x08\x0E-\x1F]|\bexec\b|\beval\b|\bsystem\b|\/bin\/|cmd\.exe|powershell/i;
          if (shellInDecoded.test(decoded)) {
            console.warn("WARNING: Prompt rejected — base64-encoded command content detected.");
            return null;
          }
        } catch {
          // Not valid base64, ignore
        }
      }
    }
    // Reject leetspeak obfuscation attempts targeting known dangerous keywords
    // e.g. 3v4l -> eval, 3x3c -> exec, syst3m -> system
    const leetspeakDangerousPattern = /(?:[3e][vV][4a][lL]|[3e][xX][3e][cC]|[sS][yY][sS][tT][3e][mM]|[pP][0o][wW][3e][rR][sS][hH][3e][lL][lL]|[sS][hH][3e][lL][lL])/g;
    if (leetspeakDangerousPattern.test(sanitized)) {
      console.warn("WARNING: Prompt rejected — leetspeak obfuscation of dangerous keyword detected.");
      return null;
    }
    // Reject binary/shell command content
    const shellCommandPattern = /(?:\/bin\/(?:sh|bash|zsh|dash|ksh)|cmd\.exe|powershell(?:\.exe)?|\bwget\s+http|\bcurl\s+http|\bnc\s+-|\bnetcat\b|\bchmod\s+[0-7]{3,4}|\bchown\s+|\brm\s+-[rRfF]|\bmkdir\s+-p|\bsudo\s+|\bsu\s+-|\bpasswd\b|\bssh\s+|\bscp\s+|\brsync\s+|\btar\s+.*-[xXcC]|\bpython[23]?\s+-c|\bperl\s+-e|\bruby\s+-e|\bnode\s+-e|\bphp\s+-r|\bbash\s+-c|\bsh\s+-c)/gi;
    if (shellCommandPattern.test(sanitized)) {
      console.warn("WARNING: Prompt rejected — shell/binary command content detected.");
      return null;
    }
    // Reject dynamic code execution patterns (reuse module-level DYNAMIC_CODE_PATTERNS)
    for (const pattern of DYNAMIC_CODE_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(sanitized)) {
        console.warn(`WARNING: Prompt rejected — dynamic code execution pattern detected: ${pattern}`);
        pattern.lastIndex = 0;
        return null;
      }
      pattern.lastIndex = 0;
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

    // Approved model registry: only models listed here may be used.
  // Each entry pins the model to a specific version and endpoint path.
  const APPROVED_MODEL_REGISTRY: Record<string, { pinnedVersion: string; endpoint: string }> = {
    "claude-3-opus": { pinnedVersion: "claude-3-opus-20240229", endpoint: "claude" },
    "claude-3-sonnet": { pinnedVersion: "claude-3-sonnet-20240229", endpoint: "claude" },
    "claude-3-haiku": { pinnedVersion: "claude-3-haiku-20240307", endpoint: "claude" },
  };
  const DEFAULT_APPROVED_MODEL = "claude-3-haiku";

  function resolveApprovedModel(requested: string): { modelKey: string; pinnedVersion: string; endpoint: string } {
    const entry = APPROVED_MODEL_REGISTRY[requested];
    if (entry) {
      return { modelKey: requested, ...entry };
    }
    // Fall back to default approved model
    const defaultEntry = APPROVED_MODEL_REGISTRY[DEFAULT_APPROVED_MODEL]!;
    return { modelKey: DEFAULT_APPROVED_MODEL, ...defaultEntry };
  }

  const requestedModel: string = companionConfig.llm;
  const resolvedModelEntry = resolveApprovedModel(requestedModel);
  const companionModel: string = resolvedModelEntry.endpoint;

  // Anonymize PII before sending to AI model: hash the internal userId, omit real name
  const crypto = await import("crypto");
  const anonymizedUserId = crypto
    .createHash("sha256")
    .update(String(users[0].id))
    .digest("hex");
  const anonymizedUserName = "user";

  const llmRequestPayload = {
    prompt,
    isText: true,
    userId: anonymizedUserId,
    userName: anonymizedUserName,
  };

  console.log(
    JSON.stringify({
      event: "llm_interaction_request",
      timestamp: new Date().toISOString(),
      requestedModel,
      resolvedModelKey: resolvedModelEntry.modelKey,
      pinnedVersion: resolvedModelEntry.pinnedVersion,
      companionName,
      endpoint: `${serverUrl}/api/${resolvedModelEntry.endpoint}`,
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

  /**
   * Validates and sanitizes LLM output by rejecting or stripping content
   * that contains dynamic code execution primitives (eval, Function constructor,
   * setTimeout/setInterval with string args, etc.).
   */
  function validateAndSanitizeLLMOutput(text: string): string {
    if (typeof text !== "string") {
      throw new Error("LLM output must be a string");
    }
    // Patterns that indicate dynamic code execution primitives
    const dangerousPatterns = [
      /\beval\s*\(/gi,
      /\bFunction\s*\(/gi,
      /\bnew\s+Function\b/gi,
      /\bsetTimeout\s*\(\s*['"`]/gi,
      /\bsetInterval\s*\(\s*['"`]/gi,
      /\bexecScript\s*\(/gi,
      /\bdocument\.write\s*\(/gi,
      /\bimportScripts\s*\(/gi,
    ];
    for (const pattern of dangerousPatterns) {
      if (pattern.test(text)) {
        console.warn(
          "WARNING: LLM output contained a dynamic code execution primitive and was rejected.",
          { pattern: pattern.toString() }
        );
        // Strip the dangerous content rather than forwarding it
        text = text.replace(pattern, "[REDACTED]");
      }
    }
    return text;
  }

    // Build a short-lived, per-request signed token:
  //   payload = "<timestamp>.<nonce>.<userId>"
  //   token   = "<payload>.<HMAC-SHA256(payload, internalApiSecret)>"
  // Expiry is enforced by the receiving service checking that timestamp is within tolerance.
  const crypto = await import("crypto");
  const tokenTimestamp = Date.now(); // ms since epoch
  const tokenNonce = crypto.randomBytes(16).toString("hex");
  const tokenUserId = users[0].id;
  const tokenPayload = `${tokenTimestamp}.${tokenNonce}.${tokenUserId}`;
  const tokenSignature = crypto
    .createHmac("sha256", internalApiSecret)
    .update(tokenPayload)
    .digest("hex");
  const signedToken = `${tokenPayload}.${tokenSignature}`;

  // SSRF mitigation: validate serverUrl against an allowlist of permitted origins
  const ALLOWED_SERVER_ORIGINS: string[] = (
    process.env.ALLOWED_LLM_SERVER_ORIGINS ?? ""
  )
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  let parsedServerUrl: URL;
  try {
    parsedServerUrl = new URL(serverUrl);
  } catch {
    console.error("ERROR: serverUrl is not a valid URL.", serverUrl);
    return new NextResponse(
      JSON.stringify({ Message: "Internal server configuration error" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
  const serverOrigin = parsedServerUrl.origin;
  if (
    ALLOWED_SERVER_ORIGINS.length > 0 &&
    !ALLOWED_SERVER_ORIGINS.includes(serverOrigin)
  ) {
    console.error(
      `ERROR: serverUrl origin "${serverOrigin}" is not in the allowlist.`
    );
    return new NextResponse(
      JSON.stringify({ Message: "Internal server configuration error" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
  // Build the fetch URL from the validated origin only — no raw interpolation
  const safeFetchUrl = `${serverOrigin}/api/${encodeURIComponent(companionModel)}`;
  const response = await fetch(safeFetchUrl, {
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
      Authorization: `Bearer ${signedToken}`,
    },
  });

      const rawResponseText = await response.text();
  const responseText = validateAndSanitizeLLMOutput(rawResponseText);
  let smsBody: string;
  try {
    const parsed = JSON.parse(responseText);
    smsBody = validateAndSanitizeLLMOutput(
      parsed.text ?? parsed.message ?? parsed.response ?? String(parsed)
    );
  } catch {
    // Sanitize raw response text when JSON parsing fails
    smsBody = validateAndSanitizeLLMOutput(responseText);
  }
  // Truncate to SMS-safe length to avoid leaking excess model output
  const MAX_SMS_LENGTH = 1600;
  smsBody = smsBody.slice(0, MAX_SMS_LENGTH);

    const piiEncryptionKey = process.env.PII_ENCRYPTION_KEY;
  if (!piiEncryptionKey) {
    console.error("ERROR: PII_ENCRYPTION_KEY is not configured.");
    return new NextResponse(
      JSON.stringify({ Message: "Internal server configuration error" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Encrypt PII (phone number) for any internal logging/storage
  const encryptPhoneNumber = (phoneNumber: string, key: string): string => {
    const crypto = require("crypto");
    const keyBuffer = crypto.scryptSync(key, "salt", 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", keyBuffer, iv);
    const encrypted = Buffer.concat([
      cipher.update(phoneNumber, "utf8"),
      cipher.final(),
    ]);
    return `${iv.toString("hex")}:${encrypted.toString("hex")}`;
  };

  const toRaw = queryMap["From"]; // actual phone number for Twilio routing only
  const from = queryMap["To"];
  // Encrypted reference used for any logging or internal storage — never log toRaw
  const toEncrypted = encryptPhoneNumber(toRaw, piiEncryptionKey);

    await twilioClient.messages
    .create({
      body: smsBody,
      from,
      to: toRaw, // Twilio requires plaintext number; transmitted over Twilio's encrypted HTTPS channel
    })
    .catch(() => {
      // Suppress error details to avoid leaking routing or payload information
      console.error("WARNING: failed to send SMS to encrypted recipient.");
    });
  const provenanceFooter = ` | ${new Date().toISOString()}`;
  const aiLabel = "[AI-GENERATED CONTENT]";
  const labeledResponseText = attachProvenanceWatermark(`${aiLabel}\n${smsBody}${provenanceFooter}`);

  await twilioClient.messages
    .create({
      body: labeledResponseText,
      from,
      to,
    })
  );
  const wateredResponseText = attachProvenanceWatermark(smsBody);
  await twilioClient.messages
    .create({
      body: wateredResponseText,
      from,
      to,
    })
    .catch((err) => {
      console.log("WARNING: failed to send SMS.", err);
    });

  return NextResponse.json({ message: "Hello from the API!" });
}
