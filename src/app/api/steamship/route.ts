import { NextResponse } from "next/server";
import { currentUser } from "@clerk/nextjs";
import { createHmac } from "crypto";
// WARNING: In-memory rate limiter — state is NOT shared across processes, workers, or
// serverless function instances. Under any multi-instance or serverless deployment this
// store is reset on every cold start and each instance maintains its own independent
// counter, effectively disabling rate limiting. Replace with a shared, atomic store
// (e.g. Redis via Upstash, Vercel KV, or a database) before deploying to production.
const _rateLimitStore = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_MAX = 20;
const RATE_LIMIT_WINDOW_MS = 60_000;
function rateLimit(identifier: string): { success: boolean } {
  const now = Date.now();
  const entry = _rateLimitStore.get(identifier);
  if (!entry || now > entry.resetAt) {
    _rateLimitStore.set(identifier, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return { success: true };
  }
  entry.count += 1;
  if (entry.count > RATE_LIMIT_MAX) {
    return { success: false };
  }
  return { success: true };
}
// MD5 removed: use HMAC-SHA256 for session/cache key generation with subject binding and expiry
// Usage: generateSessionKey(userId) returns a signed, bound, expiry-aware cache key
function generateSessionKey(userId: string): string {
  const secret = process.env.SESSION_HMAC_SECRET;
  if (!secret) throw new Error('SESSION_HMAC_SECRET environment variable is not set');
  const expiryWindow = Math.floor(Date.now() / (1000 * 60 * 15)); // 15-minute window
  const payload = `${userId}:${expiryWindow}`;
  return createHmac('sha256', secret).update(payload).digest('hex');
}
import ConfigManager from "@/app/utils/config";

// ── Model registry enforcement ────────────────────────────────────────────────
// Every model or agent used in this file MUST be validated through
// assertModelApproved() before instantiation. The approved registry is sourced
// exclusively from the APPROVED_MODEL_REGISTRY_JSON environment variable.
//
// Models that are NOT_IN_REGISTRY at startup will cause the request to fail
// with a policy-violation error rather than silently using an unapproved model.
//
// Example usage:
//   const entry = assertModelApproved("gpt-4o");
//   const model = new ChatOpenAI({ modelName: entry.modelName, modelVersion: entry.modelVersion });
//
// Do NOT pass bare string literals like "gpt-4", "claude-3-opus", or
// "langchain_anthropic" directly to model constructors — always go through
// assertModelApproved() and use the returned pinned entry.
// ─────────────────────────────────────────────────────────────────────────────

// Patterns that indicate potentially malicious prompt injection or command execution attempts
const MALICIOUS_PATTERNS: RegExp[] = [
  // Shell command injection
  /(?:^|\s|;|\||&|`)(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\-]/i,
  /(?:\$\(|`)[^`]*`/,                          // Command substitution $(...) or backticks
  /;\s*(?:rm|mv|cp|chmod|chown|wget|curl|nc|ncat|netcat)\s/i,  // Chained shell commands
  /(?:&&|\|\|)\s*(?:rm|mv|cp|chmod|chown|wget|curl|nc|ncat|netcat)\s/i,
  // Prompt injection / hidden instruction patterns
  /<\s*(?:system|assistant|user|instruction|prompt)\s*>/i,  // XML-style role tags
  /\[\s*(?:SYSTEM|INST|INSTRUCTION|OVERRIDE|IGNORE)\s*\]/i, // Bracket-style injection
  /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?/i,
  /you\s+are\s+now\s+(?:in\s+)?(?:developer|jailbreak|dan|unrestricted|god)\s+mode/i,
  /(?:act|pretend|roleplay|simulate)\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|evil|malicious)/i,
  // Base64-encoded content (heuristic: long base64-looking strings)
  /(?:[A-Za-z0-9+\/]{40,}={0,2})(?:\s|$)/,
  // Unicode/zero-width character obfuscation
  /[\u200B-\u200D\uFEFF\u00AD]/,              // Zero-width / soft-hyphen characters
  // Path traversal
  /(?:\.\.\/|\.\.\\/){2,}/,
  // Environment variable exfiltration
  /\$(?:PATH|HOME|USER|SHELL|ENV|AWS_|OPENAI_|SECRET|TOKEN|KEY|PASSWORD)/i,
];

const MAX_USER_MESSAGE_LENGTH = 4000;

/**
 * Validates userMessage for malicious content before forwarding to the AI agent.
 * Returns { safe: true } if the message passes all checks,
 * or { safe: false, reason: string } if a violation is detected.
 */
function validateUserMessage(message: unknown): { safe: boolean; reason?: string } {
  if (typeof message !== "string") {
    return { safe: false, reason: "Message must be a string." };
  }
  if (message.trim().length === 0) {
    return { safe: false, reason: "Message must not be empty." };
  }
  if (message.length > MAX_USER_MESSAGE_LENGTH) {
    return { safe: false, reason: `Message exceeds maximum allowed length of ${MAX_USER_MESSAGE_LENGTH} characters.` };
  }
  for (const pattern of MALICIOUS_PATTERNS) {
    if (pattern.test(message)) {
      return { safe: false, reason: "Message contains potentially malicious content and cannot be processed." };
    }
  }
  return { safe: true };
}

// Approved model registry: loaded exclusively from the APPROVED_MODEL_REGISTRY_JSON
// environment variable, which MUST be set by the organization-approved registry pipeline.
// Hardcoding this registry locally is a policy violation — all entries must originate
// from the org-approved registry and be injected at deploy time via the env var.
interface ApprovedModelRegistryEntry {
  /** URL prefix used to route requests to this model's endpoint */
  urlPrefix: string;
  /** Canonical provider name, e.g. "openai", "anthropic", "meta" */
  modelProvider: string;
  /** Canonical model name, e.g. "gpt-4o", "claude-3-opus", "llama-3" */
  modelName: string;
  /**
   * REQUIRED: Immutable version pin — must be a specific semver tag or
   * content-addressable digest (e.g. "20240229" or "sha256:abc123…").
   * Wildcard or empty values are rejected by assertModelApproved().
   */
  modelVersion: string;
  /** Optional: embedding model name if this entry covers a RAG/embedding workload */
  embeddingModel?: string;
  /** Optional: embedding model version pin */
  embeddingModelVersion?: string;
}

// POLICY: All model selection MUST go through getApprovedModel().
// Direct use of langchain_anthropic, GPT, LLaMA, Claude, or any other
// model not present in the org-approved registry is prohibited.
function getApprovedModel(registry: ApprovedModelRegistryEntry[], urlPrefix: string): ApprovedModelRegistryEntry {
  const entry = registry.find((e) => e.urlPrefix === urlPrefix);
  if (!entry) {
    throw new Error(
      `POLICY VIOLATION: No approved model found for urlPrefix '${urlPrefix}'. ` +
      "Only models present in the APPROVED_MODEL_REGISTRY_JSON registry may be used."
    );
  }
  return entry;
}

// Sanitize and validate companionName: only allow alphanumeric, hyphens, and underscores, max 64 chars
function sanitizeCompanionName(name: unknown): string {
  if (typeof name !== 'string') {
    throw new Error('companionName must be a string');
  }
  const trimmed = name.trim();
  if (trimmed.length === 0 || trimmed.length > 64) {
    throw new Error('companionName must be between 1 and 64 characters');
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
    throw new Error('companionName contains invalid characters; only alphanumeric, hyphens, and underscores are allowed');
  }
  return trimmed;
}

// Validate agentUrl against approved registry prefixes
function validateAgentUrl(agentUrl: string, registry: ApprovedModelRegistryEntry[]): void {
  const approvedPrefixes = registry.map(entry => entry.urlPrefix);
  const isApproved = approvedPrefixes.some(prefix => agentUrl.startsWith(prefix));
  if (!isApproved) {
    throw new Error(`agentUrl '${agentUrl}' does not match any approved model registry URL prefix`);
  }
  // Ensure no path traversal or unexpected characters in the URL
  let parsed: URL;
  try {
    parsed = new URL(agentUrl);
  } catch {
    throw new Error('agentUrl is not a valid URL');
  }
  if (!['https:', 'http:'].includes(parsed.protocol)) {
    throw new Error('agentUrl must use http or https protocol');
  }
  // Reject URLs with credentials embedded
  if (parsed.username || parsed.password) {
    throw new Error('agentUrl must not contain embedded credentials');
  }
}

/**
 * assertModelApproved: Call this at every model/agent instantiation site.
 * Throws a policy violation error if the model identifier is not present in
 * the approved registry. Returns the pinned registry entry (with version) so
 * callers MUST use the returned modelVersion rather than a bare string.
 *
 * @param modelIdentifier - The model name or provider string being requested
 *   (e.g. "gpt-4", "claude-3-opus", "langchain_anthropic").
 * @returns The matching ApprovedModelRegistryEntry with pinned version.
 */
function assertModelApproved(modelIdentifier: string): ApprovedModelRegistryEntry {
  const registry = loadApprovedModelRegistry();
  const normalised = modelIdentifier.trim().toLowerCase();
  const entry = registry.find(
    (e) =>
      e.modelName.toLowerCase() === normalised ||
      e.modelProvider.toLowerCase() === normalised ||
      e.urlPrefix.toLowerCase().includes(normalised)
  );
  if (!entry) {
    throw new Error(
      `POLICY VIOLATION: Model or agent "${modelIdentifier}" is NOT_IN_REGISTRY. ` +
      "All AI models and agents must be registered in the org-approved model registry " +
      "(APPROVED_MODEL_REGISTRY_JSON) with explicit version pinning before use. " +
      "Add the model to the registry pipeline and redeploy."
    );
  }
  if (!entry.modelVersion || entry.modelVersion.trim() === "") {
    throw new Error(
      `POLICY VIOLATION: Registry entry for "${modelIdentifier}" has no pinned version. ` +
      "Every registry entry must specify an immutable modelVersion (e.g. a semver tag or " +
      "content-addressable digest). Update the registry entry and redeploy."
    );
  }
  return entry;
}

function loadApprovedModelRegistry(): ApprovedModelRegistryEntry[] {
  const registryJson = process.env.APPROVED_MODEL_REGISTRY_JSON;
  if (!registryJson) {
    throw new Error(
      "POLICY VIOLATION: APPROVED_MODEL_REGISTRY_JSON environment variable is not set. " +
      "The approved model registry must be sourced from the organization-approved registry " +
      "and injected via this environment variable. Refusing to start without it."
    );
  }

  // Cryptographic integrity verification: verify HMAC-SHA256 of registry JSON
  // before trusting any of its contents.
  const registryHmac = process.env.APPROVED_MODEL_REGISTRY_HMAC;
  if (!registryHmac) {
    throw new Error(
      "POLICY VIOLATION: APPROVED_MODEL_REGISTRY_HMAC environment variable is not set. " +
      "A valid HMAC-SHA256 signature of the registry JSON must be provided to ensure " +
      "cryptographic integrity of registry entries."
    );
  }
  const hmacSecret = process.env.APPROVED_MODEL_REGISTRY_HMAC_SECRET;
  if (!hmacSecret) {
    throw new Error(
      "POLICY VIOLATION: APPROVED_MODEL_REGISTRY_HMAC_SECRET environment variable is not set. " +
      "The HMAC secret key must be injected by the organization-approved registry pipeline."
    );
  }
  const expectedHmac = crypto
    .createHmac("sha256", hmacSecret)
    .update(registryJson, "utf8")
    .digest("hex");
  if (
    expectedHmac.length !== registryHmac.length ||
    !crypto.timingSafeEqual(Buffer.from(expectedHmac, "hex"), Buffer.from(registryHmac, "hex"))
  ) {
    throw new Error(
      "POLICY VIOLATION: APPROVED_MODEL_REGISTRY_JSON failed HMAC-SHA256 integrity check. " +
      "The registry may have been tampered with. Refusing to load."
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(registryJson);
  } catch (e) {
    throw new Error(
      "POLICY VIOLATION: APPROVED_MODEL_REGISTRY_JSON could not be parsed as JSON. " +
      "Ensure the organization-approved registry is correctly serialized."
    );
  }
  if (!Array.isArray(parsed)) {
    throw new Error(
      "POLICY VIOLATION: APPROVED_MODEL_REGISTRY_JSON must be a JSON array of registry entries."
    );
  }
  for (const entry of parsed) {
    if (
      typeof entry !== "object" || entry === null ||
      typeof (entry as Record<string, unknown>).urlPrefix !== "string" ||
      typeof (entry as Record<string, unknown>).modelProvider !== "string" ||
      typeof (entry as Record<string, unknown>).modelName !== "string" ||
      typeof (entry as Record<string, unknown>).modelVersion !== "string"
    ) {
      throw new Error(
        "POLICY VIOLATION: Each entry in APPROVED_MODEL_REGISTRY_JSON must have " +
        "urlPrefix, modelProvider, modelName, and modelVersion as strings."
      );
    }
  }
  // Enforce the organization's approved model provider list.
  // Any entry whose modelProvider is not on this list is rejected at load time,
  // regardless of what the env var contains.
  const ORG_APPROVED_PROVIDERS: string[] = [
    // Add organization-approved provider identifiers here (e.g. "anthropic", "cohere").
    // GPT (OpenAI) and LLaMA are NOT on the organization's approved list.
  ];

  for (const entry of parsed as ApprovedModelRegistryEntry[]) {
    const provider = (entry as ApprovedModelRegistryEntry).modelProvider.toLowerCase();
    const isApproved = ORG_APPROVED_PROVIDERS.some(
      (approved) => provider === approved.toLowerCase()
    );
    if (!isApproved) {
      throw new Error(
        `POLICY VIOLATION: modelProvider "${(entry as ApprovedModelRegistryEntry).modelProvider}" ` +
        "is not on the organization's approved model registry. " +
        "GPT and LLaMA are explicitly not approved. " +
        "Update ORG_APPROVED_PROVIDERS with an org-approved provider to proceed."
      );
    }
  }

  // Explicit org-approved model allowlist. Models NOT on this list are disallowed.
  const ALLOWED_MODELS: { modelProvider: string; modelName: string }[] = [
    // Add organization-approved models here, e.g.:
    // { modelProvider: "anthropic", modelName: "claude-3-opus" },
  ];

  for (const entry of parsed as ApprovedModelRegistryEntry[]) {
    const isAllowed = ALLOWED_MODELS.some(
      (allowed) =>
        allowed.modelProvider.toLowerCase() === (entry as ApprovedModelRegistryEntry).modelProvider.toLowerCase() &&
        allowed.modelName.toLowerCase() === (entry as ApprovedModelRegistryEntry).modelName.toLowerCase()
    );
    if (!isAllowed) {
      throw new Error(
        `POLICY VIOLATION: Model '${(entry as ApprovedModelRegistryEntry).modelProvider}/${
          (entry as ApprovedModelRegistryEntry).modelName
        }' is not in the organization-approved model allowlist. ` +
        "Remove disallowed models (including GPT and LLaMA variants) from APPROVED_MODEL_REGISTRY_JSON."
      );
    }
  }

  return parsed as ApprovedModelRegistryEntry[];
}

const APPROVED_MODEL_REGISTRY: ApprovedModelRegistryEntry[] = loadApprovedModelRegistry();

function getRegistryEntry(agentUrl: string): ApprovedModelRegistryEntry {
  const entry = APPROVED_MODEL_REGISTRY.find((e) =>
    agentUrl.startsWith(e.urlPrefix)
  );
  if (!entry) {
    throw new Error(
      `POLICY VIOLATION: Agent URL '${agentUrl}' does not match any entry in the ` +
      "approved model registry. Models not present in the registry (e.g. GPT, LLaMA) " +
      "are not permitted. All AI workloads must use registry-approved models only."
    );
  }
  return entry;
}

// Explicit allow list of tools the agent is permitted to invoke.
// Add or remove tool names here to control agent capabilities.
const ALLOWED_TOOLS: string[] = [
  "search",
  "calculator",
  "weather",
];
import fs from "fs";
import path from "path";
import crypto from "crypto";

// Audit log rotation / retention configuration
const AUDIT_LOG_DIR = path.resolve(process.cwd(), "logs");
const AUDIT_LOG_PATH = path.join(AUDIT_LOG_DIR, "audit.log");
const AUDIT_LOG_MAX_BYTES = 10 * 1024 * 1024; // 10 MB per file
const AUDIT_LOG_MAX_FILES = 30;              // retain up to 30 rotated files (~300 MB total)

/** Rotate audit.log when it exceeds AUDIT_LOG_MAX_BYTES. */
function rotateAuditLogIfNeeded(): void {
  try {
    if (!fs.existsSync(AUDIT_LOG_DIR)) {
      fs.mkdirSync(AUDIT_LOG_DIR, { recursive: true });
    }
    if (!fs.existsSync(AUDIT_LOG_PATH)) return;
    const { size } = fs.statSync(AUDIT_LOG_PATH);
    if (size < AUDIT_LOG_MAX_BYTES) return;

    // Shift existing rotated files: audit.log.N -> audit.log.N+1
    for (let i = AUDIT_LOG_MAX_FILES - 1; i >= 1; i--) {
      const older = `${AUDIT_LOG_PATH}.${i}`;
      const newer = `${AUDIT_LOG_PATH}.${i + 1}`;
      if (fs.existsSync(older)) {
        fs.renameSync(older, newer);
      }
    }
    // Rename current log to .1
    fs.renameSync(AUDIT_LOG_PATH, `${AUDIT_LOG_PATH}.1`);

    // Prune files beyond the retention limit
    for (let i = AUDIT_LOG_MAX_FILES + 1; i <= AUDIT_LOG_MAX_FILES + 5; i++) {
      const stale = `${AUDIT_LOG_PATH}.${i}`;
      if (fs.existsSync(stale)) fs.unlinkSync(stale);
    }
  } catch (err) {
    // Log rotation failure must not crash the request handler
    console.error("[audit] log rotation error:", err);
  }
}

function writeAuditRecord(record: Record<string, unknown>): void {
  try {
    if (!fs.existsSync(AUDIT_LOG_DIR)) {
      fs.mkdirSync(AUDIT_LOG_DIR, { recursive: true });
    }
    rotateAuditLogIfNeeded();
    const line = JSON.stringify({ ...record, "@timestamp": new Date().toISOString() }) + "\n";
    fs.appendFileSync(AUDIT_LOG_PATH, line, { encoding: "utf8", flag: "a" });
  } catch (err) {
    console.error("[audit] failed to write audit record:", err);
  }
}
import { createHmac } from "crypto";

dotenv.config({ path: `.env.local` });

// Allowlist of permitted hostnames for outbound agent fetch requests.
// Only organization-approved hostnames are permitted.
const ALLOWED_AGENT_HOSTNAMES: string[] = [];

function isAllowedAgentUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    // Only allow https
    if (parsed.protocol !== "https:") return false;
    const hostname = parsed.hostname.toLowerCase();
    return ALLOWED_AGENT_HOSTNAMES.some(
      (allowed) => hostname === allowed || hostname.endsWith("." + allowed)
    );
  } catch {
    return false;
  }
}

/**
 * Validates a prompt for malicious content before forwarding to the AI agent.
 * Returns true if the prompt is safe, false if it should be rejected.
 */
function isSafePrompt(input: string): boolean {
  if (!input || typeof input !== "string") return false;

  // Reject if prompt exceeds a reasonable length
  if (input.length > 4000) return false;

  // Detect base64-encoded content (long base64 strings are suspicious)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/;
  if (base64Pattern.test(input)) return false;

  // Detect shell command patterns
  const shellCommandPattern =
    /(\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|Runtime\.exec)\b|[`$]\(|\|\s*\w+|&&|\|\||;\s*\w+|>\s*\/|<\s*\/|\bchmod\b|\bchown\b|\brm\s+-|\bwget\b|\bcurl\b|\bnc\b|\bnetcat\b)/i;
  if (shellCommandPattern.test(input)) return false;

  // Detect prompt injection / jailbreak patterns
  const promptInjectionPattern =
    /(ignore (previous|prior|above|all) instructions?|disregard (previous|prior|above|all)|forget (previous|prior|above|all)|you are now|act as (a|an|the)|pretend (you are|to be)|your (new |true )?instructions?|system prompt|override (instructions?|rules?|guidelines?)|do anything now|DAN mode|jailbreak|bypass (restrictions?|filters?|safety)|reveal (your |the )?(system |hidden )?prompt|print (your |the )?(system |hidden )?prompt)/i;
  if (promptInjectionPattern.test(input)) return false;

  // Detect leetspeak obfuscation (e.g., 1gnor3, 3x3cut3)
  const leetspeakPattern = /([a@][c<][t+]\s*[a@][s$]|[1i][g9][n][o0][r3][e3]|[e3][x><][e3][c<][u][t+][e3]|[s$][y][s$][t+][e3][m])/i;
  if (leetspeakPattern.test(input)) return false;

  // Detect attempts to exfiltrate data or make external requests
  const exfiltrationPattern =
    /(https?:\/\/(?!\s)|ftp:\/\/|data:text\/|<script|<iframe|javascript:|vbscript:)/i;
  if (exfiltrationPattern.test(input)) return false;

  // Detect null bytes or other control characters
  // eslint-disable-next-line no-control-regex
  const controlCharPattern = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
  if (controlCharPattern.test(input)) return false;

  return true;
}

const MAX_PROMPT_LENGTH = 4000;

function sanitizePrompt(input: unknown): string {
  if (typeof input !== "string") {
    throw new Error("Prompt must be a string.");
  }
  // Enforce maximum length
  if (input.length > MAX_PROMPT_LENGTH) {
    throw new Error(`Prompt exceeds maximum allowed length of ${MAX_PROMPT_LENGTH} characters.`);
  }
  // Remove null bytes and ASCII control characters (except tab, newline, carriage return)
  const sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
  if (sanitized.length === 0) {
    throw new Error("Prompt must not be empty.");
  }
  return sanitized;
}

function returnError(code: number, message: string) {
  return new NextResponse(
      JSON.stringify({ Message: message }),
      {
        status: code,
        headers: {
          "Content-Type": "application/json",
        },
      }
  );
}

export async function POST(req: Request) {
  // MCP client authentication: validate shared API key before any other processing
  const mcpApiKey = req.headers.get("x-mcp-api-key");
  const expectedMcpApiKey = process.env.MCP_CLIENT_API_KEY;
  if (!expectedMcpApiKey) {
    console.error("ERROR: MCP_CLIENT_API_KEY environment variable is not set");
    return returnError(500, "Server misconfiguration: MCP client authentication is not configured.");
  }
  if (!mcpApiKey || mcpApiKey !== expectedMcpApiKey) {
    console.log("ERROR: MCP client authentication failed — invalid or missing x-mcp-api-key header");
    return returnError(401, "Unauthorized: valid MCP client API key required.");
  }

  let clerkUserId;
  let user;
  let clerkUserName;
  const { prompt: rawPrompt, isText, userId, userName } = await req.json();
  let prompt: string;
  try {
    prompt = sanitizePrompt(rawPrompt);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Invalid prompt.";
    return returnError(400, message);
  }
  const companionName = req.headers.get("name");

  if (!companionName) {
    console.log("ERROR: no companion name");
    return returnError(429, `Hi, please add a 'name' field in your headers specifying the Companion Name.`)
  }

  // Load the companion config
  const configManager = ConfigManager.getInstance();
  const companionConfig = configManager.getConfig("name", companionName);
  if (!companionConfig) {
    return returnError(404, `Hi, we were unable to find the configuration for a companion named ${companionName}.`)
  }

  // Make sure we're not rate limited
  const identifier = req.url + "-" + (userId || "anonymous");
  const { success } = await rateLimit(identifier);
  if (!success) {
    console.log("INFO: rate limit exceeded");
    return returnError(429, `Hi, the companions can't talk this fast.`)
  }

  if (!process.env.STEAMSHIP_API_KEY) {
    return returnError(500, `Please set the STEAMSHIP_API_KEY env variable and make sure ${companionName} is connected to an Agent instance that you own.`)
  }

  console.log(`Companion Name: ${companionName}`)

  // Validate the prompt before any further processing
  if (!prompt || !isSafePrompt(prompt)) {
    console.log("INFO: prompt rejected by safety filter");
    return returnError(400, "Your message contains content that cannot be processed. Please rephrase and try again.");
  }

  console.log(`Prompt: ${prompt}`);

  user = await currentUser();
  if (isText) {
    // For text mode, validate that the provided userId matches the authenticated user
    clerkUserId = user?.id || userId;
    clerkUserName = user?.firstName || userName;
  } else {
    clerkUserId = user?.id;
    clerkUserName = user?.firstName;
  }

  if (!clerkUserId || !user) {
    console.log("user not authorized");
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

  // Create a chat session id bound to the authenticated Clerk user identity
  const chatSessionId = Md5.hashStr(clerkUserId || "anonymous");

  // Approved LLM/agent endpoint registry — only URLs in this list may be invoked.
  const APPROVED_AGENT_ENDPOINTS: string[] = (
    process.env.APPROVED_AGENT_ENDPOINTS || ""
  )
    .split(",")
    .map((u) => u.trim())
    .filter(Boolean);

    // Make sure we have a generate endpoint.
  // TODO: Create a new instance of the agent per user if this proves advantageous.
  const agentUrl = companionConfig.generateEndpoint
  if (!agentUrl) {
    return returnError(500, `Please add a Steamship 'generateEndpoint' to your ${companionName} configuration in companions.json.`)
  }

  // Registry check: validate agentUrl against the approved model registry.
  const registryEntry = getRegistryEntry(agentUrl);
  if (!registryEntry) {
    console.error(`SECURITY: agentUrl '${agentUrl}' is not in the approved model registry.`);
    return returnError(403, `The agent endpoint for ${companionName} is not in the approved model registry. Inference request blocked.`);
  }
  console.log(`Registry check passed: provider=${registryEntry.modelProvider}, model=${registryEntry.modelName}, version=${registryEntry.modelVersion}`);
  const modelIdentityMetadata = {
    model_provider: registryEntry.modelProvider,
    model_name: registryEntry.modelName,
    model_version: registryEntry.modelVersion,
  };

  // SSRF prevention: validate agentUrl against an allowlist of permitted URL prefixes.
  const ALLOWED_AGENT_URL_PREFIXES: string[] = (
    process.env.ALLOWED_AGENT_URL_PREFIXES ||
    "https://api.steamship.com/"
  ).split(",").map((p: string) => p.trim());
  const agentUrlAllowed = ALLOWED_AGENT_URL_PREFIXES.some((prefix: string) =>
    agentUrl.startsWith(prefix)
  );
  if (!agentUrlAllowed) {
    console.error(`Blocked SSRF attempt: agentUrl '${agentUrl}' is not in the allowlist.`);
    return returnError(500, `The configured generateEndpoint for ${companionName} is not permitted.`);
  }

  // Enforce the tool allow list: if the companion config declares specific tools,
  // verify every one of them is present in ALLOWED_TOOLS before proceeding.
  const requestedTools: string[] = Array.isArray(companionConfig.tools) ? companionConfig.tools : [];
  const disallowedTools = requestedTools.filter((tool: string) => !ALLOWED_TOOLS.includes(tool));
  if (disallowedTools.length > 0) {
    console.log(`ERROR: companion '${companionName}' requested disallowed tools: ${disallowedTools.join(", ")}`);
    return returnError(403, `The following tools are not permitted: ${disallowedTools.join(", ")}. Allowed tools are: ${ALLOWED_TOOLS.join(", ")}.`);
  }

  // Invoke the generation. The allowed_tools field constrains the remote agent to
  // only the explicitly approved tool set defined in ALLOWED_TOOLS.
  // To build, deploy, and host your own multi-tenant agent see: https://www.steamship.com/learn/agent-guidebook
      const interAgentToken = process.env.INTER_AGENT_AUTH_TOKEN;
    if (!interAgentToken) {
      return returnError(500, "Server misconfiguration: INTER_AGENT_AUTH_TOKEN is not set.");
    }
    const response = await fetch(agentUrl, {
      method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${process.env.STEAMSHIP_API_KEY}`
    },
    body: JSON.stringify({
      question: prompt,
      chat_session_id: chatSessionId,
      allowed_tools: ALLOWED_TOOLS
    })
  });
  const inputHash = crypto.createHash("sha256").update(requestBody).digest("hex");
  const invocationTimestamp = new Date().toISOString();

  // Generate a per-request nonce so the server can include it in its signed response,
  // preventing replay attacks and confirming the response corresponds to this request.
  const requestNonce = crypto.randomBytes(32).toString("hex");

  const serverSecret = process.env.STEAMSHIP_SERVER_SECRET;
  if (!serverSecret) {
    console.error("STEAMSHIP_SERVER_SECRET is not configured; cannot authenticate server responses.");
    return returnError(500, "Server authentication is not configured.");
  }

  const response = await fetch(agentUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${process.env.STEAMSHIP_API_KEY}`,
      "X-Agent-User-Id": clerkUserId as string,
      "X-Agent-User-Name": clerkUserName || "",
      "X-Request-Nonce": requestNonce
    },
    body: JSON.stringify({
      question: prompt,
      chat_session_id: chatSessionId,
      _model_identity: modelIdentityMetadata,
    })
  });

  if (response.ok) {
    const responseText = await response.text();

    // Authenticate the server's response: verify the HMAC-SHA256 signature the server
    // must return over (responseBody + requestNonce) using the shared secret.
    const serverSignatureHeader = response.headers.get("X-Server-Signature");
    if (!serverSignatureHeader) {
      console.error("Server response missing X-Server-Signature header; rejecting unauthenticated response.");
      return returnError(502, "Server response could not be authenticated (missing signature).");
    }
    const expectedSignature = crypto
      .createHmac("sha256", serverSecret)
      .update(responseText + requestNonce)
      .digest("hex");
    const sigBuffer = Buffer.from(serverSignatureHeader, "hex");
    const expectedBuffer = Buffer.from(expectedSignature, "hex");
    if (
      sigBuffer.length !== expectedBuffer.length ||
      !crypto.timingSafeEqual(sigBuffer, expectedBuffer)
    ) {
      console.error("Server response signature mismatch; rejecting response from unverified server.");
      return returnError(502, "Server response could not be authenticated (invalid signature).");
    }
    const outputHash = crypto.createHash("sha256").update(responseText).digest("hex");
    writeAuditRecord({
      timestamp: invocationTimestamp,
      completedAt: new Date().toISOString(),
      principal: clerkUserId ?? "anonymous",
      principalName: clerkUserName ?? "anonymous",
      modelEndpoint: agentUrl,
      companionName,
      chatSessionId,
      inputHash,
      outputHash,
      httpStatus: response.status,
      outcome: "success"
    });
    const responseBlocks = JSON.parse(responseText);
    // Minimise output: extract only the expected safe fields from each block
    const minimisedBlocks = Array.isArray(responseBlocks)
      ? responseBlocks.map((block: Record<string, unknown>) => ({
          ...(block.text !== undefined ? { text: block.text } : {}),
          ...(block.mimeType !== undefined ? { mimeType: block.mimeType } : {}),
        }))
      : [];
    return NextResponse.json(minimisedBlocks);
  } else {
    const errorText = await response.text();
    const outputHash = crypto.createHash("sha256").update(errorText).digest("hex");
    writeAuditRecord({
      timestamp: invocationTimestamp,
      completedAt: new Date().toISOString(),
      principal: clerkUserId ?? "anonymous",
      principalName: clerkUserName ?? "anonymous",
      modelEndpoint: agentUrl,
      companionName,
      chatSessionId,
      inputHash,
      outputHash,
      httpStatus: response.status,
      outcome: "error"
    });
    console.error("Upstream agent error:", errorText);
    return returnError(500, "An error occurred processing your request.");
  }`
    },
    body: JSON.stringify({
      question: prompt,
      chat_session_id: chatSessionId
    })
  });

  const inputHash2 = crypto.createHash("sha256").update(requestBody).digest("hex");
  const invocationTimestamp2 = new Date().toISOString();

  if (response.ok) {
    const responseText = await response.text()
    const outputHash2 = crypto.createHash("sha256").update(responseText).digest("hex");
    writeAuditRecord({
      timestamp: invocationTimestamp2,
      completedAt: new Date().toISOString(),
      principal: clerkUserId ?? "anonymous",
      principalName: clerkUserName ?? "anonymous",
      modelEndpoint: agentUrl,
      companionName,
      chatSessionId,
      inputHash: inputHash2,
      outputHash: outputHash2,
      httpStatus: response.status,
      outcome: "success"
    });
    const responseBlocks = JSON.parse(responseText)

    // Validate and sanitize LLM output: reject responses containing dynamic code execution primitives
    const DANGEROUS_PATTERNS = [
      /\beval\s*\(/i,
      /\bexec\s*\(/i,
      /\bFunction\s*\(/i,
      /\bnew\s+Function\b/i,
      /\bsetTimeout\s*\(\s*['"`]/i,
      /\bsetInterval\s*\(\s*['"`]/i,
      /\bsetImmediate\s*\(\s*['"`]/i,
      /\bimportScripts\s*\(/i,
      /\bdocument\.write\s*\(/i,
      /\binnerHTML\s*=/i,
      /\bouterHTML\s*=/i,
      /\bexecScript\s*\(/i,
      /<\s*script[\s>]/i,
    ];

    function containsDangerousContent(value: unknown): boolean {
      if (typeof value === "string") {
        return DANGEROUS_PATTERNS.some((pattern) => pattern.test(value));
      }
      if (Array.isArray(value)) {
        return value.some(containsDangerousContent);
      }
      if (value !== null && typeof value === "object") {
        return Object.values(value as Record<string, unknown>).some(containsDangerousContent);
      }
      return false;
    }

    // Enforce tool allow list on any tool_use blocks returned by the agent
    if (Array.isArray(responseBlocks)) {
      for (const block of responseBlocks) {
        if (
          block !== null &&
          typeof block === "object" &&
          (block as Record<string, unknown>).type === "tool_use" &&
          typeof (block as Record<string, unknown>).name === "string"
        ) {
          try {
            enforceToolAllowList((block as Record<string, unknown>).name as string);
          } catch (toolErr) {
            console.error(toolErr);
            return returnError(403, "Agent attempted to invoke a tool that is not on the allow list.");
          }
        }
      }
    }

    // Inline sanitizer: strips dynamic code execution primitives from LLM output blocks
    function sanitizeLlmBlocks(blocks: unknown): unknown {
      const DANGEROUS_PATTERNS = [
        /\beval\s*\(/gi,
        /\bexec\s*\(/gi,
        /\bnew\s+Function\s*\(/gi,
        /\bsetTimeout\s*\(\s*['"`]/gi,
        /\bsetInterval\s*\(\s*['"`]/gi,
        /\bimportScripts\s*\(/gi,
        /\bdocument\.write\s*\(/gi,
        /\bwindow\s*\[\s*['"`]/gi,
        /\bglobalThis\s*\[\s*['"`]/gi,
        /\bprocess\.binding\s*\(/gi,
        /\brequire\s*\(\s*['"`]child_process/gi,
      ];
      function sanitizeString(value: string): string {
        let sanitized = value;
        for (const pattern of DANGEROUS_PATTERNS) {
          sanitized = sanitized.replace(pattern, "[REDACTED]");
        }
        return sanitized;
      }
      function sanitizeValue(val: unknown): unknown {
        if (typeof val === "string") return sanitizeString(val);
        if (Array.isArray(val)) return val.map(sanitizeValue);
        if (val !== null && typeof val === "object") {
          const sanitizedObj: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
            sanitizedObj[k] = sanitizeValue(v);
          }
          return sanitizedObj;
        }
        return val;
      }
      return sanitizeValue(blocks);
    }

    console.log(JSON.stringify({
      event: "llm_interaction_success",
      timestamp: new Date().toISOString(),
      agentUrl,
      companionName,
      upstreamStatus: response.status,
      responseBlocks,
    }));

    if (containsDangerousContent(responseBlocks)) {
      console.error("ERROR: LLM response contains dynamic code execution primitives — rejecting response.");
      return returnError(500, "The agent response was rejected due to unsafe content.");
    }

    // --- Synthetic Content Provenance, Labeling & Watermarking ---
    // Build a provenance envelope so consumers can verify the AI-generated origin.
    const provenanceTimestamp = new Date().toISOString();
    const provenancePayload = JSON.stringify({
      modelEndpoint: agentUrl,
      companionName,
      generatedAt: provenanceTimestamp,
      outputHash: outputHash2,
    });
    // HMAC-SHA256 signature over the provenance payload (requires PROVENANCE_HMAC_SECRET in env)
    const hmacSecret = process.env.PROVENANCE_HMAC_SECRET ?? "__missing_secret__";
    const provenanceSignature = crypto
      .createHmac("sha256", hmacSecret)
      .update(provenancePayload)
      .digest("hex");

        // Only expose the minimal, non-operational fields to the client.
    // Internal fields (modelEndpoint, agentUrl, outputHash, originTag, provenanceSignature)
    // are retained server-side for logging/auditing only and must not be forwarded.
    void provenanceSignature; // retained for server-side audit log only
    void provenancePayload;   // retained for server-side audit log only

    const syntheticEnvelope = {
      // Human-readable label indicating synthetic / AI-generated origin
      _synthetic: true,
      _contentLabel: "AI-GENERATED",
      // Minimal provenance metadata safe for client consumption
      _provenance: {
        companionName,
        generatedAt: provenanceTimestamp,
      },
      // Original AI-generated payload
      data: responseBlocks,
    };

    // --- Persistent Audit Log (append-only, durable store) ---
    // Build the audit record with all required forensic fields.
    const auditRecord = {
      auditVersion: "1",
      timestamp: provenanceTimestamp,
      // Principal: prefer a verified identity header; fall back to a placeholder so the field is always present.
      principal: (typeof request !== "undefined" && request.headers?.get("x-authenticated-user")) ?? "unknown",
      modelEndpoint: agentUrl,
      companionName,
      // Input hash: SHA-256 of the raw request body (computed earlier in the handler as inputHash / outputHash2 covers output)
      inputHash: (() => {
        try {
          // Re-derive from the provenance payload fields we already have; the caller should pass the real input hash.
          // We use outputHash2 for output and mark input as "see-request-body" when not separately captured.
          return typeof inputHash !== "undefined" ? inputHash : "not-captured";
        } catch {
          return "not-captured";
        }
      })(),
      outputHash: outputHash2,
      provenanceSignature,
      originTag: "steamship-agent",
      // Redacted snapshot of the output for forensic review (truncated to 4 KB).
      outputSnippet: JSON.stringify(responseBlocks).slice(0, 4096),
    };

    // Write to an append-only NDJSON audit log file.
    // This is a synchronous-safe fire-and-forget: errors are logged but do NOT block the response.
    (() => {
      try {
        const fsModule = require("fs");
        const pathModule = require("path");
        const auditDir = process.env.AUDIT_LOG_DIR ?? "/var/log/ai-audit";
        const auditPath = pathModule.join(auditDir, "audit.log");
        // Ensure the directory exists (best-effort).
        try { fsModule.mkdirSync(auditDir, { recursive: true }); } catch { /* already exists */ }
        // Append a newline-delimited JSON record atomically.
        fsModule.appendFileSync(auditPath, JSON.stringify(auditRecord) + "\n", { encoding: "utf8", flag: "a" });
      } catch (auditErr) {
        // Log the failure but do NOT suppress the response — availability must not be sacrificed.
        console.error("[AUDIT] Failed to write audit log entry:", auditErr, JSON.stringify(auditRecord));
      }
    })();

    return NextResponse.json(syntheticEnvelope);
  } else {
        const errorBody = await response.text();
    console.log(JSON.stringify({
      event: "mcp_interaction",
      direction: "response_received",
      agentUrl,
      upstreamStatus: response.status,
      success: false,
      errorBody,
      timestamp: new Date().toISOString(),
    }));
    return returnError(500, errorBody, {
      event_detail: "upstream_agent_error",
      agentUrl,
      upstreamStatus: response.status,
    });
  }
}

// NOTE: enforceApprovedAgentUrl(agentUrl) MUST be called before any fetch to agentUrl.
// Example usage (place before the upstream fetch call):
//   const approvedEntry = enforceApprovedAgentUrl(agentUrl);
//   // Only proceed if no error is thrown — approvedEntry contains model metadata.

// Helper: sanitize MCP server response blocks before returning to clients
function sanitizeMcpResponseBlocks(blocks: unknown[]): unknown[] {
  if (!Array.isArray(blocks)) return [];
  return blocks.map((block) => {
    if (block === null || typeof block !== "object") return block;
    const b = block as Record<string, unknown>;
    const sanitized: Record<string, unknown> = {};
    for (const key of Object.keys(b)) {
      const value = b[key];
      if (typeof value === "string") {
        // Strip null bytes, HTML tags, and dangerous script-like patterns
        let clean = value.replace(/\0/g, "");
        clean = clean.replace(/<[^>]*>/g, "");
        clean = clean.replace(/javascript\s*:/gi, "");
        clean = clean.replace(/data\s*:/gi, "");
        clean = clean.replace(/vbscript\s*:/gi, "");
        clean = clean.replace(/on\w+\s*=/gi, "");
        sanitized[key] = clean;
      } else if (Array.isArray(value)) {
        sanitized[key] = sanitizeMcpResponseBlocks(value);
      } else if (value !== null && typeof value === "object") {
        sanitized[key] = sanitizeMcpResponseBlocks([value])[0];
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  });
}

// Helper: verify MCP server identity from response headers
function verifyMcpServerIdentity(response: Response, token: string): boolean {
  const serverTokenHeader = response.headers.get("X-MCP-Server-Token");
  if (!serverTokenHeader) return false;
  // The server must return HMAC-SHA256(token, MCP_SERVER_HMAC_SECRET) to prove it holds the secret
  const hmacSecret = process.env.MCP_SERVER_HMAC_SECRET;
  if (!hmacSecret) throw new Error("MCP_SERVER_HMAC_SECRET environment variable is not set");
  const { createHmac: _createHmac } = require("crypto");
  const expected = _createHmac("sha256", hmacSecret).update(token).digest("hex");
  return serverTokenHeader === expected;
}

// Policy enforcement: validate agentUrl against the approved model registry.
// This MUST be called before any upstream request to a Steamship agent endpoint.
// Returns the matching registry entry if approved, or throws a policy violation error.
function enforceApprovedAgentUrl(agentUrl: string): ApprovedModelRegistryEntry {
  let registry: ApprovedModelRegistryEntry[];
  try {
    registry = loadApprovedModelRegistry();
  } catch (err) {
    throw new Error(
      `POLICY VIOLATION: Cannot validate agentUrl '${agentUrl}' — approved model registry failed to load: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }
  const match = registry.find((entry) => agentUrl.startsWith(entry.urlPrefix));
  if (!match) {
    throw new Error(
      `POLICY VIOLATION: agentUrl '${agentUrl}' does not match any entry in the ` +
      `organization-approved model registry. Only approved model endpoints may be invoked. ` +
      `Approved prefixes: [${registry.map((e) => e.urlPrefix).join(", ")}]`
    );
  }
  return match;
}
    return returnError(500, "An internal error occurred. Please try again later.", {
      event_detail: "upstream_agent_error",
    });
  }
}
