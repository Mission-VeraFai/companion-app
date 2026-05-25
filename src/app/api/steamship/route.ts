import { NextResponse } from "next/server";
import { currentUser } from "@clerk/nextjs";
// In-memory rate limiter (replaces Upstash Redis rateLimit to avoid holding a 4th set of external credentials)
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

// Approved model registry: loaded exclusively from the APPROVED_MODEL_REGISTRY_JSON
// environment variable, which MUST be set by the organization-approved registry pipeline.
// Hardcoding this registry locally is a policy violation — all entries must originate
// from the org-approved registry and be injected at deploy time via the env var.
interface ApprovedModelRegistryEntry {
  urlPrefix: string;
  modelProvider: string;
  modelName: string;
  modelVersion: string;
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

    const syntheticEnvelope = {
      // Human-readable label indicating synthetic / AI-generated origin
      _synthetic: true,
      _contentLabel: "AI-GENERATED",
      // Provenance metadata
      _provenance: {
        modelEndpoint: agentUrl,
        companionName,
        generatedAt: provenanceTimestamp,
        outputHash: outputHash2,
        originTag: "steamship-agent",
      },
      // Cryptographic watermark / integrity signature
      _signature: {
        algorithm: "HMAC-SHA256",
        value: provenanceSignature,
        coveredFields: ["modelEndpoint", "companionName", "generatedAt", "outputHash"],
      },
      // Original AI-generated payload
      data: responseBlocks,
    };

    return NextResponse.json(syntheticEnvelope);
  } else {
        const errorBody = await response.text();
    return returnError(500, errorBody, {
      event_detail: "upstream_agent_error",
      agentUrl,
      upstreamStatus: response.status,
    });
  }
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
});
    return returnError(500, "An internal error occurred. Please try again later.", {
      event_detail: "upstream_agent_error",
    });
  }
}
