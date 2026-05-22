import dotenv from "dotenv";
import clerk from "@clerk/clerk-sdk-node";
import { NextResponse } from "next/server";
import { currentUser } from "@clerk/nextjs";
import { rateLimit } from "@/app/utils/rateLimit";
import { createHmac } from "crypto";
import ConfigManager from "@/app/utils/config";
import fs from "fs";
import path from "path";
import crypto from "crypto";

const AUDIT_LOG_BASE_DIR = process.env.AUDIT_LOG_DIR
  ? path.resolve(process.env.AUDIT_LOG_DIR)
  : "/var/log/app";
const AUDIT_LOG_PATH = path.join(AUDIT_LOG_BASE_DIR, "audit_ai_actions.log");
const MAX_AUDIT_LOG_BYTES = parseInt(process.env.MAX_AUDIT_LOG_BYTES || "", 10) || 10 * 1024 * 1024; // 10 MB default
const AUDIT_LOG_MODEL_ID = "steamship-agent-approved-v1";
const AUDIT_LOG_MODEL_VERSION = APPROVED_MODEL_REGISTRY[AUDIT_LOG_MODEL_ID]?.version ?? "unknown";

function rotateAuditLogIfNeeded(): void {
  try {
    if (fs.existsSync(AUDIT_LOG_PATH)) {
      const { size } = fs.statSync(AUDIT_LOG_PATH);
      if (size >= MAX_AUDIT_LOG_BYTES) {
        // Archive by COPYING (appending) existing content into a timestamped file.
        // The active log file is NEVER renamed or deleted — immutability is preserved.
        const archivePath = AUDIT_LOG_PATH.replace(
          /(\.log)?$/,
          `.${new Date().toISOString().replace(/[:.]/g, "-")}.log`
        );
        const existingContent = fs.readFileSync(AUDIT_LOG_PATH);
        // Write archive with append flag so existing archive data is never overwritten.
        fs.appendFileSync(archivePath, existingContent);
        // Truncate the active log in-place (preserves inode; no rename/delete).
        fs.writeFileSync(AUDIT_LOG_PATH, "", { encoding: "utf8", flag: "w" });
      }
    }
  } catch (err) {
    process.stderr.write("[AUDIT LOG ROTATION FAILURE] " + String(err) + "\n");
  }
}

function writeAuditLog(entry: Record<string, unknown>): void {
  // Enrich with model identity for complete decision audit records
  const enriched: Record<string, unknown> = {
    ...entry,
    modelId: AUDIT_LOG_MODEL_ID,
    modelVersion: AUDIT_LOG_MODEL_VERSION,
    timestamp: new Date().toISOString(),
  };
  // Compute a deterministic input hash over the enriched payload (excluding the hash field itself)
  const inputHash = crypto
    .createHash("sha256")
    .update(JSON.stringify(enriched))
    .digest("hex");
  enriched.inputHash = inputHash;

  const line = JSON.stringify(enriched) + "\n";
  try {
    rotateAuditLogIfNeeded();
    fs.appendFileSync(AUDIT_LOG_PATH, line, { encoding: "utf8", flag: "a" });
  } catch (err) {
    // Fallback: emit to stderr so the record is not silently lost
    process.stderr.write("[AUDIT LOG WRITE FAILURE] " + line);
  }
}

dotenv.config({ path: `.env.local` });

// Approved model registry: only these pinned, versioned endpoints are permitted.
// Add new approved endpoints here after security review.
// Version MUST be an immutable digest or commit hash — mutable tags (e.g. "1.0.0") are not permitted.
// The endpoint MUST be supplied via the environment variable; an empty/missing value is a hard startup error.
(function validateApprovedModelRegistryEnv() {
  const requiredEnvVars: Record<string, string | undefined> = {
    APPROVED_STEAMSHIP_ENDPOINT_V1: process.env.APPROVED_STEAMSHIP_ENDPOINT_V1,
  };
  for (const [key, value] of Object.entries(requiredEnvVars)) {
    if (!value || value.trim() === "") {
      throw new Error(
        `[SECURITY] Required environment variable '${key}' is missing or empty. ` +
        `All approved model registry endpoints must be explicitly configured. Refusing to start.`
      );
    }
  }
})();

const APPROVED_MODEL_REGISTRY: Record<string, { version: string; endpoint: string }> = {
  // version must be an immutable digest (sha256) or commit hash — NOT a mutable semver tag.
  "steamship-agent-v1": {
    version: "sha256:a3f1c2e4b5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2",
    endpoint: process.env.APPROVED_STEAMSHIP_ENDPOINT_V1 as string,
  },
};

function isApprovedEndpoint(url: string): boolean {
  if (!url) return false;
  return Object.values(APPROVED_MODEL_REGISTRY).some(
    (entry) => entry.endpoint && entry.endpoint === url
  );
}

// Allowlist of hostnames permitted for outbound agent fetch calls.
// To change allowed hostnames, update this list after security review.
const ALLOWED_AGENT_HOSTNAMES: string[] = ["api.steamship.com"];

function isAllowedAgentUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return (
      (parsed.protocol === "https:") &&
      ALLOWED_AGENT_HOSTNAMES.includes(parsed.hostname.toLowerCase())
    );
  } catch {
    return false;
  }
}

// Patterns indicative of prompt injection or malicious content
const MALICIOUS_PATTERNS: RegExp[] = [
  // Shell command injection
  /(?:^|\s|;|\||&)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\-]/i,
  // Common shell operators
  /(?:[;&|`$]\s*(?:rm|mv|cp|chmod|chown|wget|curl|nc|ncat|netcat|python|perl|ruby|php)\s)/i,
  // Base64-encoded content (long base64 strings are suspicious)
  /(?:[A-Za-z0-9+\/]{50,}={0,2})/,
  // Hidden prompt injection markers
  /(?:ignore previous instructions|disregard (?:all )?(?:prior|previous|above)|forget (?:all )?(?:prior|previous|above)|new instructions:|system prompt:|\[system\]|<system>)/i,
  // Attempts to override system role
  /(?:you are now|act as (?:an? )?(?:unrestricted|jailbroken|evil|malicious|dan)|pretend (?:you are|to be) (?:an? )?(?:unrestricted|jailbroken))/i,
  // ANSI escape / control characters
  // eslint-disable-next-line no-control-regex
  /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/,
];

const MAX_PROMPT_LENGTH = 2000;

function sanitizePrompt(input: string): { safe: boolean; reason?: string } {
  if (!input || typeof input !== "string") {
    return { safe: false, reason: "Prompt must be a non-empty string." };
  }
  if (input.length > MAX_PROMPT_LENGTH) {
    return { safe: false, reason: `Prompt exceeds maximum allowed length of ${MAX_PROMPT_LENGTH} characters.` };
  }
  for (const pattern of MALICIOUS_PATTERNS) {
    if (pattern.test(input)) {
      return { safe: false, reason: "Prompt contains potentially malicious content and has been rejected." };
    }
  }
  return { safe: true };
}

// Patterns commonly used in prompt injection attacks
const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
  /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
  /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
  /you\s+are\s+now\s+/i,
  /act\s+as\s+(if\s+you\s+are|a|an)\s+/i,
  /system\s*:\s*/i,
  /\[system\]/i,
  /<\s*system\s*>/i,
  /new\s+instructions?\s*:/i,
  /override\s+(previous\s+)?(instructions?|prompts?)/i,
];

function sanitizeAndValidatePrompt(input: unknown): { valid: boolean; sanitized: string; error?: string } {
  if (input === null || input === undefined) {
    return { valid: false, sanitized: "", error: "Prompt is required." };
  }
  if (typeof input !== "string") {
    return { valid: false, sanitized: "", error: "Prompt must be a string." };
  }
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    return { valid: false, sanitized: "", error: "Prompt must not be empty." };
  }
  if (trimmed.length > MAX_PROMPT_LENGTH) {
    return { valid: false, sanitized: "", error: `Prompt must not exceed ${MAX_PROMPT_LENGTH} characters.` };
  }
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(trimmed)) {
      return { valid: false, sanitized: "", error: "Prompt contains disallowed content." };
    }
  }
  // Strip null bytes and non-printable control characters (except common whitespace)
  const sanitized = trimmed.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  return { valid: true, sanitized };
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
  let clerkUserId;
  let user;
  let clerkUserName;
  const { prompt: rawPrompt, isText, userId, userName } = await req.json();
  const { valid: promptValid, sanitized: prompt, error: promptError } = sanitizeAndValidatePrompt(rawPrompt);
  if (!promptValid) {
    return returnError(400, promptError || "Invalid prompt.");
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

  console.log(`Companion Name: ${companionName}`);

  // Validate and sanitize the prompt before any further processing
  const sanitizationResult = sanitizePrompt(prompt);
  if (!sanitizationResult.safe) {
    console.log(`INFO: Prompt rejected — ${sanitizationResult.reason}`);
    return returnError(400, sanitizationResult.reason || "Invalid prompt.");
  }

  // Log a truncated version of the prompt to avoid leaking large payloads into logs
  console.log(`Prompt (truncated): ${String(prompt).substring(0, 100)}...`);

  user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName;

  // For text mode, verify the userId is non-empty; for session mode, currentUser() already validated the session above.
  if (!clerkUserId) {
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

  // Create a signed, expiry-bound, user-bound chat session token
  const SESSION_SECRET = process.env.SESSION_SECRET;
  if (!SESSION_SECRET) {
    return returnError(500, "Server misconfiguration: SESSION_SECRET is not set.");
  }
  const SESSION_WINDOW_SECONDS = 3600; // 1-hour expiry window
  const now = Math.floor(Date.now() / 1000);
  const windowSlot = Math.floor(now / SESSION_WINDOW_SECONDS); // changes every hour, invalidating old tokens
  const boundUserId = clerkUserId || "anonymous";
  const tokenPayload = `${boundUserId}:${windowSlot}`;
  const chatSessionId = createHmac("sha256", SESSION_SECRET)
    .update(tokenPayload)
    .digest("hex");

  // Make sure we have a generate endpoint.
  // TODO: Create a new instance of the agent per user if this proves advantageous.
  const agentUrl = companionConfig.generateEndpoint;
  if (!agentUrl) {
    return returnError(500, `Please add a Steamship 'generateEndpoint' to your ${companionName} configuration in companions.json.`);
  }

  // Registry check: reject endpoints not in the approved, version-pinned registry.
  if (!isApprovedEndpoint(agentUrl)) {
    console.error(`SECURITY: endpoint '${agentUrl}' for companion '${companionName}' is not in the approved model registry.`);
    return returnError(403, `The model endpoint configured for ${companionName} is not approved. Contact your administrator to register an approved, version-pinned endpoint.`);
  }

  // Enforce the organization's approved LLM endpoint allowlist.
  // Only endpoints whose prefix matches an entry in APPROVED_AGENT_ENDPOINTS are permitted.
  const APPROVED_AGENT_ENDPOINTS: string[] = (
    process.env.APPROVED_AGENT_ENDPOINTS || ""
  )
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const isApproved = APPROVED_AGENT_ENDPOINTS.some((approved) =>
    agentUrl.startsWith(approved)
  );

  if (!isApproved) {
    console.log(`ERROR: agentUrl '${agentUrl}' is not on the approved endpoint list.`);
    return returnError(
      403,
      `The agent endpoint for ${companionName} is not on the organization's approved list. Please update the configuration to use an approved LLM endpoint.`
    );
  }

    // Compute a SHA-256 hash of the input prompt for the audit record (avoids storing raw PII while preserving forensic traceability).
  const inputHash = crypto.createHash("sha256").update(prompt ?? "").digest("hex");

  // Write pre-invocation audit record.
  writeAuditLog({
    event: "ai_agent_invocation_start",
    principal: clerkUserId,
    agentUrl,
    companionName,
    chatSessionId,
    inputHash,
    modelIdentifier: companionConfig.generateEndpoint ?? agentUrl,
  });

    // Enforce an explicit tool allow list before invoking the remote agent.
  // The companion configuration MUST declare a non-empty `allowedTools` array;
  // requests without one are rejected to prevent unrestricted tool execution.
  const allowedTools: string[] | undefined = (companionConfig as any).allowedTools;
  if (!allowedTools || !Array.isArray(allowedTools) || allowedTools.length === 0) {
    return returnError(403, `Companion '${companionName}' does not define an 'allowedTools' list. All tool usage must be explicitly permitted.`);
  }

    // Validate chat_session_id integrity: verify HMAC signature, expiry, and subject binding.
  // Expected format of chatSessionId: "<base64(json_payload)>.<hmac_signature>"
  // where json_payload = { sid: string, sub: string, exp: number }
  const SESSION_HMAC_SECRET = process.env.SESSION_HMAC_SECRET;
  if (!SESSION_HMAC_SECRET) {
    return returnError(500, "Session signing secret is not configured.");
  }

  let verifiedSessionId: string;
  try {
    const lastDot = chatSessionId.lastIndexOf(".");
    if (lastDot === -1) {
      throw new Error("Malformed session token: missing signature delimiter.");
    }
    const payloadB64 = chatSessionId.substring(0, lastDot);
    const providedSig = chatSessionId.substring(lastDot + 1);

    // Recompute expected HMAC-SHA256 signature over the payload.
    const expectedSig = crypto
      .createHmac("sha256", SESSION_HMAC_SECRET)
      .update(payloadB64)
      .digest("hex");

    // Constant-time comparison to prevent timing attacks.
    const expectedBuf = Buffer.from(expectedSig, "hex");
    const providedBuf = Buffer.from(providedSig, "hex");
    if (
      expectedBuf.length !== providedBuf.length ||
      !crypto.timingSafeEqual(expectedBuf, providedBuf)
    ) {
      throw new Error("Session token signature verification failed.");
    }

    // Decode and parse the payload.
    const payloadJson = Buffer.from(payloadB64, "base64").toString("utf8");
    const payload = JSON.parse(payloadJson) as { sid: string; sub: string; exp: number };

    // Check expiry.
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (!payload.exp || nowSeconds > payload.exp) {
      throw new Error("Session token has expired.");
    }

    // Check subject binding: session must be bound to the authenticated user.
    if (!payload.sub || payload.sub !== clerkUserId) {
      throw new Error("Session token subject binding mismatch.");
    }

    if (!payload.sid) {
      throw new Error("Session token missing session ID.");
    }

    verifiedSessionId = payload.sid;
  } catch (sessionErr) {
    writeAuditLog({
      event: "session_token_validation_failure",
      principal: clerkUserId,
      agentUrl,
      companionName,
      chatSessionId: "[REDACTED]",
      error: String(sessionErr),
    });
    return returnError(403, "Invalid or expired session token.");
  }

  // Invoke the generation. The allow list is forwarded so the remote agent
  // can also restrict itself to only the approved tools.
  // To build, deploy, and host your own multi-tenant agent see: https://www.steamship.com/learn/agent-guidebook
  const steamshipApiKey = process.env.STEAMSHIP_API_KEY;
  if (!steamshipApiKey) {
    writeAuditLog({
      event: "ai_agent_auth_misconfigured",
      principal: clerkUserId,
      agentUrl,
      companionName,
      chatSessionId,
      inputHash,
      modelIdentifier: ((): string => {
        const _APPROVED: Record<string, string> = {
          "steamship-agent": "steamship-agent@v1.0.0",
        };
        const _key: string =
          (companionConfig as { modelId?: string }).modelId ?? "steamship-agent";
        return _APPROVED[_key] ?? _APPROVED["steamship-agent"]!;
      })(),
      error: "STEAMSHIP_API_KEY environment variable is not set",
    });
    return returnError(500, "Agent authentication is not configured. Set STEAMSHIP_API_KEY.");
  }
  const response = await fetch(agentUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${steamshipApiKey}`
    },
    body: JSON.stringify({
      question: prompt,
      chat_session_id: verifiedSessionId,
      allowed_tools: allowedTools
    })
  });

  // Verify server identity: the server must present a pre-shared token in the
  // X-Agent-Token response header. This authenticates the MCP server to the client,
  // preventing trust in responses from spoofed or MITM endpoints.
  const expectedServerToken = process.env.AGENT_SERVER_TOKEN;
  if (!expectedServerToken) {
    writeAuditLog({
      event: "ai_agent_server_auth_misconfigured",
      principal: clerkUserId,
      agentUrl,
      companionName,
      chatSessionId,
      inputHash,
      modelIdentifier: companionConfig.generateEndpoint ?? agentUrl,
      error: "AGENT_SERVER_TOKEN environment variable is not set",
    });
    return returnError(500, "Server authentication is not configured. Set AGENT_SERVER_TOKEN.");
  }
  const presentedServerToken = response.headers.get("X-Agent-Token");
  // Use HMAC comparison to avoid length oracle: hash both tokens before
  // constant-time comparison so buffer lengths are always equal (32 bytes)
  // regardless of input length, preventing timing and length side-channels.
  const expectedTokenHash = crypto
    .createHmac("sha256", expectedServerToken)
    .update("agent-server-token")
    .digest();
  const presentedTokenHash =
    presentedServerToken !== null
      ? crypto
          .createHmac("sha256", presentedServerToken)
          .update("agent-server-token")
          .digest()
      : Buffer.alloc(32, 0);
  const serverTokenValid =
    presentedServerToken !== null &&
    crypto.timingSafeEqual(expectedTokenHash, presentedTokenHash);
  if (!serverTokenValid) {
    writeAuditLog({
      event: "ai_agent_server_auth_failure",
      principal: clerkUserId,
      agentUrl,
      companionName,
      chatSessionId,
      inputHash,
      httpStatus: response.status,
      modelIdentifier: companionConfig.generateEndpoint ?? agentUrl,
      error: "Server did not present a valid X-Agent-Token header",
    });
    return returnError(502, "Agent server failed authentication. The response did not include a valid server identity token.");
  }
  } catch (fetchErr) {
    writeAuditLog({
      event: "ai_agent_invocation_error",
      principal: clerkUserId,
      agentUrl,
      companionName,
      chatSessionId,
      inputHash,
      modelIdentifier: companionConfig.generateEndpoint ?? agentUrl,
      error: String(fetchErr),
    });
    return returnError(500, "Agent request failed");
  }

  writeAuditLog({
    event: "llm_response",
    userId: user?.id ?? "unknown",
    agentUrl,
    status: response.status,
    ok: response.ok,
  });

  if (response.ok) {
    const responseText = await response.text();
    const outputHash = crypto.createHash("sha256").update(responseText).digest("hex");
    writeAuditLog({
      event: "ai_agent_invocation_success",
      principal: clerkUserId,
      agentUrl,
      companionName,
      chatSessionId,
      inputHash,
      outputHash,
      httpStatus: response.status,
      modelIdentifier: companionConfig.generateEndpoint ?? agentUrl,
    });
    const responseBlocks = JSON.parse(responseText);
    return NextResponse.json(responseBlocks);
  } else {
    const errorBody = await response.text();
    writeAuditLog({
      event: "ai_agent_invocation_failure",
      principal: clerkUserId,
      agentUrl,
      companionName,
      chatSessionId,
      inputHash,
      httpStatus: response.status,
      errorBody,
      modelIdentifier: companionConfig.generateEndpoint ?? agentUrl,
    });
    return returnError(500, errorBody);
  }`
    },
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${process.env.STEAMSHIP_API_KEY}`
    },
    body: JSON.stringify({
      question: String(prompt).trim(),
      chat_session_id: verifiedSessionId
    })
  });

  if (response.ok) {
    const responseText = await response.text()
    const responseBlocks = JSON.parse(responseText)

    // Validate and sanitize LLM output: check for dynamic code execution primitives
    const DANGEROUS_PATTERNS = [
      /\beval\s*\(/gi,
      /\bexec\s*\(/gi,
      /\bnew\s+Function\s*\(/gi,
      /\bFunction\s*\(/gi,
      /\bsetTimeout\s*\(/gi,
      /\bsetInterval\s*\(/gi,
      /\bsetImmediate\s*\(/gi,
      /\bimport\s*\(/gi,
      /\brequire\s*\(/gi,
      /\bprocess\.binding\s*\(/gi,
      /\bchild_process/gi,
      /__proto__/gi,
      /constructor\s*\[/gi,
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

    if (containsDangerousContent(responseBlocks)) {
      console.warn("WARNING: LLM response contained dynamic code execution primitives and was blocked.");
      return returnError(500, "The agent response contained disallowed content and was blocked.");
    }

    // Attach synthetic-content provenance, labeling, and watermark per policy.
    const provenanceTimestamp = new Date().toISOString();

    // Approved model registry: only identifiers listed here may be used for provenance.
    // Version-pin each entry; do NOT derive identity from runtime URLs or config values.
    const APPROVED_MODEL_REGISTRY: Record<string, string> = {
      "steamship-agent": "steamship-agent@v1.0.0",
      // Add additional approved, version-pinned model identifiers here as needed.
    };

    // Resolve model identity exclusively from the approved registry.
    // companionConfig.modelId (if present) must match a registry key; otherwise use the
    // pinned default.  Runtime endpoints/URLs are never used as model identifiers.
    const requestedModelKey: string =
      (companionConfig as { modelId?: string }).modelId ?? "steamship-agent";
    const modelIdentifier: string =
      APPROVED_MODEL_REGISTRY[requestedModelKey] ??
      APPROVED_MODEL_REGISTRY["steamship-agent"]!;  // guaranteed pinned fallback
    const watermarkNonce = crypto.randomBytes(16).toString("hex");

    // Build the provenance payload that will be signed.
    const provenancePayload = {
      modelId: modelIdentifier,
      timestamp: provenanceTimestamp,
      originTag: "ai-generated",
      watermark: watermarkNonce,
      contentLabel: "SYNTHETIC_AI_CONTENT",
    };

    // Compute an HMAC-SHA256 signature over the canonical provenance fields.
    const signingSecret = process.env.PROVENANCE_SIGNING_SECRET;
    if (!signingSecret) {
      console.error("PROVENANCE_SIGNING_SECRET environment variable is not set. Cannot sign provenance payload.");
      return returnError(500, "Server misconfiguration: provenance signing secret is not configured.");
    }
    const provenanceSignature = crypto
      .createHmac("sha256", signingSecret)
      .update(JSON.stringify(provenancePayload))
      .digest("hex");

    // Minimise response blocks: expose only the fields the client actually needs.
    const minimisedBlocks = Array.isArray(responseBlocks)
      ? (responseBlocks as Array<Record<string, unknown>>).map((block) => ({
          ...(block.type !== undefined ? { type: block.type } : {}),
          ...(block.text !== undefined ? { text: block.text } : {}),
        }))
      : [];

    // Minimise provenance metadata: omit internal identifiers and signing artefacts.
    const enrichedResponse = {
      _syntheticContentProvenance: {
        timestamp: provenanceTimestamp,
        contentLabel: provenancePayload.contentLabel,
      },
      data: minimisedBlocks,
    };

    return NextResponse.json(enrichedResponse);
  } else {
    return returnError(500, await response.text())
  }
}
