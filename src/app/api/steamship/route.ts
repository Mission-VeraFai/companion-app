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

const AUDIT_LOG_PATH = path.resolve(process.cwd(), "audit_ai_actions.log");

function writeAuditLog(entry: Record<string, unknown>): void {
  const line = JSON.stringify({ ...entry, timestamp: new Date().toISOString() }) + "\n";
  try {
    fs.appendFileSync(AUDIT_LOG_PATH, line, { encoding: "utf8", flag: "a" });
  } catch (err) {
    // Fallback: emit to stderr so the record is not silently lost
    process.stderr.write("[AUDIT LOG WRITE FAILURE] " + line);
  }
}

dotenv.config({ path: `.env.local` });

// Approved model registry: only these pinned, versioned endpoints are permitted.
// Add new approved endpoints here after security review.
const APPROVED_MODEL_REGISTRY: Record<string, { version: string; endpoint: string }> = {
  "steamship-agent-v1": {
    version: "1.0.0",
    endpoint: process.env.APPROVED_STEAMSHIP_ENDPOINT_V1 || "",
  },
};

function isApprovedEndpoint(url: string): boolean {
  if (!url) return false;
  return Object.values(APPROVED_MODEL_REGISTRY).some(
    (entry) => entry.endpoint && entry.endpoint === url
  );
}

// Allowlist of hostnames permitted for outbound agent fetch calls.
// Override via comma-separated ALLOWED_AGENT_HOSTNAMES env var, e.g. "api.steamship.com,staging.steamship.com"
const DEFAULT_ALLOWED_AGENT_HOSTNAMES = ["api.steamship.com"];
const ALLOWED_AGENT_HOSTNAMES: string[] = process.env.ALLOWED_AGENT_HOSTNAMES
  ? process.env.ALLOWED_AGENT_HOSTNAMES.split(",").map((h) => h.trim().toLowerCase())
  : DEFAULT_ALLOWED_AGENT_HOSTNAMES;

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

const MAX_PROMPT_LENGTH = 2000;

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

  // Invoke the generation. The allow list is forwarded so the remote agent
  // can also restrict itself to only the approved tools.
  // To build, deploy, and host your own multi-tenant agent see: https://www.steamship.com/learn/agent-guidebook
  const response = await fetch(agentUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${process.env.STEAMSHIP_API_KEY}`
    },
    body: JSON.stringify({
      question: prompt,
      chat_session_id: chatSessionId,
      allowed_tools: allowedTools
    })
  });
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
    body: JSON.stringify({
      question: String(prompt).trim(),
      chat_session_id: chatSessionId
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

    return NextResponse.json(responseBlocks)
  } else {
    return returnError(500, await response.text())
  }
}
