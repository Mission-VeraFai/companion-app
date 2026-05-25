import dotenv from "dotenv";
import clerk from "@clerk/clerk-sdk-node";
import { NextResponse } from "next/server";
import { currentUser } from "@clerk/nextjs";
import { rateLimit } from "@/app/utils/rateLimit";
import {Md5} from 'ts-md5'
import ConfigManager from "@/app/utils/config";

// Approved model registry: maps approved agentUrl prefixes to pinned model identity and version.
// Only endpoints listed here are permitted for inference.
const APPROVED_MODEL_REGISTRY: Array<{
  urlPrefix: string;
  modelProvider: string;
  modelName: string;
  modelVersion: string;
}> = [
  {
    urlPrefix: "https://api.steamship.com/",
    modelProvider: "steamship",
    modelName: "gpt-3.5-turbo",
    modelVersion: "3.5-turbo-0125",
  },
  {
    urlPrefix: "https://steamship.run/",
    modelProvider: "steamship",
    modelName: "gpt-3.5-turbo",
    modelVersion: "3.5-turbo-0125",
  },
];

function getRegistryEntry(agentUrl: string) {
  return APPROVED_MODEL_REGISTRY.find((entry) =>
    agentUrl.startsWith(entry.urlPrefix)
  ) ?? null;
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

const AUDIT_LOG_PATH = path.resolve(process.cwd(), "audit.log");

function writeAuditRecord(record: Record<string, unknown>): void {
  const line = JSON.stringify(record) + "\n";
  fs.appendFileSync(AUDIT_LOG_PATH, line, { encoding: "utf8", flag: "a" });
}
import { createHmac } from "crypto";

dotenv.config({ path: `.env.local` });

// Allowlist of permitted hostnames for outbound agent fetch requests.
const ALLOWED_AGENT_HOSTNAMES: string[] = [
  "api.steamship.com",
  "steamship.com",
];

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

    const response = await fetch(agentUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${process.env.STEAMSHIP_API_KEY}`,
      "X-Agent-User-Id": clerkUserId as string,
      "X-Agent-User-Name": clerkUserName || ""
    },
    body: JSON.stringify({
      question: prompt,
      chat_session_id: chatSessionId,
      _model_identity: modelIdentityMetadata,
    })
  });

  if (response.ok) {
    const responseText = await response.text();
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
    return NextResponse.json(responseBlocks);
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
    return returnError(500, errorText);
  }`
    },
    body: JSON.stringify({
      question: prompt,
      chat_session_id: chatSessionId
    })
  });

  if (response.ok) {
    const responseText = await response.text()
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

    if (containsDangerousContent(responseBlocks)) {
      console.error("ERROR: LLM response contains dynamic code execution primitives — rejecting response.");
      return returnError(500, "The agent response was rejected due to unsafe content.");
    }

    return NextResponse.json(responseBlocks)
  } else {
    return returnError(500, await response.text())
  }
}
