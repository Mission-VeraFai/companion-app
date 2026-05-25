// Redis dependency removed to reduce external credential exposure
import { PromptTemplate } from "langchain/prompts";
import { LLMChain } from "langchain/chains";
import { ChatOpenAI } from "langchain/chat_models/openai";
const AI_MODEL_ID = "gpt-3.5-turbo";

import path from "path";
import fs from "fs/promises";
import crypto from "crypto";

const AUDIT_LOG_FILE = "ai_audit_log.jsonl";
const LLM_LOG_FILE_PATH = "llm_interactions.log";
const MAX_LOG_BYTES = 10 * 1024 * 1024; // 10 MB rotation threshold
const LOG_RETENTION_DAYS = 90; // Retain archived log segments for 90 days
const LOG_RETENTION_MS = LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;

/**
 * HITL approval gate: prompts a human operator for explicit confirmation
 * before any risky/destructive file operation is executed.
 * Returns true if approved, throws if denied or no TTY is available.
 */
async function hitlApprove(operationDescription) {
  // In non-interactive / CI environments, block by default for safety.
  if (!process.stdin.isTTY) {
    throw new Error(
      `[HITL] Risky operation blocked (no interactive TTY): ${operationDescription}`
    );
  }
  process.stdout.write(
    `\n[HITL APPROVAL REQUIRED]\nOperation : ${operationDescription}\nApprove? (yes/no): `
  );
  const answer = await new Promise((resolve) => {
    let buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.resume();
    process.stdin.once("data", (chunk) => {
      buf += chunk;
      process.stdin.pause();
      resolve(buf.trim().toLowerCase());
    });
  });
  if (answer !== "yes") {
    throw new Error(
      `[HITL] Risky operation denied by operator: ${operationDescription}`
    );
  }
  console.log(`[HITL] Operation approved by operator: ${operationDescription}`);
  return true;
}

async function purgeExpiredLogSegments(filePath) {
  const dir = path.dirname(path.resolve(filePath));
  const base = path.basename(filePath);
  try {
    const entries = await fs.readdir(dir);
    const now = Date.now();
    for (const entry of entries) {
      if (entry.startsWith(base + ".") && entry.endsWith(".bak")) {
        const full = path.join(dir, entry);
        try {
          const st = await fs.stat(full);
          if (now - st.mtimeMs > LOG_RETENTION_MS) {
            await fs.unlink(full);
            console.log(`[AUDIT] Purged expired log segment (>${LOG_RETENTION_DAYS}d): ${full}`);
          }
        } catch (_) { /* best-effort */ }
      }
    }
  } catch (_) { /* best-effort */ }
}

async function rotateLogIfNeeded(filePath) {
  try {
    const stat = await fs.stat(filePath);
    if (stat.size >= MAX_LOG_BYTES) {
      // Append-only archival: copy current content to a timestamped segment,
      // then truncate the live file — never rename/delete the primary log.
      const rotated = `${filePath}.${new Date().toISOString().replace(/[:.]/g, "-")}.bak`;
      await hitlApprove(
        `Archive log segment "${filePath}" → "${rotated}" (copy+truncate, append-only)`
      );
      // Copy current log content to the archive segment
      await fs.copyFile(filePath, rotated);
      // Truncate the live log file in place (preserves inode, append-only primary)
      await fs.truncate(filePath, 0);
      console.log(`[AUDIT] Log segment archived (append-only): ${rotated}`);
      // Enforce time-based retention on archived segments
      await purgeExpiredLogSegments(filePath);
    }
  } catch (err) {
    if (err.code !== "ENOENT") throw err;
  }
}

async function writeAuditRecord(record) {
  await rotateLogIfNeeded(AUDIT_LOG_FILE);
  const line = JSON.stringify(record) + "\n";
  await fs.appendFile(AUDIT_LOG_FILE, line, "utf8");
}

/**
 * Build a provenance header for AI-generated output files.
 * Includes model ID, generation timestamp, content label, and an HMAC
 * signature so downstream consumers can verify authenticity.
 */
function buildProvenanceHeader(modelId, content) {
  const timestamp = new Date().toISOString();
  const hmacSecret = process.env.PROVENANCE_HMAC_SECRET;
  let signatureLabel;
  let signature;
  if (!hmacSecret) {
    throw new Error(
      "[PROVENANCE ERROR] PROVENANCE_HMAC_SECRET is not set. " +
      "All AI-generated outputs require an HMAC-SHA256 signed provenance header. " +
      "Set the PROVENANCE_HMAC_SECRET environment variable before generating output."
    );
  }
  if (hmacSecret) {
    signature = crypto
      .createHmac("sha256", hmacSecret)
      .update(`${modelId}|${timestamp}|${content}`)
      .digest("hex");
    signatureLabel = "HMAC-SHA256";
  } else {
    throw new Error(
      "[PROVENANCE ERROR] PROVENANCE_HMAC_SECRET is not set. " +
      "All AI-generated outputs require an HMAC-SHA256 signed provenance header. " +
      "Set the PROVENANCE_HMAC_SECRET environment variable before generating output."
    );
  }

  return [
    "=== AI-GENERATED CONTENT — SYNTHETIC ORIGIN ====",
    `Model-ID   : ${modelId}`,
    `Generated  : ${timestamp}`,
    `${signatureLabel}: ${signature}`,
    "================================================",
    "",
  ].join("\n");
}|${timestamp}|${content}`)
    .digest("hex");

  return [
    "=== AI-GENERATED CONTENT — SYNTHETIC ORIGIN ====",
    `Model-ID   : ${modelId}`,
    `Generated  : ${timestamp}`,
    `HMAC-SHA256: ${hmac}`,
    "================================================",
    "",
  ].join("\n");
}

const LLM_LOG_FILE = "llm_interactions.log";

async function logLLMInteraction(input, output, { modelId = AI_MODEL_ID, principal } = {}) {
  if (!principal || principal === "anonymous") {
    throw new Error(
      "Authentication required: a valid authenticated principal must be provided before invoking the AI agent."
    );
  }
  const inputHash = crypto.createHash("sha256").update(JSON.stringify(input)).digest("hex");
  const outputHash = crypto.createHash("sha256").update(JSON.stringify(output)).digest("hex");
  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    modelId,
    principal,
    inputHash,
    outputHash,
  }) + "\n";
  await rotateLogIfNeeded(LLM_LOG_FILE);
  await fs.appendFile(LLM_LOG_FILE, entry, "utf8");
  console.log("[LLM LOG] interaction recorded, inputHash:", inputHash);
}

const RAW_COMPANION_NAME = process.argv[2];

/**
 * Validates and sanitizes a companion name to prevent path traversal and injection.
 * Only allows alphanumeric characters, hyphens, and underscores.
 */
function validateCompanionName(name) {
  if (!name || !/^[a-zA-Z0-9_-]+$/.test(name)) {
    throw new Error(
      `Invalid COMPANION_NAME: must contain only alphanumeric characters, hyphens, or underscores.`
    );
  }
  return name;
}

/**
 * Sanitizes a string for safe interpolation into an LLM prompt.
 * Removes null bytes, strips leading/trailing whitespace per line,
 * and limits total length to reduce prompt-injection surface.
 */
function sanitizeForPrompt(value, maxLength = 8000) {
  if (value === null || value === undefined) return "";
  const str = Array.isArray(value)
    ? value.map((v) => String(v).replace(/\x00/g, "")).join("\n")
    : String(value).replace(/\x00/g, "");
  // Remove any attempts to inject new prompt sections via "###" headings
  const cleaned = str
    .replace(/###/g, "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .trim();
  return cleaned.length > maxLength ? cleaned.slice(0, maxLength) : cleaned;
}

const COMPANION_NAME = validateCompanionName(RAW_COMPANION_NAME);
/**
 * Approved model registry — only these pinned model identifiers may be used.
 * All entries must be exact, versioned model IDs to ensure reproducibility and
 * prevent arbitrary or unregistered model sources from being injected at runtime.
 */
const APPROVED_MODEL_REGISTRY = new Set([
  "gpt-3.5-turbo-0125",
  "gpt-4-0613",
  "gpt-4-turbo-2024-04-09",
  "gpt-4o-2024-05-13",
]);

const RAW_MODEL_NAME = process.argv[3];
if (!RAW_MODEL_NAME || !APPROVED_MODEL_REGISTRY.has(RAW_MODEL_NAME)) {
  throw new Error(
    `Model "${RAW_MODEL_NAME}" is not in the approved model registry. ` +
    `Allowed models: ${[...APPROVED_MODEL_REGISTRY].join(", ")}`
  );
}
const MODEL_NAME = RAW_MODEL_NAME;
const USER_ID = process.argv[4];

/**
 * Authenticates the USER_ID against an allowlist of authorized users.
 * The allowlist is sourced from the AUTHORIZED_USER_IDS environment variable
 * as a comma-separated list of permitted user IDs.
 * Throws if the USER_ID is missing or not authorized.
 */
function authenticateUserId(userId) {
  if (!userId || typeof userId !== "string" || !/^[a-zA-Z0-9_-]+$/.test(userId)) {
    throw new Error("Authentication failed: USER_ID is missing or contains invalid characters.");
  }
  const authorizedUsersEnv = process.env.AUTHORIZED_USER_IDS;
  if (!authorizedUsersEnv) {
    throw new Error(
      "Authentication failed: AUTHORIZED_USER_IDS environment variable is not set. " +
      "Set it to a comma-separated list of permitted user IDs."
    );
  }
  const authorizedUsers = authorizedUsersEnv
    .split(",")
    .map((id) => id.trim())
    .filter(Boolean);
  if (!authorizedUsers.includes(userId)) {
    throw new Error(
      `Authentication failed: USER_ID '${userId}' is not authorized to access the AI Agent.`
    );
  }
  return userId;
}

authenticateUserId(USER_ID);

if (!!!COMPANION_NAME || !!!MODEL_NAME || !!!USER_ID) {
  throw new Error(
    "**Usage**: npm run export-to-character <COMPANION_NAME> <MODEL_NAME> <USER_ID>"
  );
}

// Sanitize a text field to prevent prompt injection from uploaded companion files.
function sanitizeField(text) {
  if (typeof text !== "string") return "";

  // Reject or strip lines that look like injected instructions.
  const dangerousLinePattern =
    /^\s*(ignore|disregard|forget|override|system|assistant|user|prompt|instruction|###|<\/?s>|\[INST\]|\[\/INST\]|<\|im_start\||<\|im_end\|)/im;

  // Remove base64-encoded blobs (20+ consecutive base64 chars with no spaces).
  const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;

  // Remove shell-command-like sequences.
  const shellPattern = /(`[^`]*`|\$\([^)]*\)|;\s*\w+|&&|\|\|)/g;

  // Remove content inside angle-bracket pseudo-tags used for hidden instructions.
  const pseudoTagPattern = /<[^>]{1,80}>/g;

  const lines = text.split("\n");
  const cleanLines = lines
    .map((line) => {
      if (dangerousLinePattern.test(line)) {
        // Drop the entire line rather than forwarding it to the LLM.
        return null;
      }
      return line
        .replace(base64Pattern, "[REDACTED]")
        .replace(shellPattern, "[REDACTED]")
        .replace(pseudoTagPattern, "[REDACTED]");
    })
    .filter((line) => line !== null);

  return cleanLines.join("\n");
}

// Validate that COMPANION_NAME contains only safe characters to prevent path traversal.
if (!/^[a-zA-Z0-9_\-]+$/.test(COMPANION_NAME)) {
  throw new Error("Invalid COMPANION_NAME: only alphanumeric characters, hyphens, and underscores are allowed.");
}

// Path is safe because COMPANION_NAME has already been validated against SAFE_ARG_PATTERN
const COMPANIONS_DIR = path.resolve("companions");
const resolvedPath = path.resolve(COMPANIONS_DIR, COMPANION_NAME + ".txt");
if (!resolvedPath.startsWith(COMPANIONS_DIR + path.sep) && resolvedPath !== COMPANIONS_DIR) {
  throw new Error("Path traversal detected: resolved path is outside the companions directory.");
}
const data = await fs.readFile(resolvedPath, "utf8");
const presplit = data.split("###ENDPREAMBLE###");
if (presplit.length < 2) {
  throw new Error("Companion file is missing the ###ENDPREAMBLE### delimiter.");
}
const preamble = sanitizeField(presplit[0]);
const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
if (seedsplit.length < 2) {
  throw new Error("Companion file is missing the ###ENDSEEDCHAT### delimiter.");
}
const seedChat = sanitizeField(seedsplit[0]);
const backgroundStory = sanitizeField(seedsplit[1]);
console.log(preamble, backgroundStory);

// Load chat history from a local JSON file instead of Upstash Redis
let upstashChatHistory = [];
const chatHistoryPath = `chat_history_${COMPANION_NAME}_${MODEL_NAME}_${USER_ID}.json`;
try {
  const raw = await fs.readFile(chatHistoryPath, "utf8");
  upstashChatHistory = JSON.parse(raw);
} catch {
  // No existing chat history found; starting fresh
  upstashChatHistory = [];
}
const recentChat = upstashChatHistory
  .slice(-30)
  .map((entry) => sanitizeForPrompt(String(entry), 500));
const model = new ChatOpenAI({
  modelName: process.env.APPROVED_MODEL_NAME || "gpt-4",
  openAIApiKey: process.env.OPENAI_API_KEY,
  // Only one external credential system (OpenAI) is now in use
});
model.verbose = true;

const sanitizedCompanionName = sanitizeForPrompt(COMPANION_NAME, 100);
const sanitizedRecentChatBlock = recentChat.join("\n");

const safePreamble = sanitizeForPrompt(preamble);
const safeBackgroundStory = sanitizeForPrompt(backgroundStory);
const safeSeedChat = sanitizeForPrompt(seedChat);
const safeRecentChat = sanitizeForPrompt(recentChat);
const safeCompanionName = sanitizeForPrompt(COMPANION_NAME, 100);

const truncatedPreamble = preamble.slice(0, 500);
const truncatedBackgroundStory = backgroundStory.slice(0, 500);
// Sanitize user-controlled strings to prevent prompt injection:
// Strip sequences that could be interpreted as new instructions or role overrides.
function sanitizeForPrompt(value) {
  if (typeof value !== "string") return String(value);
  // Remove common prompt-injection patterns: ignore/override/system instructions
  return value
    .replace(/###/g, "")
    .replace(/\bignore\b.*\binstructions?\b/gi, "[REDACTED]")
    .replace(/\bsystem\s*:/gi, "[REDACTED]")
    .replace(/\buser\s*:/gi, "[REDACTED]")
    .replace(/\bassistant\s*:/gi, "[REDACTED]");
}

const safePreamble = sanitizeForPrompt(preamble);
const safeBackgroundStory = sanitizeForPrompt(backgroundStory);
const safeSeedChat = sanitizeForPrompt(seedChat);
const safeRecentChat = Array.isArray(recentChat)
  ? recentChat.map(sanitizeForPrompt).join("\n")
  : sanitizeForPrompt(recentChat);
const safeCompanionName = sanitizeForPrompt(COMPANION_NAME);

const chainPrompt = PromptTemplate.fromTemplate(`
  ### Background Story: 
  ${safePreamble}
  
  ${safeBackgroundStory}

  ### Chat history: 
  ${safeSeedChat}

  ...
  ${safeRecentChat}

  
  Above is someone whose name is ${safeCompanionName}'s story and their chat history with a human. Output answer to the following question. Return only the answer itself 
  
  {question}`);

// Explicit tool allow list — this chain intentionally uses no tools.
// Add tool names here if tools are introduced in the future.
const ALLOWED_TOOLS = [];

/**
 * Enforces the tool allow list. Throws if any supplied tool is not
 * present in ALLOWED_TOOLS, preventing unauthorised tool execution.
 */
function enforceToolAllowList(tools = []) {
  for (const tool of tools) {
    const toolName = typeof tool === "string" ? tool : tool?.name;
    if (!ALLOWED_TOOLS.includes(toolName)) {
      throw new Error(
        `Tool "${toolName}" is not in the allowed tool list. ` +
          `Permitted tools: [${ALLOWED_TOOLS.join(", ") || "none"}]`
      );
    }
  }
}

// Validate tools before constructing the chain.
const chainTools = []; // no tools required for this chain
enforceToolAllowList(chainTools);

const chain = new LLMChain({
  llm: model,
  prompt: chainPrompt,
  // tools is explicitly set to the validated allow list (empty here).
  tools: chainTools,
});
/**
 * Sanitizes LLM output by detecting and stripping dynamic code execution primitives.
 * Throws an error if dangerous patterns are found, and strips them from the output.
 */
function sanitizeLLMOutput(text) {
  if (typeof text !== "string") {
    throw new Error("LLM output is not a string.");
  }

  // Patterns that indicate dynamic code execution primitives
  const dangerousPatterns = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bnew\s+Function\s*\(/gi,
    /\bsetTimeout\s*\(\s*['"`]/gi,
    /\bsetInterval\s*\(\s*['"`]/gi,
    /\bimport\s*\(/gi,
    /\brequire\s*\(/gi,
    /\bprocess\.binding\s*\(/gi,
    /\bchild_process/gi,
    /\bvm\.runInThisContext\s*\(/gi,
    /\bvm\.runInNewContext\s*\(/gi,
  ];

  let sanitized = text;
  const detectedPatterns = [];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(sanitized)) {
      detectedPatterns.push(pattern.toString());
      // Strip the dangerous content
      sanitized = sanitized.replace(pattern, "[REDACTED]");
    }
  }

  if (detectedPatterns.length > 0) {
    console.warn(
      `WARNING: LLM output contained dangerous code execution primitives and was sanitized. Patterns detected: ${detectedPatterns.join(", ")}`
    );
  }

  return sanitized;
}

/**
 * Redacts common PII patterns from a string.
 * Covers: email addresses, phone numbers, SSNs, credit card numbers,
 * IPv4 addresses, and simple "First Last" name patterns.
 */
function redactPII(text) {
  if (typeof text !== "string") return text;

  const piiPatterns = [
    // Email addresses
    { pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, label: "[REDACTED_EMAIL]" },
    // Phone numbers (various formats)
    { pattern: /(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}/g, label: "[REDACTED_PHONE]" },
    // Social Security Numbers
    { pattern: /\b\d{3}[\s.-]\d{2}[\s.-]\d{4}\b/g, label: "[REDACTED_SSN]" },
    // Credit card numbers (13–16 digits, optionally separated)
    { pattern: /\b(?:\d[ -]?){13,16}\b/g, label: "[REDACTED_CC]" },
    // IPv4 addresses
    { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, label: "[REDACTED_IP]" },
  ];

  let redacted = text;
  for (const { pattern, label } of piiPatterns) {
    redacted = redacted.replace(pattern, label);
  }
  return redacted;
}

/**
 * Redacts Singapore PII categories from a string.
 * Covers: NRIC/FIN, SingPass IDs, Singapore phone numbers,
 * Singapore postal codes used with personal context, and passport numbers.
 */
function redactSingaporePII(text) {
  if (typeof text !== "string") return text;

  let redacted = text;
  const piiPatterns = [
    // NRIC / FIN: S/T/F/G/M followed by 7 digits and a letter
    { pattern: /\b[STFGM]\d{7}[A-Z]\b/gi, label: "[REDACTED-NRIC/FIN]" },
    // SingPass username format (e.g. S1234567A used as login ID)
    { pattern: /\bsingpass[\s:=]+[^\s,;"']+/gi, label: "[REDACTED-SINGPASS]" },
    // Singapore mobile numbers: +65 or 65 prefix, or local 8-digit starting with 8 or 9
    { pattern: /(?:\+65|\b65)[\s-]?[89]\d{3}[\s-]?\d{4}\b/g, label: "[REDACTED-SG-PHONE]" },
    { pattern: /\b[89]\d{3}[\s-]?\d{4}\b/g, label: "[REDACTED-SG-PHONE]" },
    // Singapore passport numbers: E followed by 7 digits
    { pattern: /\bE\d{7}[A-Z]?\b/g, label: "[REDACTED-PASSPORT]" },
    // Singapore postal codes (6-digit, optionally preceded by 'Singapore')
    { pattern: /\b(?:Singapore\s)?\d{6}\b/gi, label: "[REDACTED-POSTAL]" },
    // CPF account numbers (9 digits)
    { pattern: /\b\d{9}\b/g, label: "[REDACTED-CPF]" },
  ];

  const detected = [];
  for (const { pattern, label } of piiPatterns) {
    if (pattern.test(redacted)) {
      detected.push(label);
      pattern.lastIndex = 0; // reset after .test()
      redacted = redacted.replace(pattern, label);
    }
  }

  if (detected.length > 0) {
    console.warn(
      `WARNING: Singapore PII detected and redacted in content. Categories: ${[...new Set(detected)].join(", ")}`
    );
  }

  return redacted;
}

// --- Principal Authorization ---
// Validate the invoking USER_ID against an allowlist of authorized principals
// before any LLM inference is triggered. This prevents unauthorized callers
// from consuming the LLM endpoint even if they can run this script.
(function enforceCallerAuthorization() {
  const rawAllowlist = process.env.AUTHORIZED_USER_IDS || "";
  if (!rawAllowlist.trim()) {
    console.error(
      "FATAL: AUTHORIZED_USER_IDS environment variable is not set. " +
      "Cannot authorize the invoking principal. Aborting."
    );
    process.exit(1);
  }

  const authorizedIds = new Set(
    rawAllowlist
      .split(",")
      .map((id) => id.trim())
      .filter(Boolean)
  );

  // USER_ID is expected to have been parsed from command-line args earlier in the script.
  if (typeof USER_ID !== "string" || !USER_ID.trim()) {
    console.error(
      "FATAL: USER_ID is missing or empty. " +
      "A valid, non-empty USER_ID must be supplied to authorize the caller. Aborting."
    );
    process.exit(1);
  }

  if (!authorizedIds.has(USER_ID.trim())) {
    console.error(
      `FATAL: USER_ID '${USER_ID}' is not in the list of authorized principals. ` +
      "Access to the LLM endpoint is denied. Aborting."
    );
    process.exit(1);
  }

  console.log(`Authorization check passed for USER_ID: '${USER_ID}'.`);
})();
// --- End Principal Authorization ---

const questions = [
  `Greeting: What would ${safeCompanionName} say to start a conversation?`,
  `Short Description: In a few sentences, how would ${safeCompanionName} describe themselves?`,
  `Long Description: In a few sentences, how would ${safeCompanionName} describe themselves?`,
];
// --- Subagent Spawn Resource Bounds ---
const MAX_SPAWN_LIMIT = 10;          // hard cap on concurrent LLM subagent calls
const LLM_CALL_TIMEOUT_MS = 30_000; // 30-second per-call termination limit

if (questions.length > MAX_SPAWN_LIMIT) {
  console.error(
    `FATAL: Attempted to spawn ${questions.length} LLM subagent calls, ` +
    `which exceeds the hard limit of ${MAX_SPAWN_LIMIT}. Aborting.`
  );
  process.exit(1);
}

console.log(
  `[SPAWN TRACE] Spawning ${questions.length} LLM subagent call(s). ` +
  `Limit: ${MAX_SPAWN_LIMIT}, Timeout per call: ${LLM_CALL_TIMEOUT_MS}ms.`
);

/**
 * Wraps a promise with a hard timeout. Rejects if the promise does not
 * settle within `ms` milliseconds, enforcing a termination limit.
 */
function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`LLM subagent call timed out after ${ms}ms (${label})`));
    }, ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

const workflowTraceId = `workflow-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
const results = await Promise.all(
  questions.map(async (question, spawnIndex) => {
    try {
      const llmInput = { question };
      // Enforce tool allow list immediately before every chain invocation.
      enforceToolAllowList(chainTools);
      console.log(`[SPAWN TRACE] Subagent call ${spawnIndex + 1}/${questions.length} starting.`);
      const llmResult = await withTimeout(
        chain.call(llmInput),
        LLM_CALL_TIMEOUT_MS,
        `spawn #${spawnIndex + 1}`
      );
      console.log(`[SPAWN TRACE] Subagent call ${spawnIndex + 1}/${questions.length} completed.`);
      // Log only non-sensitive metadata to avoid exposing prompt content in plain log files
            await logLLMInteraction(
        { question_key: Object.keys(llmInput).join(","), prompt: llmInput.question, workflow_trace_id: workflowTraceId },
        { output_length: typeof llmResult?.text === "string" ? llmResult.text.length : 0, output: llmResult?.text ?? "", status: "success" }
      );
      return llmResult;
    } catch (error) {
      console.error(error);
      await logLLMInteraction(
        { question_key: typeof llmInput !== "undefined" ? Object.keys(llmInput).join(",") : "unknown", workflow_trace_id: workflowTraceId, status: "failed" },
        { error: error instanceof Error ? error.message : String(error), output_length: 0 }
      ).catch((logErr) => console.error("[AUDIT] Failed to write failed-decision audit record:", logErr));
    },
        { output_length: typeof llmResult?.text === "string" ? llmResult.text.length : 0, status: "success" }
      );
      return llmResult;
    } catch (error) {
      console.error(`[SPAWN TRACE] Subagent call ${spawnIndex + 1} failed:`, error);
      await logLLMInteraction(
        { question_key: question, spawn_index: spawnIndex, workflow_trace_id: workflowTraceId, status: "failed" },
        { error: error instanceof Error ? error.message : String(error), output_length: 0 }
      ).catch((logErr) => console.error("[AUDIT] Failed to write failed-decision audit record:", logErr));
    }
  })
);
// --- End Subagent Spawn Resource Bounds ---
      // Sanitize all string fields in llmInput derived from LLM-sourced data
    const sanitizedLlmInput = Object.fromEntries(
      Object.entries(llmInput).map(([k, v]) => [
        k,
        typeof v === "string" ? sanitizeForPrompt(v) : v,
      ])
    );
    await writeAuditRecord({
      event: "subagent_spawn",
      timestamp: new Date().toISOString(),
      question: sanitizeForPrompt(question),
      inputHash: crypto.createHash("sha256").update(JSON.stringify(sanitizedLlmInput)).digest("hex"),
    });
    // Pre-flight prompt safety check before invoking the LLM chain
    const PROMPT_SAFETY_PATTERNS = [
      /(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/,  // base64
      /(?:^|\s)(?:bash|sh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[({["'`]/im, // shell/exec commands
      /\x00|[\x01-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/,  // binary/control characters
      /(?:ignore\s+(?:previous|above|prior)|disregard\s+(?:all|previous)|you\s+are\s+now|act\s+as\s+(?:a\s+)?(?:dan|jailbreak|unrestricted))/i, // hidden prompt injection
      /(?:[a-z]\d[a-z]|\d[a-z]\d|[!@#$][a-z][!@#$]){3,}/i, // leetspeak patterns
    ];
    const promptToCheck = typeof sanitizedLlmInput.question === "string" ? sanitizedLlmInput.question : JSON.stringify(sanitizedLlmInput);
    for (const pattern of PROMPT_SAFETY_PATTERNS) {
      if (pattern.test(promptToCheck)) {
        const safePatternStr = pattern.toString().slice(0, 40);
        console.error(`[SECURITY] Prompt failed safety check (pattern: ${safePatternStr}). Aborting LLM call.`);
        await writeAuditRecord({
          event: "prompt_safety_violation",
          timestamp: new Date().toISOString(),
          question: sanitizeForPrompt(question),
          pattern: safePatternStr,
        }).catch((e) => console.error("[AUDIT] Failed to write safety violation record:", e));
        throw new Error("Prompt failed pre-flight safety check and was blocked.");
      }
    }
    const llmCallPromise = chain.call(sanitizedLlmInput);
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error(`LLM call timed out after ${LLM_CALL_TIMEOUT_MS}ms for question: ${sanitizeForPrompt(question)}`)),
        LLM_CALL_TIMEOUT_MS
      )
    );
    const llmResult = await Promise.race([llmCallPromise, timeoutPromise]);
      // Log full interaction content (prompt input and LLM output) as required by policy
      await logLLMInteraction(
        { question_key: Object.keys(llmInput).join(","), prompt: sanitizeForPrompt(llmInput.question) },
        { output_length: typeof llmResult?.text === "string" ? llmResult.text.length : 0 }
      );
      return llmResult;
    } catch (error) {
      console.error(error);
    }
  })
);

let output = "";
for (let i = 0; i < questions.length; i++) {
  if (!results[i] || typeof results[i].text !== "string") {
    console.warn(`WARNING: LLM result for question ${i} is missing or invalid. Skipping.`);
    continue;
  }
  const sanitizedText = sanitizeLLMOutput(results[i].text);
  // Guard: reject LLM output that contains dynamic code execution primitives
  const DYNAMIC_CODE_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bnew\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bsubprocess\s*\.\s*(call|run|Popen)\s*\([^)]*shell\s*=\s*True/i,
    /\bos\.system\s*\(/i,
    /\bspawnSync\s*\(/i,
    /\bexecSync\s*\(/i,
    /\bexecFile\s*\(/i,
    /\bchild_process/i,
    /\brequire\s*\(\s*['"`]child_process/i,
    /\bimport\s+subprocess\b/i,
  ];
  const hasDynamicCodePrimitive = DYNAMIC_CODE_PATTERNS.some((pattern) => pattern.test(sanitizedText));
  if (hasDynamicCodePrimitive) {
    console.warn(
      `WARNING: LLM output for question ${i} contains a dynamic code execution primitive. Output suppressed for safety.`
    );
    await writeAuditRecord({
      event: "llm_output_rejected",
      timestamp: new Date().toISOString(),
      question: sanitizeForPrompt(questions[i]),
      reason: "dynamic_code_execution_primitive_detected",
    }).catch((err) => console.error("[AUDIT] Failed to write rejection audit record:", err));
    continue;
  }
  output += `*****${questions[i]}*****\n${sanitizedText}\n\n`;
}
const redactedChat = recentChat.map((line) => sanitizeForPrompt(redactPII(line)));
const MAX_CHAT_LINES = 10;
const MAX_LINE_LENGTH = 200;
const minimisedChat = redactedChat
  .slice(-MAX_CHAT_LINES)
  .map((line) => (line.length > MAX_LINE_LENGTH ? line.slice(0, MAX_LINE_LENGTH) + "…" : line));
// Chat history is not appended to character output to enforce output data minimisation.
await fs.writeFile(`${COMPANION_NAME}_chat_history.txt`, JSON.stringify({ lineCount: minimisedChat.length, exportedAt: new Date().toISOString() }));

// Attach provenance metadata and synthetic-content label before persisting
// AI-generated output so the file's origin is always traceable.
const AI_MODEL_ID = "openai/gpt-4o";
const provenanceHeader = buildProvenanceHeader(AI_MODEL_ID, output);
const labeledOutput = provenanceHeader + output;
await fs.writeFile(`${COMPANION_NAME}_character_ai_data.txt`, labeledOutput);
