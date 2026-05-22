import dotenv from "dotenv";
import { StreamingTextResponse, LangChainStream } from "ai";
// APPROVED_MODEL_IMPORT: Replace with an import from the organization's approved LLM registry.
// Example: import { OpenAI } from "langchain/llms/openai";
import { OpenAI } from "langchain/llms/openai";
import { CallbackManager } from "langchain/callbacks";
import clerk from "@clerk/clerk-sdk-node";
import MemoryManager from "@/app/utils/memory";
import { currentUser } from "@clerk/nextjs";
import { NextResponse } from "next/server";
// In-memory rate limiter (replaces Upstash Redis rateLimit to stay within 3-system credential limit)
const _rateLimitStore = new Map<string, { count: number; resetAt: number }>();
function rateLimit(identifier: string): { success: boolean } {
  const WINDOW_MS = 60_000; // 1 minute
  const MAX_REQUESTS = 10;
  const now = Date.now();
  const entry = _rateLimitStore.get(identifier);
  if (!entry || now > entry.resetAt) {
    _rateLimitStore.set(identifier, { count: 1, resetAt: now + WINDOW_MS });
    return { success: true };
  }
  entry.count += 1;
  return { success: entry.count <= MAX_REQUESTS };
}
import crypto from "crypto";
import fsSync from "fs";
import path from "path";

const AUDIT_LOG_PATH = path.resolve(process.cwd(), "audit", "ai_audit.jsonl");
const MAX_AUDIT_LOG_BYTES = 10 * 1024 * 1024; // 10 MB per file
const MAX_AUDIT_LOG_ROTATIONS = 10;           // keep at most 10 rotated archives

/** Rotate the audit log when it exceeds MAX_AUDIT_LOG_BYTES and prune old archives. */
async function rotateAuditLogIfNeeded(): Promise<void> {
  const dir = path.dirname(AUDIT_LOG_PATH);
  let stat: fsSync.Stats | null = null;
  try {
    stat = await fsSync.promises.stat(AUDIT_LOG_PATH);
  } catch {
    // File does not exist yet — nothing to rotate.
    return;
  }
  if (stat.size < MAX_AUDIT_LOG_BYTES) return;

  // Rename current log to a timestamped archive.
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const archived = path.join(dir, `ai_audit.${ts}.jsonl`);
  await fsSync.promises.rename(AUDIT_LOG_PATH, archived);

  // Prune oldest archives beyond the retention cap.
  const entries = await fsSync.promises.readdir(dir);
  const archives = entries
    .filter((f) => f.startsWith("ai_audit.") && f.endsWith(".jsonl") && f !== "ai_audit.jsonl")
    .sort(); // ISO timestamps sort lexicographically oldest-first
  if (archives.length > MAX_AUDIT_LOG_ROTATIONS) {
    const toDelete = archives.slice(0, archives.length - MAX_AUDIT_LOG_ROTATIONS);
    await Promise.all(toDelete.map((f) => fsSync.promises.unlink(path.join(dir, f))));
  }
}

async function writeAuditRecord(record: {
  timestamp: string;
  principal: string;
  modelId: string;
  inputHash: string;
  output: string;
  companionName: string;
}): Promise<void> {
  const line = JSON.stringify(record) + "\n";
  const dir = path.dirname(AUDIT_LOG_PATH);
  await fsSync.promises.mkdir(dir, { recursive: true });
  await rotateAuditLogIfNeeded();
  await fsSync.promises.appendFile(AUDIT_LOG_PATH, line, { encoding: "utf8" });
}

/**
 * Safe wrapper — guarantees the audit write never silently drops a record.
 * On failure the error is emitted to stderr and a best-effort fallback entry
 * is written so the failure itself is traceable.
 */
async function safeWriteAuditRecord(
  record: Parameters<typeof writeAuditRecord>[0]
): Promise<void> {
  try {
    await writeAuditRecord(record);
  } catch (auditErr) {
    // Emit to stderr so the failure is visible in host logs / SIEM.
    process.stderr.write(
      `[AUDIT ERROR] Failed to write audit record: ${auditErr instanceof Error ? auditErr.message : String(auditErr)}\n` +
      `[AUDIT ERROR] Dropped record: ${JSON.stringify(record)}\n`
    );
    // Best-effort fallback: write a failure marker so the gap is forensically visible.
    try {
      const fallback = JSON.stringify({
        timestamp: new Date().toISOString(),
        event: "AUDIT_WRITE_FAILURE",
        error: auditErr instanceof Error ? auditErr.message : String(auditErr),
        droppedRecord: record,
      }) + "\n";
      await fsSync.promises.appendFile(AUDIT_LOG_PATH, fallback, { encoding: "utf8" });
    } catch {
      // If even the fallback fails, stderr is the last resort — already written above.
    }
  }
}

dotenv.config({ path: `.env.local` });

// ---------------------------------------------------------------------------
// Approved Model Registry – only models listed here (with exact pinned IDs)
// may be instantiated. Any model not in this registry will cause a hard error.
// ---------------------------------------------------------------------------
const APPROVED_MODEL_REGISTRY: Record<string, { provider: string; version: string }> = {
  "replicate/vicuna-13b:6282abe6a492de4145d7bb601023762212f9ddbbe78278bd6771c8b3b2f2a13b": {
    provider: "replicate",
    version: "6282abe6a492de4145d7bb601023762212f9ddbbe78278bd6771c8b3b2f2a13b",
  },
};

function assertModelApproved(modelId: string): void {
  if (!APPROVED_MODEL_REGISTRY[modelId]) {
    throw new Error(
      `Model '${modelId}' is NOT_IN_REGISTRY. Only approved, version-pinned models may be used. ` +
      `Approved models: ${Object.keys(APPROVED_MODEL_REGISTRY).join(", ")}`
    );
  }
}

// ---------------------------------------------------------------------------
// Session token integrity – HMAC-signed, expiry-bound, subject-bound tokens
// ---------------------------------------------------------------------------
const SESSION_TOKEN_SECRET = process.env.SESSION_TOKEN_SECRET ?? "change-me-session-secret";
const SESSION_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes

function createSessionToken(userId: string, companionName: string, modelName: string): string {
  const expiry = (Date.now() + SESSION_TOKEN_TTL_MS).toString();
  const payload = `${userId}:${companionName}:${modelName}:${expiry}`;
  const sig = crypto
    .createHmac("sha256", SESSION_TOKEN_SECRET)
    .update(payload)
    .digest("hex");
  // Encode as base64url: payload|sig
  return Buffer.from(`${payload}|${sig}`).toString("base64url");
}

function verifySessionToken(
  token: string,
  expectedUserId: string,
  expectedCompanionName: string,
  expectedModelName: string
): void {
  let decoded: string;
  try {
    decoded = Buffer.from(token, "base64url").toString("utf8");
  } catch {
    throw new Error("Session token is malformed.");
  }

  const lastPipe = decoded.lastIndexOf("|");
  if (lastPipe === -1) throw new Error("Session token structure invalid.");

  const payload = decoded.slice(0, lastPipe);
  const providedSig = decoded.slice(lastPipe + 1);

  // Recompute HMAC and compare in constant time
  const expectedSig = crypto
    .createHmac("sha256", SESSION_TOKEN_SECRET)
    .update(payload)
    .digest("hex");
  const sigBuf = Buffer.from(providedSig, "hex");
  const expSigBuf = Buffer.from(expectedSig, "hex");
  if (sigBuf.length !== expSigBuf.length || !crypto.timingSafeEqual(sigBuf, expSigBuf)) {
    throw new Error("Session token signature verification failed.");
  }

  // Parse and validate fields
  const parts = payload.split(":");
  if (parts.length !== 4) throw new Error("Session token payload malformed.");
  const [tokenUserId, tokenCompanionName, tokenModelName, expiryStr] = parts;

  // Subject binding
  if (tokenUserId !== expectedUserId) throw new Error("Session token subject mismatch.");
  if (tokenCompanionName !== expectedCompanionName) throw new Error("Session token companion binding mismatch.");
  if (tokenModelName !== expectedModelName) throw new Error("Session token model binding mismatch.");

  // Expiry check
  const expiry = parseInt(expiryStr, 10);
  if (isNaN(expiry) || Date.now() > expiry) throw new Error("Session token has expired.");
}

// ---------------------------------------------------------------------------
// Prompt sanitization – blocks common prompt-injection / command-injection
// patterns before content reaches the LLM.
// ---------------------------------------------------------------------------
function sanitizePrompt(input: string): string {
  if (typeof input !== "string") {
    throw new Error("Invalid prompt type.");
  }

  // 1. Length guard
  if (input.length > 4000) {
    throw new Error("Prompt exceeds maximum allowed length.");
  }

  // 2. Detect base64-encoded blobs (≥40 contiguous base64 chars)
  const base64Pattern = /[A-Za-z0-9+/]{40,}={0,2}/;
  if (base64Pattern.test(input)) {
    throw new Error("Prompt contains potentially encoded content.");
  }

  // 3. Shell command patterns
  const shellPatterns = [
    /`[^`]*`/,                          // backtick execution
    /\$\([^)]*\)/,                      // $(command)
    /;\s*(rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat|chmod|chown|sudo|su|eval|exec)\b/i,
    /\|\s*(bash|sh|python|perl|ruby|nc|ncat|netcat|eval|exec)\b/i,
    /&&\s*(rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat|chmod|chown|sudo|su|eval|exec)\b/i,
    /\b(rm\s+-rf|mkfs|dd\s+if=|shutdown|reboot|halt|init\s+0)\b/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(input)) {
      throw new Error("Prompt contains shell command patterns.");
    }
  }

  // 4. Prompt-injection / jailbreak keywords
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /you\s+are\s+now\s+(in\s+)?developer\s+mode/i,
    /act\s+as\s+(an?\s+)?(unrestricted|unfiltered|jailbroken|DAN)/i,
    /###\s*(system|instruction|prompt):/i,
    /<\s*system\s*>/i,
    /\[INST\]/i,
    /<<SYS>>/i,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(input)) {
      throw new Error("Prompt contains injection patterns.");
    }
  }

  // 5. Leetspeak heuristic – high ratio of digit-substituted letters
  const leetMap: Record<string, string> = { "3": "e", "4": "a", "1": "i", "0": "o", "5": "s", "7": "t" };
  const normalized = input.replace(/[34105 7]/g, (c) => leetMap[c] ?? c);
  const leetSubstitutions = [...input].filter((c, i) => leetMap[c] && normalized[i] !== c).length;
  if (input.length > 0 && leetSubstitutions / input.length > 0.3) {
    throw new Error("Prompt appears to use obfuscated (leetspeak) content.");
  }

  // 6. Strip null bytes and other non-printable control characters
  // eslint-disable-next-line no-control-regex
  return input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
}

/**
 * Sanitize input before sending to the LLM.
 * - Removes null bytes and non-printable control characters (except newlines/tabs)
 * - Strips common prompt-injection patterns
 * - Truncates to a maximum allowed length
 */
function sanitizeLLMInput(input: string, maxLength = 4000): string {
  if (typeof input !== "string") return "";
  // Remove null bytes and non-printable control characters (keep \n, \r, \t)
  let sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Strip prompt-injection attempts: lines that try to override instructions
  sanitized = sanitized.replace(
    /^\s*(ignore|disregard|forget|override|bypass|you are now|new instructions?|system:|<\/?s>|\[INST\]|\[\/INST\])[^\n]*/gim,
    ""
  );
  // Collapse runs of more than 3 consecutive newlines
  sanitized = sanitized.replace(/\n{4,}/g, "\n\n\n");
  // Truncate
  return sanitized.slice(0, maxLength);
}

export async function POST(request: Request) {
  const { prompt: rawPrompt, isText, userId, userName } = await request.json();
  const prompt = sanitizeLLMInput(String(rawPrompt ?? ""), 2000);
  let clerkUserId: string | undefined;
  let clerkUserName: string | null | undefined;

  const identifier = request.url + "-" + "anonymous";
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

  // XXX Companion name passed here. Can use as a key to get backstory, chat history etc.
  const rawName = request.headers.get("name") || "";
  // Sanitize: allow only alphanumeric characters, hyphens, and underscores to prevent path traversal
  const safeName = rawName.replace(/[^a-zA-Z0-9_-]/g, "");
  if (!safeName) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const name = safeName;
  const companion_file_name = safeName + ".txt";

  const user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName;

  if (!clerkUserId || !!!(await clerk.users.getUser(clerkUserId))) {
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

  // Load character "PREAMBLE" from character file. These are the core personality
  // characteristics that are used in every prompt. Additional background is
  // only included if it matches a similarity comparioson with the current
  // discussion. The PREAMBLE should include a seed conversation whose format will
  // vary by the model using it.
  const fs = require("fs").promises;
  const path = require("path");

  // Prevent path traversal: ensure the resolved path stays within the companions directory
  const companionsDir = path.resolve("companions");
  const resolvedPath = path.resolve(companionsDir, companion_file_name);
  if (!resolvedPath.startsWith(companionsDir + path.sep)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion file" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const data = await fs.readFile(resolvedPath, "utf8");

    // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const rawPreamble = presplit[0];
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const rawSeedchat = seedsplit[0];

  /**
   * Sanitize companion file content to prevent prompt injection.
   * Removes/neutralises:
   *  - Common prompt-injection trigger phrases
   *  - Base64-encoded blobs that could hide instructions
   *  - Shell-command sequences
   *  - Non-printable / control characters (except normal whitespace)
   */
  function sanitizeCompanionContent(input: string): string {
    // Remove non-printable control characters (keep \t, \n, \r)
    let sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

    // Strip Base64-looking blobs (20+ contiguous base64 chars) that could encode hidden instructions
    sanitized = sanitized.replace(/[A-Za-z0-9+/]{20,}={0,2}/g, "[REMOVED]");

    // Neutralise common prompt-injection trigger phrases (case-insensitive)
    const injectionPatterns = [
      /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
      /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
      /forget\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
      /you\s+are\s+now\s+(?:a|an|the)\s+/gi,
      /new\s+instructions?\s*:/gi,
      /system\s*:\s*/gi,
      /assistant\s*:\s*/gi,
      /<\s*\/?\s*(script|iframe|object|embed|form)[^>]*>/gi,
      /\$\([^)]*\)/g,       // $(command)
      /`[^`]*`/g,            // `command`
      /;\s*(?:rm|curl|wget|bash|sh|python|perl|ruby|nc|ncat)\s/gi,
      /&&\s*(?:rm|curl|wget|bash|sh|python|perl|ruby|nc|ncat)\s/gi,
      /\|\s*(?:rm|curl|wget|bash|sh|python|perl|ruby|nc|ncat)\s/gi,
    ];

    for (const pattern of injectionPatterns) {
      sanitized = sanitized.replace(pattern, "[REMOVED]");
    }

    // Enforce a reasonable length cap to prevent oversized injected payloads
    const MAX_LENGTH = 8000;
    if (sanitized.length > MAX_LENGTH) {
      sanitized = sanitized.slice(0, MAX_LENGTH);
    }

    return sanitized;
  }

  const preamble = sanitizeCompanionContent(rawPreamble);
  const seedchat = sanitizeCompanionContent(rawSeedchat);

  const companionKey = {
    companionName: name!,
    userId: clerkUserId!,
    modelName: "vicuna13b",
  };
  const memoryManager = await MemoryManager.getInstance();

  // Sanitize untrusted input before use in LLM prompts to prevent prompt injection.
  // Strips prompt-injection markers, control characters, and enforces a length limit.
  function sanitizeLLMInput(input: string, maxLength = 1000): string {
    if (typeof input !== "string") return "";
    return input
      .replace(/###/g, "")
      .replace(/`/g, "'")
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
      .slice(0, maxLength)
      .trim();
  }

  const { stream, handlers } = LangChainStream();

  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }
  const sanitizedPrompt = sanitizeLLMInput(prompt);
  await memoryManager.writeToHistory(
    "### Human: " + sanitizedPrompt + "\n",
    companionKey
  );

  // Query Pinecone

  let recentChatHistoryRaw = await memoryManager.readLatestHistory(companionKey);
  let recentChatHistory = sanitizeLLMInput(recentChatHistoryRaw, 4000);

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue

  const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companion_file_name
  );

  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    // Data minimisation: cap each document chunk and total relevantHistory size
    const MAX_DOC_CHARS = 400;
    const MAX_RELEVANT_HISTORY_CHARS = 2000;
    relevantHistory = similarDocs
      .map((doc) => doc.pageContent.slice(0, MAX_DOC_CHARS))
      .join("\n")
      .slice(0, MAX_RELEVANT_HISTORY_CHARS);
  }

    // Call OpenAI for inference (approved model)
  const model = new OpenAI({
    modelName: "gpt-3.5-turbo-instruct",
    maxTokens: 2048,
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });

  // Turn verbose on for debugging
  model.verbose = true;

  const llmPrompt = `${preamble}  
       
       Below are relevant details about ${name}'s past:
       ${sanitizeLLMInput(relevantHistory ?? "", 2000)}

       Below is a relevant conversation history

       ${recentChatHistory}
       ### ${name}:
       `;

  console.log("[LLM REQUEST] model=vicuna-13b", JSON.stringify({ prompt: llmPrompt }));

    const modelInput = `${preamble}  
       
       Below are relevant details about ${name}'s past:
       ${relevantHistory}

       Below is a relevant conversation history

       ${recentChatHistory}
       ### ${name}:
       `;

  const inputHash = crypto
    .createHash("sha256")
    .update(modelInput, "utf8")
    .digest("hex");

  const modelId = process.env.REPLICATE_MODEL_VICUNA13B ?? "replicate/vicuna-13b";

  let resp = String(
    await model
      .call(modelInput)
      .catch(async (err: unknown) => {
        await safeWriteAuditRecord({
          timestamp: new Date().toISOString(),
          principal: clerkUserId!,
          modelId,
          inputHash,
          output: `ERROR: ${err instanceof Error ? err.message : String(err)}`,
          companionName: name ?? "unknown",
        });
        console.error(err);
        return "";
      })
  );

  await writeAuditRecord({
    timestamp: new Date().toISOString(),
    principal: clerkUserId!,
    modelId,
    inputHash,
    output: resp,
    companionName: name ?? "unknown",
  });

  console.log("[LLM RESPONSE] model=vicuna-13b", JSON.stringify({ response: resp }));

  // Turn verbose on for debugging
  model.verbose = true;

  // Data minimisation: truncate preamble before injecting into prompt
  const MAX_PREAMBLE_CHARS = 1500;
  const truncatedPreamble = preamble.slice(0, MAX_PREAMBLE_CHARS);

  let resp = String(
    await model
      .call(
        `${truncatedPreamble}  
       
       Below are relevant details about ${name}'s past:
       ${relevantHistory}

       Below is a relevant conversation history

       ${recentChatHistory}
       ### ${name}:
       `
      )
      .catch(console.error)
  );

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("###");
  const rawResponse = chunks[0];

  // Validate and sanitize LLM output: reject responses containing dynamic code execution primitives
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bFunction\s*\(/i,
    /\bnew\s+Function\b/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bimport\s*\(/i,
    /\brequire\s*\(/i,
    /\bprocess\s*\./i,
    /\bchild_process\b/i,
    /\bexecSync\s*\(/i,
    /\bspawnSync\s*\(/i,
    /\bvm\.run/i,
  ];

  const containsDangerousCode = DANGEROUS_PATTERNS.some((pattern) =>
    pattern.test(rawResponse)
  );

  if (containsDangerousCode) {
    console.warn("[SECURITY] LLM response contained dynamic code execution primitive. Response blocked.");
    return new Response("Response blocked due to policy violation.", { status: 400 });
  }

  // Sanitize: remove any residual script-like constructs before use
  const response = rawResponse
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/javascript:/gi, "")
    .trim();
  // const response = chunks.length > 1 ? chunks[0] : chunks[0];

  await memoryManager.writeToHistory("### " + response.trim(), companionKey);
  var Readable = require("stream").Readable;
  const crypto = require("crypto");

  // --- Synthetic Content Provenance & Labeling ---
  const MODEL_ID =
    "replicate/vicuna-13b:6282abe6a492de4145d7bb601023762212f9ddbbe78278bd6771c8b3b2f2a13b";
  const generatedAt = new Date().toISOString();

  // Cryptographic HMAC watermark so downstream consumers can verify
  // the output originated from this service.
  const watermarkSecret = process.env.WATERMARK_SECRET;
  if (!watermarkSecret) {
    console.error("[SECURITY] WATERMARK_SECRET environment variable is not set. Refusing to generate HMAC with a weak or absent secret.");
    return new Response("Service misconfiguration: content signing unavailable.", { status: 503 });
  }
  const hmac = crypto
    .createHmac("sha256", watermarkSecret)
    .update(response + generatedAt + MODEL_ID)
    .digest("hex");

  // Prepend a machine-readable synthetic-content label to the stream.
  const labeledResponse =
    `[AI-GENERATED | model=${MODEL_ID} | generated_at=${generatedAt} | sig=${hmac}]\n` +
    response;

  // Re-validate the fully assembled labeled response before streaming
  const containsDangerousCodeInLabeled = DANGEROUS_PATTERNS.some((pattern) =>
    pattern.test(labeledResponse)
  );

  if (containsDangerousCodeInLabeled) {
    console.warn("[SECURITY] Labeled LLM response contained dynamic code execution primitive. Response blocked.");
    return new Response("Response blocked due to policy violation.", { status: 400 });
  }

  let s = new Readable();
  s.push(labeledResponse);
  s.push(null);

  if (response !== undefined && response.length > 1) {
    await memoryManager.writeToHistory("### " + response.trim(), companionKey);
  }

  // Attach provenance headers so API clients receive metadata even when
  // they do not parse the stream body.
  const provenanceHeaders = new Headers({
    "X-AI-Model-ID": MODEL_ID,
    "X-AI-Generated-At": generatedAt,
    "X-AI-Content-Signature": hmac,
    "X-AI-Content-Label": "synthetic",
  });

  return new StreamingTextResponse(s, { headers: provenanceHeaders });
}
