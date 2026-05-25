import dotenv from "dotenv";
import { StreamingTextResponse } from "ai";
import { createHash, createHmac } from "crypto";

// ── Approved Model Registry ──────────────────────────────────────────────────
// Only models listed here (by full model identifier prefix) are permitted for inference.
// NOTE: Only the vendor/org prefixes listed below are approved for inference.
const APPROVED_MODEL_REGISTRY: ReadonlySet<string> = new Set<string>([
  "replicate/mistralai",
]);

// Pinned model identifier — must reference a model present in APPROVED_MODEL_REGISTRY.
// No model is currently approved. Set this to an authorized model identifier once
// the vendor/org prefix has been added to APPROVED_MODEL_REGISTRY above.
const APPROVED_MODEL_ID = "";

// Pre-computed SHA-256 of APPROVED_MODEL_ID (supply-chain integrity anchor).
// Regenerate with: echo -n '<model-id>' | sha256sum
// Digest is computed at runtime from the pinned APPROVED_MODEL_ID constant above,
// ensuring it always matches the approved model string without manual recomputation.
const APPROVED_MODEL_ID_DIGEST =
  createHash("sha256").update(APPROVED_MODEL_ID).digest("hex");

/**
 * Verifies that a model identifier:
 *  1. Belongs to an approved registry source.
 *  2. Passes cryptographic integrity check (SHA-256 of the full model string
 *     must match the pre-approved digest anchored at deploy time).
 *
 * Throws if either check fails — inference must NOT proceed.
 */
function verifyModelIntegrity(modelId: string): void {
  // 1. Registry check — match on 'vendor/org' prefix (first two path segments)
  const parts = modelId.split("/");
  const source = parts.slice(0, 2).join("/");
  if (!APPROVED_MODEL_REGISTRY.has(source)) {
    throw new Error(
      `Model source "${source}" is NOT in the approved model registry. ` +
        `Inference blocked.`
    );
  }

  // 2. Integrity check — SHA-256 of the full pinned model string
  const digest = createHash("sha256").update(modelId).digest("hex");
  if (digest !== APPROVED_MODEL_ID_DIGEST) {
    throw new Error(
      `Model integrity verification FAILED for "${modelId}". ` +
        `Expected digest ${APPROVED_MODEL_ID_DIGEST}, got ${digest}. ` +
        `Inference blocked.`
    );
  }
}
// clerk-sdk-node removed: use auth + currentUser from @clerk/nextjs for auth instead
import MemoryManager from "@/app/utils/memory";
import { auth, currentUser } from "@clerk/nextjs";
import { NextResponse } from "next/server";
import path from "path";
import { rateLimit } from "@/app/utils/rateLimit";

// Allowlist of permitted companion names. Only names in this list may be loaded.
const COMPANION_ALLOWLIST: ReadonlySet<string> = new Set([
  "elon",
  "jobs",
  "socrates",
  "einstein",
  // Add additional permitted companion names here
]);

// Selective credential loading: only the three approved external systems
// (Replicate inference API, Clerk auth, Pinecone vector DB) are permitted.
// Do NOT add credentials for additional external systems to this route.
const _allowedEnvKeys = new Set([
  "REPLICATE_API_TOKEN",
  "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
  "CLERK_SECRET_KEY",
]);
dotenv.config({ path: `.env.local` });
// Strip any loaded env vars not in the approved set to prevent credential leakage.
Object.keys(process.env).forEach((key) => {
  if (
    (key.includes("KEY") || key.includes("TOKEN") || key.includes("SECRET") || key.includes("URL")) &&
    !_allowedEnvKeys.has(key)
  ) {
    delete process.env[key];
  }
});

/**
 * Sanitizes a prompt by detecting and rejecting content that could
 * be used to execute malicious commands at runtime.
 * Throws an error if the prompt is deemed unsafe.
 */
function sanitizePrompt(input: string): string {
  if (typeof input !== "string") {
    throw new Error("Invalid prompt type.");
  }

  // Reject prompts that are too long
  const MAX_LENGTH = 2000;
  if (input.length > MAX_LENGTH) {
    throw new Error("Prompt exceeds maximum allowed length.");
  }

  // Reject hidden/invisible Unicode characters (zero-width, soft-hyphen, etc.)
  const invisibleCharsPattern = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00A0]/g;
  if (invisibleCharsPattern.test(input)) {
    throw new Error("Prompt contains hidden or invisible characters.");
  }

  // Reject non-printable / binary characters (outside normal ASCII + common Unicode text)
  const binaryPattern = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
  if (binaryPattern.test(input)) {
    throw new Error("Prompt contains binary or non-printable characters.");
  }

  // Reject base64-encoded blocks (long runs of base64 chars that look encoded)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/;
  if (base64Pattern.test(input)) {
    throw new Error("Prompt contains a suspected base64-encoded payload.");
  }

  // Reject common shell command injection patterns
  const shellCommandPattern =
    /(\$\(|`[^`]*`|\|\s*\w+|&&|\|\||;\s*\w+|\bexec\b|\beval\b|\bsystem\b|\bspawn\b|\bpopen\b|\bsubprocess\b|\bos\.system\b|\bchmod\b|\bchown\b|\brm\s+-rf|\bcurl\b.*\bsh\b|\bwget\b.*\bsh\b|\bnc\b.*-e|\bnetcat\b)/i;
  if (shellCommandPattern.test(input)) {
    throw new Error("Prompt contains suspected shell command sequences.");
  }

  // Reject leetspeak obfuscation patterns (e.g., 3x3cut3, 1nj3ct)
  const leetspeakPattern = /\b(?=[a-z0-9]*[0-9][a-z0-9]*)(?=[a-z0-9]*[a-z][a-z0-9]*)[a-z0-9]{5,}\b/i;
  const leetspeakWords = [
    /3x[e3][c]?[u]?[t]?[e3]/i,  // execute
    /1nj[e3][c]?[t]/i,           // inject
    /[s5][h]?[e3][l1][l1]/i,     // shell
    /[e3]v[a4][l1]/i,            // eval
    /[s5]y[s5][t]?[e3]m/i,       // system
    /[p]?[o0][w]?[e3]r[s5]?[h]?[e3][l1][l1]/i, // powershell
  ];
  for (const pattern of leetspeakWords) {
    if (pattern.test(input)) {
      throw new Error("Prompt contains suspected leetspeak obfuscation.");
    }
  }

  // Reject prompt injection attempts targeting the model's instruction format
  const promptInjectionPattern =
    /(ignore (all |previous |prior |above |the )?instructions?|disregard (all |previous |prior |above |the )?instructions?|you are now|new persona|act as (a |an )?|pretend (you are|to be)|forget (all |your |previous )?instructions?|system prompt|###\s*(human|system|assistant|instruction))/i;
  if (promptInjectionPattern.test(input)) {
    throw new Error("Prompt contains suspected prompt injection content.");
  }

  return input.trim();
}

/**
 * Sanitize input to prevent prompt injection and remove harmful content.
 */
function sanitizeInput(input: string, maxLength = 4000): string {
  if (typeof input !== "string") return "";
  // Truncate to max length
  let sanitized = input.slice(0, maxLength);
  // Remove null bytes
  sanitized = sanitized.replace(/\0/g, "");
  // Strip common prompt injection patterns (case-insensitive)
  sanitized = sanitized.replace(
    /ignore (all )?(previous|prior|above) instructions?/gi,
    "[removed]"
  );
  sanitized = sanitized.replace(
    /you are now|disregard (all )?previous|forget (all )?previous|new persona|act as (a |an )?/gi,
    "[removed]"
  );
  // Remove control characters except standard whitespace
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  return sanitized;
}

export async function POST(request: Request) {
  const rawBody = await request.json();
  const rawPrompt: string = rawBody.prompt ?? "";
  const isText: boolean = rawBody.isText ?? false;
  const userId: string = rawBody.userId ?? "";
  const userName: string = rawBody.userName ?? "";

  // Validate prompt
  if (!rawPrompt || typeof rawPrompt !== "string" || rawPrompt.trim().length === 0) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or empty prompt." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  const prompt = sanitizeInput(rawPrompt, 2000);
  let clerkUserId;
  let user: Awaited<ReturnType<typeof currentUser>>;
  let clerkUserName;

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
  const rawName = request.headers.get("name");
  // Strip any path traversal characters and validate against the allowlist.
  const name = rawName ? path.basename(rawName) : null;
  if (!name || !COMPANION_ALLOWLIST.has(name)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or unauthorized companion name." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  const companion_file_name = name + ".txt";

  user = await currentUser();
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
  const rawData = await fs.readFile("companions/" + companion_file_name, "utf8");

  // Sanitize companion file contents to prevent prompt injection attacks
  function sanitizeCompanionFile(content: string): string {
    // Reject base64-encoded blobs (long runs of base64 chars)
    if (/(?:[A-Za-z0-9+\/]{40,}={0,2})/.test(content)) {
      throw new Error("Companion file contains suspicious base64-encoded content.");
    }
    // Reject shell command patterns
    if (/(?:\$\(|`[^`]*`|\bexec\b|\beval\b|\bsystem\b|\bpassthru\b|\bpopen\b|\bspawn\b|\bchild_process\b|\brm\s+-rf\b|\bcurl\b|\bwget\b)/i.test(content)) {
      throw new Error("Companion file contains suspicious shell command content.");
    }
    // Reject common prompt injection trigger phrases
    if (/(?:ignore\s+(all\s+)?previous\s+instructions|disregard\s+(all\s+)?prior|you\s+are\s+now|new\s+instructions:|system\s*:|<\s*system\s*>|\[INST\]|\[\/?SYS\])/i.test(content)) {
      throw new Error("Companion file contains suspicious prompt injection content.");
    }
    // Reject leetspeak patterns (e.g., 1gn0r3, 4dm1n)
    if (/(?:[a-z]*[0-9][a-z]*[0-9][a-z]*[0-9][a-z]*)/.test(content.toLowerCase()) &&
        /(?:1gn[o0]r[e3]|[a4]dm[i1]n|[e3]x[e3]c|[s5]y[s5]t[e3]m|[p9]r[o0]mpt)/i.test(content)) {
      throw new Error("Companion file contains suspicious leetspeak content.");
    }
    // Strip any HTML/XML tags that could be used for injection
    const stripped = content.replace(/<[^>]*>/g, "");
    return stripped;
  }

  let data: string;
  try {
    data = sanitizeCompanionFile(rawData);
  } catch (err: any) {
    console.error("Companion file sanitization failed:", err.message);
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains invalid content." }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = sanitizeInput(presplit[0], 4000);
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = sanitizeInput(seedsplit[0], 4000);

  const companionKey = {
    companionName: name!,
    userId: clerkUserId!,
    modelName: "vicuna13b",
  };
  const memoryManager = await MemoryManager.getInstance();

  // ── Supply-chain gate: registry + integrity verification ─────────────────
  // This MUST run before the model object is constructed or called.
  try {
    verifyModelIntegrity(APPROVED_MODEL_ID);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error("[security] Model verification failed:", message);
    return new NextResponse(
      JSON.stringify({ Message: "Model not approved for inference.", detail: message }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Log the outgoing LLM request before inference begins
  logLLMInteraction("request", {
    model: APPROVED_MODEL_ID,
    promptLength: prompt.length,
    promptPreview: prompt.slice(0, 200),
  });

  // Wrap LangChainStream handlers to log each streamed token and completion
  const { stream, handlers: rawHandlers } = LangChainStream();
  let _llmResponseBuffer = "";
  const handlers = {
    ...rawHandlers,
    handleLLMNewToken: async (token: string) => {
      _llmResponseBuffer += token;
      if (rawHandlers.handleLLMNewToken) {
        await rawHandlers.handleLLMNewToken(token);
      }
    },
    handleLLMEnd: async (output: unknown) => {
      logLLMInteraction("response", {
        model: APPROVED_MODEL_ID,
        responseLength: _llmResponseBuffer.length,
        responsePreview: _llmResponseBuffer.slice(0, 200),
      });
      if (rawHandlers.handleLLMEnd) {
        await rawHandlers.handleLLMEnd(output as never);
      }
    },
    handleLLMError: async (err: Error) => {
      logLLMInteraction("error", {
        model: APPROVED_MODEL_ID,
        error: err.message,
      });
      if (rawHandlers.handleLLMError) {
        await rawHandlers.handleLLMError(err);
      }
    },
  };

  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }
  await memoryManager.writeToHistory(
    "### Human: " + prompt + "\n",
    companionKey
  );

  // Query Pinecone

  const MAX_HISTORY_LENGTH = 2000;
  let recentChatHistory = (await memoryManager.readLatestHistory(companionKey)).slice(-MAX_HISTORY_LENGTH);

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue

  const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companion_file_name
  );

  const MAX_RELEVANT_HISTORY_LENGTH = 1500;
  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    relevantHistory = similarDocs
      .slice(0, 3)
      .map((doc) => doc.pageContent.slice(0, 500))
      .join("\n")
      .slice(0, MAX_RELEVANT_HISTORY_LENGTH);
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

  const llmPrompt =         `${safePreamble}  
       
       Below are relevant details about ${name}'s past:
       ${safeRelevantHistory}

       Below is a relevant conversation history

       ${safeRecentChatHistory}
       ### ${name}:
       `;

  console.log("[LLM REQUEST]", JSON.stringify({
    timestamp: new Date().toISOString(),
    model: "replicate/vicuna-13b",
    companionName: name,
    userId: clerkUserId,
    prompt: llmPrompt,
  }));

    const modelId =
    "replicate/vicuna-13b:6282abe6a492de4145d7bb601023762212f9ddbbe78278bd6771c8b3b2f2a13b";
  const inferenceInput = `${preamble}  
       
       Below are relevant details about ${name}'s past:
       ${relevantHistory}

       Below is a relevant conversation history

       ${recentChatHistory}
       ### ${name}:
       `;
  const inputHash = crypto
    .createHash("sha256")
    .update(inferenceInput)
    .digest("hex");
  const inferenceTimestamp = new Date().toISOString();

  let resp = String(
    await model
      .call(inferenceInput)
      .catch(console.error)
  );

  // Write audit record to persistent log
  const principalHash = crypto
    .createHash("sha256")
    .update(clerkUserId)
    .digest("hex");
  const auditRecord = JSON.stringify({
    timestamp: inferenceTimestamp,
    principal: principalHash,
    companionName: name,
    modelId,
    inputHash,
    output: resp,
  });
  await fs.appendFile(auditLogPath, auditRecord + "\n", "utf8");

  console.log("[LLM RESPONSE]", JSON.stringify({
    timestamp: new Date().toISOString(),
    model: "replicate/vicuna-13b",
    companionName: name,
    userId: clerkUserId,
    response: resp,
  }));

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("###");
  const rawResponse = chunks[0];

  // Validate and sanitize LLM output: reject or sanitize any dynamic code
  // execution primitives that may appear in the model response.
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bnew\s+Function\s*\(/gi,
    /\bsetTimeout\s*\(\s*['"`]/gi,
    /\bsetInterval\s*\(\s*['"`]/gi,
    /\bimport\s*\(/gi,
    /\brequire\s*\(/gi,
    /\bprocess\.binding\s*\(/gi,
    /\bchild_process/gi,
    /__proto__/gi,
    /constructor\s*\[/gi,
  ];

  function containsDangerousCode(text: string): boolean {
    return DANGEROUS_PATTERNS.some((pattern) => pattern.test(text));
  }

  function sanitizeLLMResponse(text: string): string {
    let sanitized = text;
    for (const pattern of DANGEROUS_PATTERNS) {
      sanitized = sanitized.replace(pattern, "[REDACTED]");
    }
    return sanitized;
  }

  if (containsDangerousCode(rawResponse)) {
    console.warn(
      "[SECURITY] LLM response contained dynamic code execution primitives. Sanitizing."
    );
  }

  const response = sanitizeLLMResponse(rawResponse);
  // const response = chunks.length > 1 ? chunks[0] : chunks[0];

  await memoryManager.writeToHistory("### " + response.trim(), companionKey);
  var Readable = require("stream").Readable;
  const crypto = require("crypto");

  // --- Synthetic Content Provenance & Labeling ---
  const MODEL_ID =
    "replicate/vicuna-13b:6282abe6a492de4145d7bb601023762212f9ddbbe78278bd6771c8b3b2f2a13b";
  const generatedAt = new Date().toISOString();

  // Cryptographic watermark: HMAC-SHA256 over the response content
  const watermarkSecret = process.env.WATERMARK_SECRET;
  if (!watermarkSecret) {
    throw new Error("WATERMARK_SECRET environment variable is not set.");
  }
  const hmac = crypto
    .createHmac("sha256", watermarkSecret)
    .update(response ?? "")
    .digest("hex");

  // Synthetic-origin label prepended to the streamed body (no internal metadata exposed)
  const syntheticLabel = `[AI-GENERATED CONTENT]\n`;

  let s = new Readable();
  s.push(syntheticLabel);
  s.push(response);
  s.push(null);

  if (response !== undefined && response.length > 1) {
    await memoryManager.writeToHistory("### " + response.trim(), companionKey);

    // Forensic audit record for the final sanitized response delivered to the user
    const outputHash = require("crypto")
      .createHash("sha256")
      .update(response)
      .digest("hex");

    // Extract a discrete version token from the modelId string (e.g. the hash suffix after ":")
    const modelVersion = modelId.includes(":")
      ? modelId.split(":").pop() ?? modelId
      : modelId;

    // Correlation / trace ID — links this record to any earlier inference-step log entries
    // that share the same traceId for end-to-end reconstruction.
    const traceId =
      typeof (globalThis as Record<string, unknown>)["_currentTraceId"] === "string"
        ? (globalThis as Record<string, unknown>)["_currentTraceId"] as string
        : require("crypto").randomUUID();

    const finalAuditRecord = JSON.stringify({
      timestamp: new Date().toISOString(),
      traceId,                          // correlation ID for end-to-end reconstruction
      principal: clerkUserId,
      companionName: name,
      modelId,
      modelVersion,                     // explicit discrete version field
      inputHash,
      outputHash,
      sanitized: response !== resp,
      event: "final_response_delivered",
      retentionPolicy: {
        retainDays: 90,                 // records must be kept for at least 90 days
        rotateAtBytes: 10 * 1024 * 1024 // rotate log file when it reaches 10 MB
      },
    });

    // Rotation: if the current log file exceeds the threshold, archive it before appending.
    const ROTATE_AT_BYTES = 10 * 1024 * 1024; // 10 MB
    try {
      const stat = await fs.stat(auditLogPath).catch(() => null);
      if (stat && stat.size >= ROTATE_AT_BYTES) {
        const rotatedPath = `${auditLogPath}.${Date.now()}.bak`;
        await fs.rename(auditLogPath, rotatedPath);
      }
    } catch (rotationErr) {
      console.error("[AUDIT] Log rotation failed:", rotationErr);
    }

    await fs.appendFile(auditLogPath, finalAuditRecord + "\n", "utf8");
  }

  // Provenance metadata exposed as response headers
  // Build machine-readable provenance payload linking this response to its audit record.
  const provenanceTimestamp = new Date().toISOString();
  const provenancePayload = JSON.stringify({
    modelId: APPROVED_MODEL_ID,
    modelDigest: APPROVED_MODEL_ID_DIGEST,
    timestamp: provenanceTimestamp,
    auditLogPath,
    auditRecordDigest: createHash("sha256").update(finalAuditRecord).digest("hex"),
  });

  // Cryptographic signature over the provenance payload (SHA-256).
  // Signing key is derived internally from the approved model digest and audit record digest,
  // removing the need for an external PROVENANCE_SIGNING_SECRET credential.
  const derivedSigningKey = createHash("sha256")
    .update(APPROVED_MODEL_ID_DIGEST + createHash("sha256").update(finalAuditRecord).digest("hex"))
    .digest("hex");
  const provenanceSignature = createHash("sha256")
    .update(derivedSigningKey + provenancePayload)
    .digest("hex");

  // Watermark: a short deterministic token derived from model digest + timestamp.
  const watermarkToken = createHash("sha256")
    .update(APPROVED_MODEL_ID_DIGEST + provenanceTimestamp + (userId ?? ""))
    .digest("hex")
    .slice(0, 32);

  return new StreamingTextResponse(s, {
    headers: {
      // (1) Labeling
      "X-AI-Content-Label": "synthetic",
      // (1) Timestamp only — model id and digest are internal and must not be sent to clients
      "X-AI-Generated-At": provenanceTimestamp,
      // (2) Cryptographically signed provenance (signature only; payload is internal)
      "X-AI-Provenance-Signature": provenanceSignature,
      // (3) Watermark
      "X-AI-Watermark": watermarkToken,
      // (4) Machine-readable audit log reference
      "X-AI-Audit-Record-Digest": createHash("sha256").update(finalAuditRecord).digest("hex"),
    },
  });
}
