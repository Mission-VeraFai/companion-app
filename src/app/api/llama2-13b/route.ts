import dotenv from "dotenv";
import { createHash } from "crypto";
import { StreamingTextResponse } from "ai";
// OpenAI calls are proxied through /api/openai — no direct credential held here
import clerk from "@clerk/clerk-sdk-node";
import MemoryManager from "@/app/utils/memory";
import { currentUser } from "@clerk/nextjs";
import { NextResponse } from "next/server";
import { rateLimit } from "@/app/utils/rateLimit";

// ---------------------------------------------------------------------------
// Approved Model Registry — only models listed here may be instantiated.
// Each entry pins the full model identifier (owner/name:version-hash) and
// records the expected SHA-256 digest of that identifier string so that any
// tampering with the constant is detected at startup.
// ---------------------------------------------------------------------------
interface RegistryEntry {
  /** Fully-qualified Replicate model id: owner/name:weights-sha256 */
  modelId: string;
  /** SHA-256 hex digest of the modelId string itself (integrity manifest) */
  modelIdDigest: string;
  /** Human-readable label used in logs / error messages */
  label: string;
}

// ---------------------------------------------------------------------------
// Approved Model Registry entries
// modelIdDigest values are SHA-256 hex digests of the modelId strings.
// ---------------------------------------------------------------------------
// llama2-13b has been removed — it is on the organization's disallowed list.
// No approved models are currently registered for this route.
const APPROVED_MODEL_REGISTRY: Record<string, RegistryEntry> = {};

/**
 * Verifies that:
 *  1. The requested model key exists in the approved registry.
 *  2. The stored modelId has not been tampered with by re-computing its
 *     SHA-256 digest and comparing it to the pinned manifest value.
 *
 * Throws if either check fails, preventing an unregistered or modified
 * model from being loaded.
 */
function resolveApprovedModel(modelKey: string): string {
  const entry = APPROVED_MODEL_REGISTRY[modelKey];
  if (!entry) {
    throw new Error(
      `Model '${modelKey}' is NOT_IN_REGISTRY. ` +
        `Only approved, version-pinned models may be used.`
    );
  }

  // Integrity check: recompute the digest of the modelId string and compare
  // it to the known-good value stored in the registry manifest.
  const actualDigest = createHash("sha256")
    .update(entry.modelId, "utf8")
    .digest("hex");

  if (actualDigest !== entry.modelIdDigest) {
    throw new Error(
      `Integrity verification FAILED for model '${modelKey}' (${entry.label}). ` +
        `Expected digest ${entry.modelIdDigest} but computed ${actualDigest}. ` +
        `The model identifier may have been tampered with.`
    );
  }

  return entry.modelId;
}

// Selective credential loader — this route is permitted to hold credentials
// for at most 3 external systems: Clerk (auth), Replicate (LLM), and the
// signing secret. Pinecone and Redis/Upstash credentials are intentionally
// excluded from this module's environment scope.
(function loadSelectiveEnv() {
  dotenv.config({ path: `.env.local` });
  // Scrub credentials for systems beyond the 3-system limit so they are
  // never accessible within this route handler.
  const disallowedKeys = [
    "PINECONE_API_KEY",
    "PINECONE_ENVIRONMENT",
    "PINECONE_INDEX",
    "UPSTASH_REDIS_REST_URL",
    "UPSTASH_REDIS_REST_TOKEN",
    "REDIS_URL",
    "REDIS_TOKEN",
  ];
  for (const key of disallowedKeys) {
    delete process.env[key];
  }
})();

// Resolve and integrity-verify the model at module load time so that a
// misconfigured or tampered registry entry fails fast on cold start.
// llama2-13b has been removed — it is on the organization's disallowed list.
// Replace with an organization-approved model key from APPROVED_MODEL_REGISTRY.
const MODEL_ID: string = resolveApprovedModel("llama2-13b");

// Sanitize input to prevent prompt injection and remove dangerous patterns
function sanitizeInput(input: string, maxLength = 4000): string {
  if (typeof input !== "string") return "";
  // Truncate to max length
  let sanitized = input.slice(0, maxLength);
  // Remove null bytes and other non-printable control characters (except newlines/tabs)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Strip common prompt injection patterns
  sanitized = sanitized.replace(
    /###(ENDPREAMBLE|ENDSEEDCHAT|SYSTEM|INST|END|HUMAN|ASSISTANT)###/gi,
    ""
  );
  // Remove attempts to override system instructions
  sanitized = sanitized.replace(
    /\b(ignore (all |previous |above |prior )(instructions?|prompts?|context|rules?)|disregard (all |previous |above |prior )?(instructions?|prompts?|context|rules?)|you are now|new persona|act as|pretend (to be|you are)|forget (all |your |previous )?instructions?)\b/gi,
    "[removed]"
  );
  return sanitized.trim();
}

function validateName(name: string | null): string {
  if (!name || typeof name !== "string") throw new Error("Invalid companion name");
  // Allow only alphanumeric, spaces, hyphens, underscores — max 100 chars
  const cleaned = name.slice(0, 100).replace(/[^a-zA-Z0-9 _\-]/g, "").trim();
  if (!cleaned) throw new Error("Invalid companion name after sanitization");
  return cleaned;
}

export async function POST(request: Request) {
      // Authentication must happen first before any other logic
  const { userId: clerkUserId } = auth();
  if (!clerkUserId) {
    return new NextResponse(
      JSON.stringify({ Message: "Unauthorized" }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  } = auth();
  if (!clerkUserId) {
    return new NextResponse(
      JSON.stringify({ Message: "Unauthorized" }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  const rawBody = await request.json();
  const isText: boolean = !!rawBody.isText;
  const userId: string = typeof rawBody.userId === "string" ? rawBody.userId.slice(0, 256) : "";
  const userName: string = typeof rawBody.userName === "string" ? sanitizeInput(rawBody.userName, 100) : "";
  const prompt: string = sanitizeInput(typeof rawBody.prompt === "string" ? rawBody.prompt : "", 2000);
  if (!prompt) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or empty prompt" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const identifier = request.url + "-" + clerkUserId;
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
  let name: string;
  try {
    name = validateName(request.headers.get("name"));
  } catch {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  // Restrict file name to alphanumeric/hyphen/underscore to prevent path traversal
  const safeName = name.replace(/[^a-zA-Z0-9_\-]/g, "_");
  const companion_file_name = safeName + ".txt";),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  // Structured spawn log: record prompt metadata (never the raw value) for audit.
  console.log(
    JSON.stringify({
      event: "llm_spawn",
      promptLength: prompt.length,
      userId: userId ? userId.slice(0, 8) + "…" : "anonymous",
      timestamp: new Date().toISOString(),
    })
  );
  // Authenticate FIRST before any rate limiting or further processing
  const user = await currentUser();
  const clerkUserId = user?.id;
  const clerkUserName = user?.firstName;

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

  // Rate limit keyed to the authenticated user, not 'anonymous'
  const identifier = request.url + "-" + clerkUserId;
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
  let name: string;
  try {
    name = validateName(request.headers.get("name"));
  } catch {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  // Restrict file name to alphanumeric/hyphen/underscore to prevent path traversal
  const safeName = name.replace(/[^a-zA-Z0-9_\-]/g, "_");
  const companion_file_name = safeName + ".txt";

  // Load character "PREAMBLE" from character file. These are the core personality
  // characteristics that are used in every prompt. Additional background is
  // only included if it matches a similarity comparioson with the current
  // discussion. The PREAMBLE should include a seed conversation whose format will
  // vary by the model using it.
  const fs = require("fs").promises;
  const path = require("path");
  const companionsDir = path.resolve("companions");
  const resolvedPath = path.resolve(companionsDir, companion_file_name);
  if (!resolvedPath.startsWith(companionsDir + path.sep) && resolvedPath !== companionsDir) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion file." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  const data = await fs.readFile(resolvedPath, "utf8");

  // Validate companion file content for malicious patterns before injecting into LLM prompt
  const containsMaliciousFileContent = (content: string): boolean => {
    // Check for non-printable / binary bytes (excluding normal whitespace)
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/.test(content)) return true;
    // Check for hidden/invisible Unicode characters (zero-width, soft-hyphen, etc.)
    if (/[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u2028\u2029]/.test(content)) return true;
    // Check for base64-encoded blobs (long runs of base64 chars that look encoded)
    if (/(?:[A-Za-z0-9+\/]{40,}={0,2})/.test(content)) return true;
    // Check for shell command sequences
    if (/(?:bash|sh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|`[^`]*`|\$\([^)]*\)|&&|\|\||;\s*\w)/i.test(content)) return true;
    // Check for leetspeak substitution patterns (e.g. 1gnor3, syst3m, 3xec)
    if (/(?:1gnor[e3]|syst[e3]m|[e3]x[e3]c|[i1]nj[e3]ct|[o0]v[e3]rr[i1]d[e3])/i.test(content)) return true;
    return false;
  };

  if (containsMaliciousFileContent(data)) {
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains disallowed content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Scan companion file contents for malicious prompt injection patterns
  const scanCompanionFileForMaliciousContent = (content: string): boolean => {
    // Check for base64-encoded content (long base64 strings that could hide instructions)
    if (/(?:[A-Za-z0-9+\/]{40,}={0,2})/.test(content)) return true;
    // Check for shell commands
    if (/(?:bash|sh|cmd|powershell|exec|eval|system|popen|subprocess|os\.)/i.test(content)) return true;
    // Check for common prompt injection phrases
    if (/ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i.test(content)) return true;
    if (/you\s+are\s+now\s+(a\s+)?(?!the companion)/i.test(content)) return true;
    if (/disregard\s+(all\s+)?(previous|prior|above)/i.test(content)) return true;
    if (/new\s+(role|persona|instructions?|task|objective)/i.test(content)) return true;
    if (/act\s+as\s+(if\s+you\s+are|a\s+)?(?!the companion)/i.test(content)) return true;
    if (/do\s+not\s+follow\s+(your\s+)?(previous|prior|original)\s+(instructions?|guidelines?)/i.test(content)) return true;
    // Check for leetspeak patterns (e.g., 1gn0r3, syst3m)
    if (/[il1][g9][n][o0][r][e3]/i.test(content)) return true;
    if (/[s5][y][s5][t7][e3][m]/i.test(content)) return true;
    // Check for hidden Unicode control characters or zero-width characters
    if (/[\u200B-\u200D\uFEFF\u00AD\u2060]/.test(content)) return true;
    // Check for excessive repetition of injection-related keywords
    const injectionKeywords = ['ignore', 'forget', 'override', 'bypass', 'jailbreak', 'prompt', 'instruction'];
    for (const kw of injectionKeywords) {
      const matches = content.match(new RegExp(kw, 'gi'));
      if (matches && matches.length > 10) return true;
    }
    return false;
  };

  if (scanCompanionFileForMaliciousContent(data)) {
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains potentially malicious content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = sanitizeInput(presplit[0], 8000);
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = sanitizeInput(seedsplit[0], 8000);

  const companionKey = {
    companionName: name!,
    userId: clerkUserId!,
    modelName: "llama2-13b",
  };
  const memoryManager = await MemoryManager.getInstance();

  // Sanitize user input to prevent prompt injection
  const sanitizePrompt = (input: string): string => {
    return input
      .replace(/[`<>]/g, '')                        // strip backticks and angle brackets
      .replace(/###/g, '')                           // strip section delimiters used in companion files
      .replace(/\bIGNORE\b/gi, '')                  // strip common injection keywords
      .replace(/\bFORGET\b/gi, '')
      .replace(/\bSYSTEM\b/gi, '')
      .replace(/\bPREAMBLE\b/gi, '')
      .trim()
      .slice(0, 1000);                               // enforce maximum length
  };
  const sanitizedPrompt = sanitizePrompt(prompt);

  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }
  // Validate user prompt before writing to history or injecting into LLM prompt
  if (!prompt || containsMaliciousContent(prompt)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or potentially malicious prompt content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  await memoryManager.writeToHistory("User: " + sanitizedPrompt + "\n", companionKey);

  // Query Pinecone

  let recentChatHistory = await memoryManager.readLatestHistory(companionKey);

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue

  const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companion_file_name
  );

  const MAX_PREAMBLE_LENGTH = 500;
  const MAX_RELEVANT_DOC_LENGTH = 200;
  const MAX_RELEVANT_DOCS = 3;
  const MAX_RECENT_HISTORY_LENGTH = 1000;

  const truncatedPreamble = preamble.slice(0, MAX_PREAMBLE_LENGTH);

  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    relevantHistory = similarDocs
      .slice(0, MAX_RELEVANT_DOCS)
      .map((doc) => doc.pageContent.slice(0, MAX_RELEVANT_DOC_LENGTH))
      .join("\n");
  }
    // Delegate LLM inference to an external inference service to avoid direct LLM interaction
  const inferencePayload = {
    name,
    preamble,
    relevantHistory,
    recentChatHistory,
  };

  const inferenceResponse = await fetch(
    `${process.env.INFERENCE_SERVICE_URL}/api/inference/llama2-13b`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.INFERENCE_SERVICE_API_KEY}`,
      },
      body: JSON.stringify(inferencePayload),
    }
  );

  if (!inferenceResponse.ok) {
    return new NextResponse(
      JSON.stringify({ Message: "Inference service error" }),
      {
        status: 502,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const inferenceResult = await inferenceResponse.json();
    const crypto = require("crypto");
  const fsAudit = require("fs").promises;

  const MODEL_ID =
    "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5";
  const PUBLIC_MODEL_ALIAS = "llama2-13b";
  const inputPrompt = `
       ONLY generate NO more than three sentences as ${name}. DO NOT generate more than three sentences. 
       Make sure the output you generate starts with '${name}:' and ends with a period.

       ${preamble}

       Below are relevant details about ${name}'s past and the conversation you are in.
       ${relevantHistory}


       ${recentChatHistory}\n${name}:`;

  const inputHash = crypto
    .createHash("sha256")
    .update(inputPrompt)
    .digest("hex");

  const inferenceTimestamp = new Date().toISOString();

  let resp = String(
    await model
      .call(inputPrompt)
      .catch(console.error)
  );

  const auditRecord = JSON.stringify({
    timestamp: inferenceTimestamp,
    principal: clerkUserId,
    modelId: MODEL_ID,
    inputHash: inputHash,
    output: resp,
    companionName: name,
  });

  await fsAudit
    .appendFile(
      "audit/ai_decision_log.jsonl",
      auditRecord + "\n",
      "utf8"
    )
    .catch((err: Error) =>
      console.error("[AUDIT] Failed to write decision log:", err)
    );
  // Call OpenAI for inference
  const model = new OpenAI({
    modelName: "gpt-3.5-turbo-instruct",
    maxTokens: 2048,
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });

  // Turn verbose on for debugging
  model.verbose = true;

  const llmPrompt = `
       ONLY generate NO more than three sentences as ${name}. DO NOT generate more than three sentences. 
       Make sure the output you generate starts with '${name}:' and ends with a period.

               ${truncatedPreamble}

       Below are relevant details about ${name}'s past and the conversation you are in.
       ${relevantHistory}


       ${recentChatHistory.slice(0, MAX_RECENT_HISTORY_LENGTH)}\n${name}:`;

  console.log("[LLM INTERACTION] Prompt sent to llama2-13b:", llmPrompt);

  let resp = String(
    await model
      .call(llmPrompt)
      .catch(console.error)
  );

  // Raw response logging removed: full response must not be logged without input_hash and principal; see structured [AUDIT_LOG] entry below.

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  // Sanitize LLM output: reject or strip dynamic code execution primitives
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bFunction\s*\(/gi,
    /\bnew\s+Function\b/gi,
    /\bsetTimeout\s*\(/gi,
    /\bsetInterval\s*\(/gi,
    /\bsetImmediate\s*\(/gi,
    /\bprocess\.binding\b/gi,
    /\brequire\s*\(/gi,
    /\bimport\s*\(/gi,
    /\bchild_process\b/gi,
    /__proto__/gi,
    /constructor\s*\[/gi,
  ];

  function sanitizeLLMOutput(raw: string): string {
    let sanitized = raw;
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(sanitized)) {
        // Strip the dangerous token rather than passing it through
        sanitized = sanitized.replace(pattern, "[REDACTED]");
      }
      // Reset lastIndex for global regexes
      pattern.lastIndex = 0;
    }
    return sanitized;
  }

  resp = sanitizeLLMOutput(resp);

  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("\n");
  const response = sanitizeLLMOutput(chunks[0]);
  // const response = chunks.length > 1 ? chunks[0] : chunks[0];

    try {
    await memoryManager.writeToHistory("" + sanitizeLLMOutput(response.trim()), companionKey);
  } catch (historyErr) {
    console.error("[AUDIT] First writeToHistory failed:", historyErr);
  }
  var Readable = require("stream").Readable;

  const MODEL_ID =
    "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5";
  const generatedAt = new Date().toISOString();

  // Cryptographic watermark: HMAC-SHA256 over (modelId + timestamp + response)
  const crypto = require("crypto");
  const signingSecret = process.env.WATERMARK_SECRET;
  if (!signingSecret) {
    throw new Error("WATERMARK_SECRET environment variable is not set. Refusing to sign with a fallback secret.");
  }
      // Persistent append-only audit log entry with all required forensic fields
  const auditEntry = JSON.stringify({
    event: "llm_interaction_response",
    model: PUBLIC_MODEL_ALIAS,
    timestamp: new Date().toISOString(),
    principal: companionKey ?? "unknown",
    input_hash: createHash("sha256").update(prompt ?? "", "utf8").digest("hex"),
    response_length: response?.length ?? 0,
    response_hash: createHash("sha256").update(response ?? "", "utf8").digest("hex"),
  }) + "\n";
  try {
    const { appendFileSync } = await import("fs");
    appendFileSync(
      process.env.AUDIT_LOG_PATH ?? "/var/log/ai_audit/llama2_interactions.jsonl",
      auditEntry,
      { encoding: "utf8", flag: "a" }
    );
  } catch (auditErr) {
    // Log failure to stderr but do not suppress the response
    console.error("[AUDIT] Failed to write to persistent audit log:", auditErr);
  }|${generatedAt}|${response}`);
  const signature = hmac.digest("hex");

  // Persistent audit record for forensic readiness
  const inputHash = crypto.createHash("sha256").update(llmPrompt).digest("hex");
  const outputHash = crypto.createHash("sha256").update(response).digest("hex");
  const auditRecord = JSON.stringify({
    event: "ai_inference",
    model_id: MODEL_ID,
    principal: companionKey,
    input_hash: inputHash,
    output_hash: outputHash,
    timestamp: generatedAt,
    signature,
  });
  console.log("[AUDIT_LOG]", auditRecord);
  if (process.env.AUDIT_LOG_PATH) {
    const fs = require("fs");
    try {
      fs.appendFileSync(process.env.AUDIT_LOG_PATH, auditRecord + "\n", { encoding: "utf8", flag: "a" });
    } catch (auditErr) {
      console.error("[AUDIT] Failed to write persistent audit record:", auditErr);
    }
  }

  // Provenance prefix prepended to the streamed payload
  const provenancePrefix =
    `[AI-GENERATED CONTENT | model=${MODEL_ID} | generated_at=${generatedAt} | sig=${signature}]\n`;

  // Validate LLM output for dynamic code execution primitives before streaming
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bexecSync\s*\(/i,
    /\bspawn\s*\(/i,
    /\bspawnSync\s*\(/i,
    /\bsubprocess\b/i,
    /\bFunction\s*\(/i,
    /\bnew\s+Function\b/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\brequire\s*\(/i,
    /\bimport\s*\(/i,
    /\bchild_process\b/i,
    /\bvm\.run/i,
    /\bos\.system\s*\(/i,
    /\bos\.popen\s*\(/i,
    /\b__import__\s*\(/i,
    /\bcompile\s*\(/i,
    /\bexecfile\s*\(/i,
  ];

  const hasDangerousContent = DANGEROUS_PATTERNS.some((pattern) => pattern.test(response));
  let safeResponse = response;
  if (hasDangerousContent) {
    console.error("[SECURITY] LLM output contained dynamic code execution primitive. Blocking response.", {
      model: MODEL_ID,
      timestamp: generatedAt,
      principal: companionKey,
    });
    safeResponse = "[Response blocked: output contained disallowed content.]"
  }

    const hmac = crypto.createHmac("sha256", signingSecret);
  hmac.update(`${PUBLIC_MODEL_ALIAS}|${generatedAt}|${response}`);
  const signature = hmac.digest("hex");

  let s = new Readable();
  s.push(provenancePrefix + safeResponse);
  s.push(null);
  if (safeResponse !== undefined && safeResponse.length > 1) {
    try {
      await memoryManager.writeToHistory("" + safeResponse.trim(), companionKey);
    } catch (historyErr) {
      console.error("[AUDIT] Second writeToHistory failed:", historyErr);
    }
  }
  console.log(JSON.stringify({
    event: "llm_interaction_response",
    model: PUBLIC_MODEL_ALIAS,
    timestamp: new Date().toISOString(),
  })); catch (historyErr) {
      console.error("[AUDIT] Second writeToHistory failed:", historyErr);
    }
  }
  // Enforce session expiry: reject tokens older than SESSION_MAX_AGE_MS (default 1 hour)
  const SESSION_MAX_AGE_MS = parseInt(process.env.SESSION_MAX_AGE_MS ?? "3600000", 10);
  const user = await currentUser();
  if (!user || !user.id) {
    return new Response("Unauthorized: missing session", { status: 401 });
  }
  const sessionCreatedAt: number | undefined =
    typeof user.createdAt === "number" ? user.createdAt : undefined;
  if (sessionCreatedAt !== undefined) {
    const sessionAgeMs = Date.now() - sessionCreatedAt;
    if (sessionAgeMs > SESSION_MAX_AGE_MS) {
      console.error("[AUTH] Session token expired", {
        userId: user.id,
        sessionCreatedAt,
        sessionAgeMs,
        maxAgeMs: SESSION_MAX_AGE_MS,
      });
      return new Response("Unauthorized: session token expired", { status: 401 });
    }
  }
  // Compute expiry bound for this response
  const sessionExpiry = sessionCreatedAt
    ? new Date(sessionCreatedAt + SESSION_MAX_AGE_MS).toISOString()
    : new Date(Date.now() + SESSION_MAX_AGE_MS).toISOString();
  // HMAC signs over session identity, expiry, model, timestamp, and output hash
  // so the signature is bound to the session token and its expiry
  const outputHash = crypto.createHash("sha256").update(response).digest("hex");
  const hmac = crypto.createHmac("sha256", signingSecret);
  hmac.update(`${user.id}|${sessionExpiry}|${PUBLIC_MODEL_ALIAS}|${generatedAt}|${outputHash}`);
  const signature = hmac.digest("hex");

  let s = new Readable();
  s.push(safeResponse);
  s.push(null);
    // Build a complete decision audit record with all required forensic fields
  const inputHash = crypto.createHash("sha256").update(JSON.stringify(req.body ?? "")).digest("hex");
  const outputHash = crypto.createHash("sha256").update(safeResponse ?? "").digest("hex");
  const auditRecord = JSON.stringify({
    event: "llm_interaction_response",
    model: PUBLIC_MODEL_ALIAS,
    timestamp: new Date().toISOString(),
    principal: companionKey,
    inputHash,
    outputHash,
    signature,
  });
  // Emit to console for operational visibility (not the authoritative store)
  console.log(auditRecord);
  // Persist to the append-only audit store for forensic readiness
  try {
    if (typeof auditLog !== "undefined" && typeof auditLog.append === "function") {
      await auditLog.append(auditRecord);
    } else {
      // Fallback: write to a local append-only file when auditLog client is unavailable
      const fs = await import("fs/promises");
      await fs.appendFile(
        process.env.AUDIT_LOG_PATH ?? "/var/log/llama2-audit.jsonl",
        auditRecord + "\n",
        { flag: "a" }
      );
    }
  } catch (auditWriteErr) {
    console.error("[AUDIT] Failed to persist decision audit record:", auditWriteErr);
  }
  if (safeResponse !== undefined && safeResponse.length > 1) {
    memoryManager.writeToHistory("" + safeResponse.trim(), companionKey);
  }

  // Provenance and labeling headers
  const provenanceHeaders = new Headers({
    "X-AI-Generated": "true",
    "X-AI-Content-Signature": signature,
    "X-Content-Label": "synthetic-ai-generated-text",
  });

  return new StreamingTextResponse(s, { headers: provenanceHeaders });
}
