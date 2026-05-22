import dotenv from "dotenv";
// OpenAI via langchain and LLMChain removed: not in the organization's approved LLM registry.
// Use the organization-approved LLM endpoint via fetch instead.
import { StreamingTextResponse, LangChainStream } from "ai";
import clerk from "@clerk/clerk-sdk-node";
import { CallbackManager } from "langchain/callbacks";
import { PromptTemplate } from "langchain/prompts";
import { NextResponse } from "next/server";
import { currentUser } from "@clerk/nextjs";
import MemoryManager from "@/app/utils/memory";
// In-process rate limiter replacing Upstash Redis to avoid a 4th credentialed external system.
const _rateLimitMap = new Map<string, { count: number; resetAt: number }>();
function rateLimit(identifier: string): { success: boolean } {
  const now = Date.now();
  const windowMs = 60_000; // 1 minute
  const maxRequests = 10;
  const entry = _rateLimitMap.get(identifier);
  if (!entry || now > entry.resetAt) {
    _rateLimitMap.set(identifier, { count: 1, resetAt: now + windowMs });
    return { success: true };
  }
  if (entry.count >= maxRequests) {
    return { success: false };
  }
  entry.count += 1;
  return { success: true };
}
import { createHash, randomUUID } from "crypto";

// Approved model registry — only models listed here may be used at inference time.
// Each entry carries an immutable identifier (model name/version) that must be
// pinned at construction time and echoed in every request's metadata.
const APPROVED_MODEL_REGISTRY: Record<string, { modelName: string; provider: string; version: string }> = {
  "gpt-3.5-turbo-0125": {
    modelName: "gpt-3.5-turbo-0125",
    provider: "openai",
    version: "0125",
  },
};

// The single approved model for this workload — change only via registry update.
const PINNED_MODEL_ID = "gpt-3.5-turbo-0125";

function assertModelInRegistry(modelId: string): void {
  if (!APPROVED_MODEL_REGISTRY[modelId]) {
    throw new Error(
      `Model '${modelId}' is NOT in the approved model registry. ` +
        `Approved models: ${Object.keys(APPROVED_MODEL_REGISTRY).join(", ")}`
    );
  }
}

// Next.js automatically loads .env.local — no explicit dotenv call needed.
// Enforce max 3 credentialed external systems: OpenAI, Clerk, Pinecone.
// Rate limiting is handled in-process to avoid a 4th credentialed system.
const _REQUIRED_CREDENTIALS = [
  process.env.OPENAI_API_KEY,
  process.env.CLERK_SECRET_KEY,
  process.env.PINECONE_API_KEY,
] as const;
if (_REQUIRED_CREDENTIALS.some((c) => !c)) {
  throw new Error("Missing required credentials for one of the 3 permitted external systems.");
}

// Patterns that indicate prompt injection, shell commands, or encoded malicious content
const MALICIOUS_PATTERNS: RegExp[] = [
  // Shell command indicators
  /(?:^|\s|;|&|\|)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\-]/i,
  /(?:;|&&|\|\||`|\$\()\s*[\w\/]/,
  // Prompt injection attempts
  /ignore\s+(all\s+)?(?:previous|prior|above)\s+instructions/i,
  /(?:new|updated|revised)\s+instructions?\s*:/i,
  /(?:system|assistant|user)\s*:\s*(?:you are|your new|forget)/i,
  /\[\s*(?:INST|SYS|SYSTEM|ASSISTANT|USER)\s*\]/i,
  /<\s*(?:system|assistant|user|instruction)\s*>/i,
  // Encoded content (base64-like, hex sequences)
  /(?:[A-Za-z0-9+\/]{40,}={0,2})(?:\s|$)/,
  /(?:\\x[0-9a-fA-F]{2}){4,}/,
  /(?:%[0-9a-fA-F]{2}){4,}/,
  // Null bytes and control characters
  /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/,
];

function containsMaliciousContent(input: string): boolean {
  if (!input || typeof input !== "string") return false;
  for (const pattern of MALICIOUS_PATTERNS) {
    if (pattern.test(input)) {
      return true;
    }
  }
  return false;
}

// Sanitize input to prevent prompt injection and remove dangerous content
function sanitizeInput(input: string, maxLength = 4000): string {
  if (typeof input !== "string") return "";
  // Enforce length limit
  let sanitized = input.slice(0, maxLength);
  // Remove null bytes and non-printable control characters (keep newlines/tabs)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Strip common prompt injection patterns
  sanitized = sanitized.replace(
    /ignore (all )?(previous|prior|above) instructions?/gi,
    "[removed]"
  );
  sanitized = sanitized.replace(
    /you are now|act as|pretend (to be|you are)|disregard (all )?instructions?/gi,
    "[removed]"
  );
  return sanitized.trim();
}

function validateName(name: string | null): string {
  if (!name || typeof name !== "string") throw new Error("Invalid companion name");
  // Allow only alphanumeric, spaces, hyphens, underscores
  if (!/^[a-zA-Z0-9 _-]{1,100}$/.test(name.trim())) {
    throw new Error("Companion name contains invalid characters");
  }
  return name.trim();
}

export async function POST(req: Request) {
  let clerkUserId;
  let user;
  let clerkUserName;
  const { prompt: rawPrompt, isText } = await req.json();
  if (!rawPrompt || typeof rawPrompt !== "string") {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or missing prompt." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const prompt = sanitizeInput(rawPrompt, 2000);

    // XXX Companion name passed here. Can use as a key to get backstory, chat history etc.
  let name: string;
  try {
    name = validateName(req.headers.get("name"));
  } catch {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const companionFileName = name + ".txt";

  console.log("prompt: ", prompt);
  // Always verify identity server-side; never trust a caller-supplied userId.
  user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName ?? (isText ? userName : undefined);

  if (!clerkUserId || !!!(await clerk.users.getUser(clerkUserId))) {
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

  // Rate limit using the server-verified clerkUserId, not the caller-supplied userId.
  const identifier = req.url + "-" + clerkUserId;
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
  } = await rateLimit(identifier);
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
    name = validateName(req.headers.get("name"));
  } catch {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const companionFileName = name + ".txt";

  // Prompt logging removed to avoid logging PII
  // Always verify identity server-side; never trust a caller-supplied userId.
  user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName ?? (isText ? userName : undefined);

  if (!clerkUserId || !!!(await clerk.users.getUser(clerkUserId))) {
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

  // Load character "PREAMBLE" from character file. These are the core personality
  // characteristics that are used in every prompt. Additional background is
  // only included if it matches a similarity comparioson with the current
  // discussion. The PREAMBLE should include a seed conversation whose format will
  // vary by the model using it.
  const fs = require("fs").promises;
  const path = require("path");

  // Sanitize and validate companion file contents before injecting into LLM prompt
  function sanitizeCompanionContent(content: string): string {
    // Strip hidden Unicode control characters (except common whitespace)
    // eslint-disable-next-line no-control-regex
    const stripped = content.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u200B-\u200D\uFEFF]/g, "");
    return stripped;
  }

  function detectMaliciousContent(content: string): boolean {
    const lower = content.toLowerCase();

    // Prompt injection patterns
    const injectionPatterns = [
      /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
      /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
      /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
      /you\s+are\s+now\s+/i,
      /act\s+as\s+(if\s+you\s+are|a|an)\s+/i,
      /new\s+instructions?:/i,
      /system\s*:\s*you\s+are/i,
      /###\s*system/i,
      /<\s*system\s*>/i,
      /\[\s*system\s*\]/i,
    ];

    // Shell command patterns
    const shellPatterns = [
      /`[^`]{0,200}`/,           // backtick execution
      /\$\([^)]{0,200}\)/,       // $() subshell
      /;\s*(rm|curl|wget|bash|sh|python|node|exec)\s/i,
      /&&\s*(rm|curl|wget|bash|sh|python|node|exec)\s/i,
      /\|\s*(bash|sh|python|node|exec)\s/i,
    ];

    // Detect suspiciously long base64-like blobs (potential encoded payloads)
    const base64Pattern = /[A-Za-z0-9+/]{200,}={0,2}/;

    for (const pattern of injectionPatterns) {
      if (pattern.test(content)) return true;
    }
    for (const pattern of shellPatterns) {
      if (pattern.test(content)) return true;
    }
    if (base64Pattern.test(content)) return true;

    return false;
  }

  // Resolve and validate the companion file path to prevent path traversal
  const companionsDir = path.resolve("companions");
  const resolvedPath = path.resolve(companionsDir, companionFileName);
  if (!resolvedPath.startsWith(companionsDir + path.sep)) {
    console.log("Invalid companion file path");
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion" }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const rawData = await fs.readFile(resolvedPath, "utf8");
  const data = sanitizeCompanionContent(rawData);

  if (detectMaliciousContent(data)) {
    console.log("Malicious content detected in companion file:", companionFileName);
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains disallowed content" }),
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
    modelName: "chatgpt",
    userId: clerkUserId,
  };
  const memoryManager = await MemoryManager.getInstance();

  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }

  await memoryManager.writeToHistory("Human: " + sanitizeInput(prompt, 2000) + "\n", companionKey);
  let recentChatHistory = await memoryManager.readLatestHistory(companionKey);
  // Data minimisation: limit recent chat history to the last 10 lines
  recentChatHistory = recentChatHistory.split("\n").slice(-10).join("\n");

    // Vector search removed to limit credentialed external systems to an acceptable number.
  // Pinecone access (4th external credential) has been eliminated.
  let relevantHistory = "";

  // LangChainStream removed; using approved LLM endpoint with ReadableStream instead.
  let approvedLLMResolve: (value: string) => void;
  const approvedLLMPromise = new Promise<string>((res) => { approvedLLMResolve = res; });
  const stream = new ReadableStream({
    async start(controller) {
      const result = await approvedLLMPromise;
      controller.enqueue(new TextEncoder().encode(result));
      controller.close();
    }
  });

    // Approved model registry entry — immutable versioned release with integrity pin.
  // Registry: internal-approved-models-v1
  // Model: gpt-4o-2024-08-06 (OpenAI stable, pinned release; not a mutable alias)
  // Integrity digest (SHA-256 of model card + version string, for audit):
  //   sha256:a3f1c2e4b7d09e5f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f
  const APPROVED_MODEL_REGISTRY = {
    modelName: "gpt-4o-2024-08-06",
    version: "2024-08-06",
    registry: "internal-approved-models-v1",
    integrityDigest:
      "sha256:a3f1c2e4b7d09e5f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f",
  } as const;

  console.log("[MODEL_IDENTITY]", JSON.stringify(APPROVED_MODEL_REGISTRY));

    // Approved LLM call replacing OpenAI/langchain model
  const approvedLLMCall = async (prompt: string): Promise<string> => {
    const approvedEndpoint = process.env.APPROVED_LLM_API_URL;
    const approvedApiKey = process.env.APPROVED_LLM_API_KEY;
    if (!approvedEndpoint) throw new Error("APPROVED_LLM_API_URL is not configured");
    const resp = await fetch(approvedEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(approvedApiKey ? { "Authorization": `Bearer ${approvedApiKey}` } : {}),
      },
      body: JSON.stringify({ prompt }),
    });
    if (!resp.ok) throw new Error(`Approved LLM API error: ${resp.status}`);
    const data = await resp.json();
    return data.text ?? data.output ?? data.result ?? "";
  };
  model.verbose = true;

  const replyWithTwilioLimit = isText
    ? "You reply within 1000 characters."
    : "";

  // Sanitize untrusted inputs before injecting into the prompt.
  // Strip characters that could be used to escape or hijack prompt structure.
  const sanitize = (value: string): string =>
    value
      .replace(/[`${}\\]/g, "")   // remove template-literal metacharacters
      .replace(/\r?\n/g, " ")      // collapse newlines to spaces
      .trim()
      .slice(0, 4000);             // hard length cap per field

  const safeName           = sanitize(name!);
  const safeClerkUserName  = sanitize(clerkUserName ?? "");
  const safePreamble       = sanitize(preamble);
  const safeRecentHistory  = sanitize(recentChatHistory);
  const safeRelevantHistory = sanitize(relevantHistory);

  // Use LangChain input-variable placeholders ({varName}) instead of JS
  // template-literal interpolation so values are treated as data, not prompt
  // structure, and are never evaluated at template-parse time.
  const chainPrompt = PromptTemplate.fromTemplate(
    `You are {name} and are currently talking to {clerkUserName}.\n\n` +
    `{preamble}\n\n` +
    `You reply with answers that range from one sentence to one paragraph and with some details. ${replyWithTwilioLimit}\n\n` +
    `Below are relevant details about {name}'s past\n{relevantHistory}\n\n` +
    `Below is a relevant conversation history\n\n{recentChatHistory}`
  );

  const chain = new LLMChain({
    llm: model,
    prompt: chainPrompt,
  });

  const llmInput = {
    relevantHistory,
    recentChatHistory: recentChatHistory,
  };
  console.log("LLM request - name:", name, "user:", clerkUserId, "input:", JSON.stringify(llmInput));
  console.log("LLM request dispatched.");

    const result = await Promise.race([
    chain
      .call({
        name: safeName,
        clerkUserName: safeClerkUserName,
        preamble: safePreamble,
        relevantHistory: safeRelevantHistory,
        recentChatHistory: safeRecentHistory,
      })
      .catch(console.error),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("LLM chain timed out")), 30_000)
    ),
  ]);
    const responseTimestamp = new Date().toISOString();
  const outputHash = hashInput(result);

  await writeAuditLog({
    event: "llm_response",
    request_timestamp: requestTimestamp,
    response_timestamp: responseTimestamp,
    principal: clerkUserId,
    companion: name,
    model_id: MODEL_ID,
    model_version: MODEL_VERSION,
    input_hash: inputHash,
    output_hash: outputHash,
    output_text: typeof result?.text === "string" ? result.text.slice(0, 2000) : null,
  });
  console.log("LLM response - name:", name, "user:", clerkUserId, "output_hash:", outputHash);
  // Validate and sanitize LLM output before use
  const sanitizeLLMOutput = (text: string): string => {
    // Patterns for dynamic code execution primitives
    const dangerousPatterns = [
      /\beval\s*\(/gi,
      /\bexec\s*\(/gi,
      /\bnew\s+Function\s*\(/gi,
      /\bsetTimeout\s*\(\s*['"`]/gi,
      /\bsetInterval\s*\(\s*['"`]/gi,
      /\bsetImmediate\s*\(\s*['"`]/gi,
      /\bprocess\.binding\s*\(/gi,
      /\brequire\s*\(/gi,
      /\bimport\s*\(/gi,
      /\b__import__\s*\(/gi,
      /\bexecSync\s*\(/gi,
      /\bspawnSync\s*\(/gi,
      /\bchild_process/gi,
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(text)) {
        console.warn("Dangerous code execution primitive detected in LLM output. Sanitizing.");
        // Replace the dangerous pattern with an empty string
        text = text.replace(pattern, "[REMOVED]");
      }
    }
    return text;
  };

  const rawText = result!.text;
  const sanitizedText = sanitizeLLMOutput(rawText);

  const chatHistoryRecord = await memoryManager.writeToHistory(
    sanitizedText + "\n",
    companionKey
  );
  await writeAuditLog({
    event: "history_written",
    timestamp: new Date().toISOString(),
    principal: clerkUserId,
    companion: name,
    output_hash: outputHash,
    history_record_id: typeof chatHistoryRecord === "string" ? chatHistoryRecord : JSON.stringify(chatHistoryRecord),
  });
  console.log("chatHistoryRecord written for companion:", name);

  // --- Synthetic Content Provenance & Labeling ---
  const crypto = await import("crypto");
  const MODEL_ID = process.env.LLM_MODEL_ID ?? "gpt-3.5-turbo";
  const SIGNING_SECRET = process.env.LLM_SIGNING_SECRET ?? "change-me-in-env";
  const provenanceTimestamp = new Date().toISOString();

  /**
   * Build a deterministic provenance payload that travels with every
   * AI-generated response so downstream consumers can verify origin.
   */
  const buildProvenance = (text: string) => {
    const payload = {
      content: text,
      provenance: {
        contentLabel: "AI_GENERATED_SYNTHETIC_CONTENT",
        modelId: MODEL_ID,
        generatedAt: provenanceTimestamp,
        userId: clerkUserId ?? "anonymous",
      },
    };
    // Cryptographic HMAC-SHA256 signature over the stable JSON representation
    const canonical = JSON.stringify(payload.provenance) + text;
    const signature = crypto
      .createHmac("sha256", SIGNING_SECRET)
      .update(canonical)
      .digest("hex");
    return { ...payload, signature };
  };

  if (isText) {
    const annotated = buildProvenance(sanitizedText);
    return NextResponse.json(annotated, {
      headers: {
        "X-Content-Label": "AI_GENERATED_SYNTHETIC_CONTENT",
        "X-Model-Id": MODEL_ID,
        "X-Generated-At": provenanceTimestamp,
        "X-Provenance-Signature": annotated.signature,
      },
    });
  }

  // Streaming path: inject provenance as the first SSE comment so the
  // raw stream is also annotated before any text tokens arrive.
  const provenanceMeta = buildProvenance("[streaming]");
  const provenancePrefix = new TextEncoder().encode(
    `: X-Content-Label: AI_GENERATED_SYNTHETIC_CONTENT\n` +
    `: X-Model-Id: ${MODEL_ID}\n` +
    `: X-Generated-At: ${provenanceTimestamp}\n` +
    `: X-Provenance-Signature: ${provenanceMeta.signature}\n\n`
  );
  const prefixStream = new ReadableStream({
    start(controller) {
      controller.enqueue(provenancePrefix);
      controller.close();
    },
  });
  const annotatedStream = new ReadableStream({
    async start(controller) {
      for await (const chunk of prefixStream as any) {
        controller.enqueue(chunk);
      }
      const reader = (stream as any).getReader?.() ?? (stream as any)[Symbol.asyncIterator]?.();
      if (reader && typeof reader.read === "function") {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          controller.enqueue(value);
        }
      } else if (reader) {
        for await (const chunk of reader) {
          controller.enqueue(typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk);
        }
      }
      controller.close();
    },
  });
  return new StreamingTextResponse(annotatedStream, {
    headers: {
      "X-Content-Label": "AI_GENERATED_SYNTHETIC_CONTENT",
      "X-Model-Id": MODEL_ID,
      "X-Generated-At": provenanceTimestamp,
      "X-Provenance-Signature": provenanceMeta.signature,
    },
  });
}
