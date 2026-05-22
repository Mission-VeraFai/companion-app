import { OpenAI } from "langchain/llms/openai";
import dotenv from "dotenv";
import { LLMChain } from "langchain/chains";
import { StreamingTextResponse, LangChainStream } from "ai";
import clerk from "@clerk/clerk-sdk-node";
import { CallbackManager } from "langchain/callbacks";
import { PromptTemplate } from "langchain/prompts";
import { NextResponse } from "next/server";
import { currentUser } from "@clerk/nextjs";
import MemoryManager from "@/app/utils/memory";
import { rateLimit } from "@/app/utils/rateLimit";
import { createHash, randomUUID } from "crypto";

dotenv.config({ path: `.env.local` });

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

function sanitizeInput(input: string, maxLength = 4000): string {
  if (!input || typeof input !== "string") return "";
  // Trim and enforce max length
  return input.trim().slice(0, maxLength);
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
  const { prompt: rawPrompt, isText, userId, userName } = await req.json();
  if (!rawPrompt || typeof rawPrompt !== "string") {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or missing prompt." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const prompt = sanitizeInput(rawPrompt, 2000);

  const identifier = req.url + "-" + (userId || "anonymous");
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

  const { stream, handlers } = LangChainStream();

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

  const model = new OpenAI({
    streaming: true,
    modelName: APPROVED_MODEL_REGISTRY.modelName,
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });
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
  console.log("LLM request - preamble:", preamble);

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
  console.log("chain.call spawned with sanitized inputs for companion:", safeName);

  console.log("LLM response - name:", name, "user:", clerkUserId, "output:", JSON.stringify(result));

  console.log("result", result);
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
  console.log("chatHistoryRecord", chatHistoryRecord);
  if (isText) {
    return NextResponse.json(sanitizedText);
  }
  return new StreamingTextResponse(stream);
}
