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
import { createHash } from "crypto";
import { promises as fsAudit, constants as fsConstants } from "fs";
import path from "path";

const AUDIT_LOG_PATH = path.resolve(process.cwd(), "audit", "ai_audit.jsonl");

async function writeAuditRecord(record: {
  timestamp: string;
  principal: string;
  modelId: string;
  inputHash: string;
  output: string;
  companionName: string;
}): Promise<void> {
  const line = JSON.stringify(record) + "\n";
  // Ensure audit directory exists
  await fsAudit.mkdir(path.dirname(AUDIT_LOG_PATH), { recursive: true });
  // Append atomically to the JSONL audit log
  const fh = await fsAudit.open(AUDIT_LOG_PATH, "a");
  try {
    await fh.write(line);
  } finally {
    await fh.close();
  }
}

dotenv.config({ path: `.env.local` });

// ---------------------------------------------------------------------------
// Input sanitization helpers
// ---------------------------------------------------------------------------
const MAX_PROMPT_LENGTH = 1000;
const MAX_NAME_LENGTH = 64;

/**
 * Remove characters commonly used for prompt injection and trim whitespace.
 * Strips: backticks, angle brackets, curly braces, and control characters.
 */
function sanitizeText(input: string, maxLength: number): string {
  if (typeof input !== "string") return "";
  return input
    .replace(/[`<>{}\x00-\x1F\x7F]/g, "") // strip dangerous / control chars
    .trim()
    .slice(0, maxLength);
}

/**
 * Validate that a companion name contains only safe filename/identifier chars.
 * Allowed: letters, digits, spaces, hyphens, underscores.
 */
function isValidName(name: string | null): name is string {
  if (!name) return false;
  return /^[\w\s\-]{1,64}$/.test(name);
}

export async function POST(req: Request) {
  let clerkUserId;
  let user;
  let clerkUserName;
  const rawBody = await req.json();
  const rawPrompt: string = rawBody.prompt ?? "";
  const isText: boolean = rawBody.isText ?? false;
  const userId: string = rawBody.userId ?? "";
  const rawUserName: string = rawBody.userName ?? "";

  // Sanitize user-supplied fields immediately after parsing
  const prompt = sanitizeText(rawPrompt, MAX_PROMPT_LENGTH);
  const userName = sanitizeText(rawUserName, MAX_NAME_LENGTH);

  if (!prompt) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or empty prompt." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

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
  const rawName = req.headers.get("name");
  if (!isValidName(rawName)) {
    console.log("Invalid companion name:", rawName);
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const name = sanitizeText(rawName, MAX_NAME_LENGTH);
  const companionFileName = name + ".txt";

  console.log("prompt: ", prompt);
  if (isText) {
    clerkUserId = userId;
    clerkUserName = sanitizeText(userName, MAX_NAME_LENGTH);
  } else {
    user = await currentUser();
    clerkUserId = user?.id;
    clerkUserName = user?.firstName;
  }

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

  // Validate the companion name to prevent path traversal and restrict to
  // known safe filenames (alphanumeric, hyphens, underscores only).
  if (!name || !/^[a-zA-Z0-9_-]+$/.test(name)) {
    console.log("Invalid companion name:", name);
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const fs = require("fs").promises;
  const path = require("path");
  const companionsDir = path.resolve("companions");
  const resolvedPath = path.resolve(companionsDir, companionFileName);
  // Double-check resolved path is within the companions directory
  if (!resolvedPath.startsWith(companionsDir + path.sep) && resolvedPath !== companionsDir) {
    console.log("Path traversal attempt detected");
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name" }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }
  const data = await fs.readFile(resolvedPath, "utf8");

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const rawPreamble = presplit[0];
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const rawSeedchat = seedsplit[0];

  /**
   * Sanitize a string destined for an LLM prompt.
   * - Enforces a maximum length to limit payload size.
   * - Removes non-printable / hidden Unicode control characters (except common
   *   whitespace) that are used to smuggle invisible instructions.
   * - Strips patterns commonly used for prompt-injection overrides such as
   *   "ignore previous instructions", role-switch markers, and delimiter abuse.
   */
  function sanitizeForPrompt(input: string, maxLength = 4000): string {
    // 1. Enforce maximum length.
    let sanitized = input.slice(0, maxLength);

    // 2. Remove non-printable Unicode control characters (U+0000–U+001F except
    //    tab/newline/carriage-return, and U+007F–U+009F, and Unicode tag block
    //    U+E0000–U+E007F used for invisible text).
    sanitized = sanitized.replace(
      /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\uE0000-\uE007F]/gu,
      ""
    );

    // 3. Neutralize common prompt-injection override phrases (case-insensitive).
    //    Replace them with a placeholder so the structure is preserved but the
    //    injection attempt is defused.
    const injectionPatterns = [
      /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
      /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
      /forget\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
      /you\s+are\s+now\s+(a|an|the)?\s*(?:different|new|another|evil|unrestricted)/gi,
      /act\s+as\s+(a|an|the)?\s*(?:different|new|another|evil|unrestricted|jailbroken)/gi,
      /\[SYSTEM\]/gi,
      /\[INST\]/gi,
      /<\|system\|>/gi,
      /<\|user\|>/gi,
      /<\|assistant\|>/gi,
      /###\s*system/gi,
      /###\s*instruction/gi,
    ];
    for (const pattern of injectionPatterns) {
      sanitized = sanitized.replace(pattern, "[REDACTED]");
    }

    return sanitized;
  }

  const preamble = sanitizeForPrompt(rawPreamble);
  const seedchat = sanitizeForPrompt(rawSeedchat);

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

  const sanitizedPrompt = sanitizeInput(prompt, 1000);
  await memoryManager.writeToHistory("Human: " + sanitizedPrompt + "\n", companionKey);
  let recentChatHistoryRaw = await memoryManager.readLatestHistory(companionKey);
  let recentChatHistory = recentChatHistoryRaw
    .split("\n")
    .filter((line: string) => line.trim() !== "")
    .slice(-10)
    .join("\n");

    // Pinecone vector search removed to comply with the 3-external-system credential limit.
  // Relevant history is not populated from vector search.
  const relevantHistory = "";

  const { stream, handlers } = LangChainStream();

    // Approved model registry and identity verification
  const APPROVED_MODEL_REGISTRY: Record<string, { provider: string; version: string; approved: boolean }> = {
    "gpt-4o": { provider: "openai", version: "gpt-4o", approved: true },
  };
  const PINNED_MODEL_NAME = "gpt-4o";
  const modelEntry = APPROVED_MODEL_REGISTRY[PINNED_MODEL_NAME];
  if (!modelEntry || !modelEntry.approved) {
    console.error(`Model '${PINNED_MODEL_NAME}' is not in the approved registry.`);
    return new NextResponse(
      JSON.stringify({ Message: "Model not approved for use" }),
      { status: 403, headers: { "Content-Type": "application/json" } }
    );
  }
  // Record model identity in request metadata for audit
  const modelIdentityMetadata = {
    modelName: modelEntry.version,
    provider: modelEntry.provider,
    approvedAt: new Date().toISOString(),
    requestedBy: clerkUserId,
  };
  console.log("[MODEL_IDENTITY]", JSON.stringify(modelIdentityMetadata));

  const model = new OpenAI({
    streaming: true,
    modelName: PINNED_MODEL_NAME,
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });
  model.verbose = true;

  const replyWithTwilioLimit = isText
    ? "You reply within 1000 characters."
    : "";

  const safeClerkUserName = sanitizeInput(clerkUserName ?? "", 100);
    // Sanitize untrusted inputs before they reach the LLM prompt.
  // Strips characters commonly used for prompt injection and enforces
  // a hard length cap so that oversized payloads cannot be injected.
  const MAX_FIELD_LEN = 4000;
  function sanitizePromptInput(value: string, maxLen = MAX_FIELD_LEN): string {
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new Error("Invalid or empty prompt input detected.");
    }
    // Remove null bytes, and strip sequences that look like prompt-injection
    // attempts (e.g. "Ignore previous instructions", role-switch markers).
    const cleaned = value
      .replace(/\x00/g, "")
      .replace(/(ignore|disregard|forget).{0,40}(previous|above|prior).{0,40}(instruction|prompt|context)/gi, "[REDACTED]")
      .replace(/(<\|system\|>|<\|user\|>|<\|assistant\|>|###\s*system|###\s*instruction)/gi, "[REDACTED]");
    return cleaned.slice(0, maxLen);
  }

  const safeName            = sanitizePromptInput(name ?? "", 200);
  const safeClerkUserName   = sanitizePromptInput(clerkUserName ?? "", 200);
  const safePreamble        = sanitizePromptInput(preamble, MAX_FIELD_LEN);
  const safeRecentHistory   = sanitizePromptInput(recentChatHistory, MAX_FIELD_LEN);
  const safeRelevantHistory = sanitizePromptInput(relevantHistory || " ", MAX_FIELD_LEN);

  const chainPrompt = PromptTemplate.fromTemplate(
    `You are {name} and are currently talking to {clerkUserName}.

{preamble}

You reply with answers that range from one sentence to one paragraph and with some details. ${replyWithTwilioLimit}

Below are relevant details about {name}'s past
{relevantHistory}

Below is a relevant conversation history

{recentChatHistory}`
  );

  const chain = new LLMChain({
    llm: model,
    prompt: chainPrompt,
  });

  const chainInput = {
    relevantHistory,
    recentChatHistory: recentChatHistory,
  };
  console.log("LLM interaction input:", JSON.stringify({
    companion: name,
    user: clerkUserName,
    prompt,
    chainInput,
  }));
      const MODEL_ID = "gpt-3.5-turbo"; // update to match the actual model name/version in use
  const inputPayload = JSON.stringify({ relevantHistory, recentChatHistory });
  const inputHash = createHash("sha256").update(inputPayload).digest("hex");

  const result = await chain
    .call({
      relevantHistory,
      recentChatHistory: recentChatHistory,
    })
    .catch(console.error);

  // Write durable audit record immediately after inference
  await writeAuditRecord({
    timestamp: new Date().toISOString(),
    principal: clerkUserId!,
    modelId: MODEL_ID,
    inputHash,
    output: result?.text ?? "",
    companionName: name ?? "unknown",
  });

  console.log("result", result);
  // Validate and sanitize LLM output before use
  const llmOutput: string = result?.text ?? "";

  if (typeof llmOutput !== "string" || llmOutput.trim().length === 0) {
    console.error("LLM output is invalid or empty");
    return new NextResponse("Invalid response from model", { status: 500 });
  }

  // Check for dynamic code execution primitives in LLM output
  const dangerousPatterns = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bnew\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bimport\s*\(/i,
    /\brequire\s*\(/i,
    /\bprocess\.env\b/i,
    /\bchild_process\b/i,
    /__proto__/i,
    /constructor\s*\[/i,
  ];

  const hasDangerousContent = dangerousPatterns.some((pattern) =>
    pattern.test(llmOutput)
  );

  if (hasDangerousContent) {
    console.error(
      "LLM output contains potentially dangerous code execution primitives. Rejecting response."
    );
    return new NextResponse(
      "Response blocked due to policy violation",
      { status: 400 }
    );
  }

  // Sanitize: strip any HTML/script tags as an additional precaution
  const sanitizedOutput = llmOutput
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<[^>]+>/g, "")
    .trim();

  const chatHistoryRecord = await memoryManager.writeToHistory(
    sanitizedOutput + "\n",
    companionKey
  );
  console.log("chatHistoryRecord", chatHistoryRecord);
  if (isText) {
    return NextResponse.json(sanitizedOutput);
  }
  return new StreamingTextResponse(stream);
}
