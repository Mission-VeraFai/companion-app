import dotenv from "dotenv";
import { StreamingTextResponse } from "ai";
import OpenAI from "openai";
import clerk from "@clerk/clerk-sdk-node";
import MemoryManager from "@/app/utils/memory";
import { currentUser } from "@clerk/nextjs";
import { NextResponse } from "next/server";
import { rateLimit } from "@/app/utils/rateLimit";

dotenv.config({ path: `.env.local` });

function containsMaliciousContent(input: string): boolean {
  if (!input || typeof input !== "string") return false;

  // Check for shell command patterns
  const shellCommandPattern = /([`$]\(|\|\s*\w+|;\s*\w+|&&\s*\w+|\|\||>\s*\/|<\s*\/|\bexec\b|\beval\b|\bsystem\b|\bspawn\b|\bpopen\b|\bsubprocess\b|\bos\.system\b|\bchild_process\b)/i;

  // Check for base64 encoded content (long base64 strings are suspicious)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/;

  // Check for leetspeak obfuscation patterns (e.g., 1gnor3, 3x3cut3)
  const leetspeakPattern = /\b(?:[a-z]*[013456789][a-z0-9]*){3,}\b/i;

  // Check for prompt injection / hidden instruction patterns
  const promptInjectionPattern = /(?:ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?|disregard\s+(?:all\s+)?(?:previous|above|prior)|you\s+are\s+now|new\s+instructions?:|system\s*:|<\s*system\s*>|\[\s*system\s*\]|###\s*instruction|forget\s+(?:all\s+)?(?:previous|your))/i;

  // Check for encoded/obfuscated script tags or HTML injection
  const encodedInjectionPattern = /(?:%3C|%3E|%22|%27|&#x?[0-9a-f]+;|\\u[0-9a-f]{4}|\\x[0-9a-f]{2})/i;

  return (
    shellCommandPattern.test(input) ||
    base64Pattern.test(input) ||
    leetspeakPattern.test(input) ||
    promptInjectionPattern.test(input) ||
    encodedInjectionPattern.test(input)
  );
}

export async function POST(request: Request) {
  const { prompt } = await request.json();

  if (!prompt || typeof prompt !== "string" || prompt.trim().length === 0) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid prompt." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  if (containsMaliciousContent(prompt)) {
    console.warn("SECURITY: Malicious content detected in prompt from user:", userId || "anonymous");
    return new NextResponse(
      JSON.stringify({ Message: "Prompt contains disallowed content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  let clerkUserId: string | undefined;
  let user: Awaited<ReturnType<typeof currentUser>>;
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
  const name = request.headers.get("name");
  // companion_file_name is derived safely below after sanitization
  const companion_file_name = (name || "").replace(/[^a-zA-Z0-9_-]/g, "") + ".txt";

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

  // Validate companion file content for malicious patterns before use.
  function validateCompanionContent(content: string): void {
    // Check for prompt injection / jailbreak attempts
    const promptInjectionPatterns = [
      /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
      /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
      /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
      /you\s+are\s+now\s+(a\s+)?(?!${name})/i,
      /act\s+as\s+(if\s+you\s+are\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken)/i,
      /do\s+anything\s+now/i,
      /DAN\b/,
      /\[SYSTEM\]/i,
      /<<SYS>>/i,
      /<\|system\|>/i,
      /###\s*system/i,
    ];

    // Check for base64-encoded payloads (long base64 strings are suspicious)
    const base64Pattern = /(?:[A-Za-z0-9+/]{40,}={0,2})/;

    // Check for shell command injection
    const shellCommandPatterns = [
      /`[^`]{0,200}`/,
      /\$\([^)]{0,200}\)/,
      /;\s*(rm|wget|curl|bash|sh|python|perl|nc|ncat|netcat)\s/i,
      /\|\s*(bash|sh|python|perl)\s/i,
      /&&\s*(rm|wget|curl|bash|sh|python|perl)\s/i,
    ];

    // Check for leetspeak obfuscation (excessive use of character substitutions)
    const leetspeakPattern = /(?:[a@][s$][s$]|[h#][a@4][x*][o0][r]|[i!1][g9][n][o0][r][e3])/i;

    // Check for hidden/invisible unicode characters used for obfuscation
    const hiddenUnicodePattern = /[\u200B-\u200D\uFEFF\u00AD\u2060]/;

    // Check for excessive special characters that may indicate obfuscation
    const excessiveSpecialCharsPattern = /(?:[^\w\s.,!?'"\-:;()\[\]{}\n]){5,}/;

    const allPatterns: Array<{ pattern: RegExp; label: string }> = [
      ...promptInjectionPatterns.map((p) => ({ pattern: p, label: "prompt injection" })),
      { pattern: base64Pattern, label: "base64 encoded content" },
      ...shellCommandPatterns.map((p) => ({ pattern: p, label: "shell command" })),
      { pattern: leetspeakPattern, label: "leetspeak obfuscation" },
      { pattern: hiddenUnicodePattern, label: "hidden unicode characters" },
      { pattern: excessiveSpecialCharsPattern, label: "excessive special characters" },
    ];

    for (const { pattern, label } of allPatterns) {
      if (pattern.test(content)) {
        throw new Error(`Companion file contains potentially malicious content: ${label}`);
      }
    }

    // Enforce a reasonable maximum length to prevent prompt flooding
    const MAX_CONTENT_LENGTH = 32768;
    if (content.length > MAX_CONTENT_LENGTH) {
      throw new Error("Companion file exceeds maximum allowed length");
    }
  }

  // Load character "PREAMBLE" from character file. These are the core personality
  // characteristics that are used in every prompt. Additional background is
  // only included if it matches a similarity comparioson with the current
  // discussion. The PREAMBLE should include a seed conversation whose format will
  // vary by the model using it.
  const fs = require("fs").promises;
  const path = require("path");
  // Sanitize: allow only alphanumeric, hyphens, and underscores in the companion name
  const safeName = (name || "").replace(/[^a-zA-Z0-9_-]/g, "");
  if (!safeName) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const companionsDir = path.resolve("companions");
  const companionFilePath = path.resolve(companionsDir, safeName + ".txt");
  if (!companionFilePath.startsWith(companionsDir + path.sep)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const data = await fs.readFile(companionFilePath, "utf8");

  // Validate companion file content for malicious patterns before injecting into prompts
  try {
    validateCompanionContent(data);
  } catch (err: any) {
    console.error("Companion file validation failed:", err.message);
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
  const preamble = presplit[0];
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = seedsplit[0];

  const companionKey = {
    companionName: name!,
    userId: clerkUserId!,
    modelName: "llama2-13b",
  };
  const memoryManager = await MemoryManager.getInstance();

  // Sanitize untrusted string input before use in LLM prompts.
  // Removes characters that could break prompt structure or inject instructions.
  const sanitizeInput = (input: string): string => {
    return input
      .replace(/`/g, "'")           // replace backticks to prevent template-literal injection
      .replace(/\\[nrt]/g, " ")     // collapse escape sequences
      .replace(/[\r\n]+/g, " ")     // collapse real newlines to a single space
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "") // strip control chars
      .trim()
      .slice(0, 1000);              // hard cap to limit prompt-stuffing
  };

  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
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

  const MAX_RELEVANT_DOCS = 3;
  const MAX_DOC_CHARS = 200;
  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    relevantHistory = similarDocs
      .slice(0, MAX_RELEVANT_DOCS)
      .map((doc) => (doc.pageContent || "").slice(0, MAX_DOC_CHARS))
      .join("\n");
  }
    // The llama13b-v2-chat model via a16z-infra on Replicate is not on the
  // organization's approved LLM registry and has been disabled.
  return new NextResponse(
    JSON.stringify({
      Message:
        "The requested model (llama2-13b via Replicate/a16z-infra) is not on the approved LLM registry and cannot be used.",
    }),
    {
      status: 403,
      headers: {
        "Content-Type": "application/json",
      },
    }
  );

  // Dead code retained for structural reference only — do not remove the early return above.
  let resp = "";
  // Call approved OpenAI model for inference
  const model = new OpenAI({
    modelName: "gpt-3.5-turbo-instruct",
    maxTokens: 2048,
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
    streaming: true,
  });

  // Turn verbose on for debugging
  model.verbose = true;

  const llmPrompt = `
       ONLY generate NO more than three sentences as ${name}. DO NOT generate more than three sentences. 
       Make sure the output you generate starts with '${name}:' and ends with a period.

       ${sanitizedPreamble}

       Below are relevant details about ${name}'s past and the conversation you are in.
       ${sanitizedRelevantHistory}


       ${sanitizeInput(recentChatHistory)}\n${name}:`;

  console.log("[LLM INTERACTION] Model: llama2-13b | Prompt sent to LLM:", llmPrompt);

    const crypto = require("crypto");
  const path = require("path");

  const modelIdentifier =
    "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5";

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

  const auditTimestamp = new Date().toISOString();
  const auditLogPath = path.resolve(process.cwd(), "audit", "ai_decisions.jsonl");

  // Ensure audit directory exists
  await fs.mkdir(path.dirname(auditLogPath), { recursive: true });

  let resp: string;
  let inferenceError: unknown = null;

  try {
    resp = String(
      await model
        .call(inputPrompt)
        .catch((err: unknown) => {
          inferenceError = err;
          console.error(err);
        })
    );
  } finally {
    const auditRecord = JSON.stringify({
      timestamp: auditTimestamp,
      principal: clerkUserId,
      modelIdentifier,
      companionName: name,
      inputHash,
      output: inferenceError ? null : resp!,
      error: inferenceError
        ? String(inferenceError)
        : null,
    });
    await fs
      .appendFile(auditLogPath, auditRecord + "\n", "utf8")
      .catch((logErr: unknown) =>
        console.error("[AUDIT] Failed to write audit log:", logErr)
      );
  }

  console.log("[LLM INTERACTION] Model: llama2-13b | Response received from LLM:", resp);

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("\n");
  const rawResponse = chunks[0];

  // Validate and sanitize LLM output: reject responses containing dynamic code execution primitives
  const dangerousPatterns = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bFunction\s*\(/i,
    /\bnew\s+Function\b/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bimport\s*\(/i,
    /\brequire\s*\(/i,
    /\bprocess\.exec/i,
    /\bchild_process/i,
    /\bspawn\s*\(/i,
    /\bexecSync\s*\(/i,
    /\bvm\.run/i,
  ];

  const containsDangerousCode = dangerousPatterns.some((pattern) =>
    pattern.test(rawResponse)
  );

  if (containsDangerousCode) {
    console.warn("LLM response contained dangerous code execution primitive and was rejected.");
    return new Response("Response blocked due to policy violation.", { status: 400 });
  }

  // Strip any residual script-like tags or backtick code blocks as an extra precaution
  const response = rawResponse
    .replace(/<script[^>]*>.*?<\/script>/gi, "")
    .replace(/```[\s\S]*?```/g, "")
    .trim();
  // const response = chunks.length > 1 ? chunks[0] : chunks[0];

  await memoryManager.writeToHistory("" + response.trim(), companionKey);
  var Readable = require("stream").Readable;

  // --- Synthetic Content Provenance & Watermarking ---
  const MODEL_ID =
    "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5";
  const generatedAt = new Date().toISOString();

  // Build a cryptographic HMAC-SHA256 watermark over (modelId + timestamp + response)
  const crypto = require("crypto");
  const watermarkSecret = process.env.WATERMARK_SECRET ?? "changeme-set-WATERMARK_SECRET";
  const hmac = crypto.createHmac("sha256", watermarkSecret);
  hmac.update(`${MODEL_ID}|${generatedAt}|${response}`);
  const watermarkToken = hmac.digest("hex");

  // Prepend a machine-readable synthetic-content label + watermark to the stream
  const provenancePrefix =
    `[AI-GENERATED|model=${MODEL_ID}|ts=${generatedAt}|sig=${watermarkToken}]\n`;

  let s = new Readable();
  s.push(provenancePrefix + response);
  s.push(null);

  if (response !== undefined && response.length > 1) {
    memoryManager.writeToHistory("" + response.trim(), companionKey);
  }

  // Attach provenance headers so API consumers can verify synthetic origin
  const provenanceHeaders = new Headers({
    "X-AI-Model-ID": MODEL_ID,
    "X-AI-Generated-At": generatedAt,
    "X-AI-Watermark": watermarkToken,
    "X-Content-Type-Label": "ai-generated-synthetic-text",
  });

  return new StreamingTextResponse(s, { headers: provenanceHeaders });
}
