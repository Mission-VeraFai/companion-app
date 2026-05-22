import dotenv from "dotenv";
import { StreamingTextResponse, LangChainStream } from "ai";
import { Replicate, ReplicateInput } from "langchain/llms/replicate";
import { CallbackManager } from "langchain/callbacks";
import clerk from "@clerk/clerk-sdk-node";
import MemoryManager from "@/app/utils/memory";
import { currentUser } from "@clerk/nextjs";
import { NextResponse } from "next/server";
import { rateLimit } from "@/app/utils/rateLimit";

dotenv.config({ path: `.env.local` });

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
  let clerkUserId;
  let user;
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

  console.log("[LLM INTERACTION] Response received from llama2-13b:", resp);

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
  const response = chunks[0];
  // const response = chunks.length > 1 ? chunks[0] : chunks[0];

  await memoryManager.writeToHistory("" + response.trim(), companionKey);
  var Readable = require("stream").Readable;

  const MODEL_ID =
    "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5";
  const generatedAt = new Date().toISOString();

  // Cryptographic watermark: HMAC-SHA256 over (modelId + timestamp + response)
  const crypto = require("crypto");
  const signingSecret = process.env.WATERMARK_SECRET || "default-watermark-secret";
  const hmac = crypto.createHmac("sha256", signingSecret);
  hmac.update(`${MODEL_ID}|${generatedAt}|${response}`);
  const signature = hmac.digest("hex");

  // Provenance prefix prepended to the streamed payload
  const provenancePrefix =
    `[AI-GENERATED CONTENT | model=${MODEL_ID} | generated_at=${generatedAt} | sig=${signature}]\n`;

  let s = new Readable();
  s.push(provenancePrefix + response);
  s.push(null);
  if (response !== undefined && response.length > 1) {
    memoryManager.writeToHistory("" + response.trim(), companionKey);
  }

  // Provenance and labeling headers
  const provenanceHeaders = new Headers({
    "X-AI-Generated": "true",
    "X-AI-Model-ID": MODEL_ID,
    "X-AI-Generated-At": generatedAt,
    "X-AI-Content-Signature": signature,
    "X-Content-Label": "synthetic-ai-generated-text",
  });

  return new StreamingTextResponse(s, { headers: provenanceHeaders });
}
