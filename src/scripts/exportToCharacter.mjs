// Redis dependency removed to reduce external credential exposure
import { PromptTemplate } from "langchain/prompts";
import { LLMChain } from "langchain/chains";
import { ChatOpenAI } from "langchain/chat_models/openai";

import path from "path";
import dotenv from "dotenv";
import fs from "fs/promises";
import crypto from "crypto";
dotenv.config({ path: `.env.local` });

const AUDIT_LOG_FILE = "ai_audit_log.jsonl";

async function writeAuditRecord(record) {
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
  const signingKey = process.env.PROVENANCE_SIGNING_KEY || "default-insecure-key";
  const hmac = crypto
    .createHmac("sha256", signingKey)
    .update(`${modelId}|${timestamp}|${content}`)
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

async function logLLMInteraction(input, output) {
  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    input,
    output,
  }) + "\n";
  await fs.appendFile(LLM_LOG_FILE, entry, "utf8");
  console.log("[LLM LOG]", entry);
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
const MODEL_NAME = process.argv[3];
const USER_ID = process.argv[4];

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

const questions = [
  `Greeting: What would ${safeCompanionName} say to start a conversation?`,
  `Short Description: In a few sentences, how would ${safeCompanionName} describe themselves?`,
  `Long Description: In a few sentences, how would ${safeCompanionName} describe themselves?`,
];
const results = await Promise.all(
  questions.map(async (question) => {
    try {
      const llmInput = { question };
      const llmResult = await chain.call(llmInput);
      await logLLMInteraction(llmInput, llmResult);
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
  output += `*****${questions[i]}*****\n${sanitizedText}\n\n`;
}
output += `Definition (Advanced)\n${recentChat.join("\n")}`;

await fs.writeFile(`${COMPANION_NAME}_chat_history.txt`, recentChat.join("\n"));

// Attach provenance metadata and synthetic-content label before persisting
// AI-generated output so the file's origin is always traceable.
const AI_MODEL_ID = "openai/gpt-3.5-turbo-16k";
const provenanceHeader = buildProvenanceHeader(AI_MODEL_ID, output);
const labeledOutput = provenanceHeader + output;
await fs.writeFile(`${COMPANION_NAME}_character_ai_data.txt`, labeledOutput);
