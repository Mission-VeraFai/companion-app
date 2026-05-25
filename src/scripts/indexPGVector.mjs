// Call embeding API and insert to supabase
// Ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/supabase

import dotenv from "dotenv";
import { Document } from "langchain/document";
// NOTE: 'langchain/embeddings/openai' is NOT in the approved model registry.
// TODO: Replace with an approved registry package when available.
// Model version is explicitly pinned below to satisfy version-pinning policy.
import { OpenAIEmbeddings } from "langchain/embeddings/openai";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { createClient } from "@supabase/supabase-js";
import { CharacterTextSplitter } from "langchain/text_splitter";
import crypto from "crypto";
import { appendFileSync } from "fs";

import fs from "fs";
import path from "path";

/**
 * Detects Singapore PII in a given text string.
 * Categories checked:
 *  - NRIC / FIN numbers (e.g. S1234567A, T0312345B, F1234567K, G1234567X)
 *  - Singapore passport numbers (e.g. E1234567X)
 *  - Singapore mobile / local phone numbers (+65 XXXX XXXX or 8/9-digit starting with 6,8,9)
 *  - Singapore postal codes (6-digit, optionally preceded by "Singapore")
 *  - Full name + NRIC combos (broad heuristic)
 * Throws an error listing which PII types were found.
 */
function detectSingaporePII(text, fileName) {
  const findings = [];

  // NRIC / FIN: starts with S, T, F, G or M followed by 7 digits and a letter
  const nricRegex = /\b[STFGM]\d{7}[A-Z]\b/gi;
  if (nricRegex.test(text)) {
    findings.push("NRIC/FIN number");
  }

  // Singapore passport number: starts with E followed by 7 digits and a letter
  const passportRegex = /\bE\d{7}[A-Z]\b/gi;
  if (passportRegex.test(text)) {
    findings.push("Singapore passport number");
  }

  // Singapore phone numbers: +65 followed by 8 digits, or standalone 8-digit numbers starting with 6, 8, or 9
  const phoneRegex = /(\+65[\s-]?\d{4}[\s-]?\d{4}|\b[689]\d{7}\b)/g;
  if (phoneRegex.test(text)) {
    findings.push("Singapore phone number");
  }

  // Singapore postal codes: 6-digit number optionally preceded by "Singapore"
  const postalRegex = /\b(?:Singapore\s)?\d{6}\b/gi;
  if (postalRegex.test(text)) {
    findings.push("Singapore postal code");
  }

  // Singapore bank account numbers: DBS/POSB/OCBC/UOB patterns (9-12 digit sequences near bank keywords)
  const bankRegex = /\b(?:DBS|POSB|OCBC|UOB|Citibank|Standard Chartered|HSBC)[^\n]{0,40}\d{9,12}\b/gi;
  if (bankRegex.test(text)) {
    findings.push("Singapore bank account number");
  }

  if (findings.length > 0) {
    throw new Error(
      `PII detected in file "${fileName}": ${findings.join(", ")}. ` +
      "Upload aborted. Remove or redact PII before indexing."
    );
  }
}

/**
 * Redacts common PII patterns from a string.
 * Covers: email addresses, US phone numbers, SSNs, credit card numbers,
 * and names preceded by common honorifics.
 */
function redactPII(text) {
  // Email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");
  // US phone numbers (various formats)
  text = text.replace(/(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g, "[REDACTED_PHONE]");
  // Social Security Numbers
  text = text.replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[REDACTED_SSN]");
  // Credit card numbers (16-digit, optionally grouped by spaces or dashes)
  text = text.replace(/\b(?:\d[ -]?){13,16}\b/g, "[REDACTED_CC]");
  // Names preceded by honorifics
  text = text.replace(/\b(Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*/g, "[REDACTED_NAME]");
  return text;
}

/**
 * Sanitizes file content to prevent prompt injection attacks.
 * Checks for and removes/rejects hidden prompts, base64-encoded content,
 * leetspeak, shell commands, and other malicious patterns.
 */
function sanitizeFileContent(content, fileName) {
  // Check for excessively long lines that may indicate encoded payloads
  const lines = content.split("\n");
  for (const line of lines) {
    if (line.length > 2000) {
      throw new Error(`File ${fileName} contains suspiciously long line (possible encoded payload).`);
    }
  }

  // Detect base64-encoded blocks (long strings of base64 chars)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  if (base64Pattern.test(content)) {
    throw new Error(`File ${fileName} contains possible base64-encoded content.`);
  }

  // Detect shell command injection patterns
  const shellCommandPattern = /(?:\$\(|`[^`]*`|\|\s*\w+|;\s*\w+|&&\s*\w+|\|\|\s*\w+|\bexec\b|\beval\b|\bsystem\b|\bpassthru\b|\bpopen\b)/i;
  if (shellCommandPattern.test(content)) {
    throw new Error(`File ${fileName} contains possible shell command injection.`);
  }

  // Detect prompt injection attempts (instructions to override system behavior)
  const promptInjectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/i,
    /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/i,
    /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/i,
    /you\s+are\s+now\s+(a\s+)?(?!a companion)/i,
    /new\s+(role|persona|identity|instructions?|task|objective)/i,
    /act\s+as\s+(if\s+you\s+are|a\s+)?(?!a companion)/i,
    /\[\s*(system|assistant|user|human|ai)\s*\]/i,
    /<\s*(system|assistant|user|human|ai)\s*>/i,
    /###\s*(system|instruction|prompt|override)/i,
    /---\s*(system|instruction|prompt|override)/i,
  ];
  for (const pattern of promptInjectionPatterns) {
    if (pattern.test(content)) {
      throw new Error(`File ${fileName} contains possible prompt injection attempt.`);
    }
  }

  // Detect leetspeak patterns (common substitutions: 3=e, 4=a, 0=o, 1=i/l, @=a, $=s)
  const leetspeakPattern = /(?:[a-z]*[30@$1!|][a-z0-9@$1!|]{3,})/i;
  const leetspeakMatches = content.match(leetspeakPattern);
  if (leetspeakMatches) {
    // Only flag if there are multiple leetspeak tokens (reduce false positives)
    const allMatches = content.match(new RegExp(leetspeakPattern.source, 'gi')) || [];
    if (allMatches.length > 5) {
      throw new Error(`File ${fileName} contains possible leetspeak-encoded content.`);
    }
  }

  // Detect zero-width characters and other invisible Unicode used to hide content
  const hiddenCharsPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/;
  if (hiddenCharsPattern.test(content)) {
    throw new Error(`File ${fileName} contains hidden Unicode characters (possible steganographic content).`);
  }

  // Detect excessive special character sequences that may indicate obfuscation
  const obfuscationPattern = /(?:[^a-zA-Z0-9\s.,!?'"\-]{4,})/;
  const obfuscationMatches = content.match(new RegExp(obfuscationPattern.source, 'g')) || [];
  if (obfuscationMatches.length > 10) {
    throw new Error(`File ${fileName} contains excessive special characters (possible obfuscation).`);
  }

  // Strip any remaining control characters except standard whitespace
  const sanitized = content.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  return sanitized;
}

dotenv.config({ path: `.env.local` });

// Validate that all required credentials are supplied via environment variables only
const REQUIRED_ENV_VARS = ["SUPABASE_URL", "SUPABASE_PRIVATE_KEY", "OPENAI_API_KEY"];
for (const envVar of REQUIRED_ENV_VARS) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}. Credentials must be provided via .env.local and must never be hardcoded.`);
  }
}

/**
 * Sanitizes text content to prevent prompt injection attacks before
 * passing it to the AI embedding API.
 * Removes/neutralizes:
 *  - Hidden prompt injection patterns (e.g. "ignore previous instructions")
 *  - Base64-encoded blobs that could decode to malicious prompts
 *  - Shell command sequences
 */
function sanitizeContent(text) {
  if (typeof text !== "string") return "";

  // Remove null bytes and non-printable control characters (except common whitespace)
  let sanitized = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Detect and strip base64-encoded blobs (runs of 40+ base64 chars)
  sanitized = sanitized.replace(/[A-Za-z0-9+/]{40,}={0,2}/g, "[REDACTED_BASE64]");

  // Remove shell command patterns
  const shellPatterns = [
    /`[^`]*`/g,                          // backtick command substitution
    /\$\([^)]*\)/g,                      // $(...) command substitution
    /;\s*(rm|curl|wget|bash|sh|python|perl|ruby|nc|ncat|netcat|eval|exec)\b[^;\n]*/gi,
    /&&\s*(rm|curl|wget|bash|sh|python|perl|ruby|nc|ncat|netcat|eval|exec)\b[^&\n]*/gi,
    /\|\s*(rm|curl|wget|bash|sh|python|perl|ruby|nc|ncat|netcat|eval|exec)\b[^|\n]*/gi,
  ];
  for (const pattern of shellPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED_CMD]");
  }

  // Detect prompt injection phrases and neutralize them
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/gi,
    /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/gi,
    /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/gi,
    /you\s+are\s+now\s+(a\s+)?(?!a\s+companion)/gi,
    /new\s+(system\s+)?prompt\s*:/gi,
    /\[system\]/gi,
    /\[assistant\]/gi,
    /<\s*system\s*>/gi,
    /<\s*\/\s*system\s*>/gi,
    /###\s*system/gi,
    /###\s*instruction/gi,
  ];
  for (const pattern of injectionPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED_INJECTION]");
  }

  return sanitized;
}

const COMPANIONS_BASE_DIR = path.resolve("companions");
const fileNames = fs.readdirSync(COMPANIONS_BASE_DIR);
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (fileName.endsWith(".txt")) {
      const filePath = path.resolve(COMPANIONS_BASE_DIR, fileName);
      if (!filePath.startsWith(COMPANIONS_BASE_DIR + path.sep) && filePath !== COMPANIONS_BASE_DIR) {
        throw new Error(`Path traversal detected for file: ${fileName}`);
      }
      const rawContent = fs.readFileSync(filePath, "utf8");
      const fileContent = sanitizeFileContent(rawContent, fileName);
      const lastSection = sanitizeContent(
        fileContent.split("###ENDSEEDCHAT###").slice(-1)[0]
      );
      const splitDocs = await splitter.createDocuments([lastSection]);
      return splitDocs.map((doc) => {
        return new Document({
          metadata: { fileName },
          pageContent: doc.pageContent,
        });
      });
    }
  })
);

/**
 * Sanitize a text string before sending it to the embedding API.
 * - Removes null bytes and non-printable ASCII control characters (except normal whitespace).
 * - Trims leading/trailing whitespace.
 * - Enforces a maximum character length to prevent oversized payloads.
 */
const MAX_CHUNK_LENGTH = 2000;

function sanitizeText(text) {
  if (typeof text !== "string") return "";
  // Remove null bytes and non-printable control characters (keep \t, \n, \r)
  let sanitized = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Trim whitespace
  sanitized = sanitized.trim();
  // Enforce maximum length
  if (sanitized.length > MAX_CHUNK_LENGTH) {
    sanitized = sanitized.slice(0, MAX_CHUNK_LENGTH);
  }
  return sanitized;
}

function sanitizeDocument(doc) {
  if (!doc || typeof doc.pageContent !== "string") return null;
  const cleanContent = sanitizeText(doc.pageContent);
  if (!cleanContent) return null;
  return new Document({
    metadata: doc.metadata,
    pageContent: cleanContent,
  });
}

const auth = {
  detectSessionInUrl: false,
  persistSession: false,
  autoRefreshToken: false,
};

const client = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_PRIVATE_KEY,
  { auth }
);

// Patterns that indicate dynamic code execution primitives in LLM output
const DANGEROUS_PATTERNS = [
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bnew\s+Function\s*\(/i,
  /\bsetTimeout\s*\(\s*['"`]/i,
  /\bsetInterval\s*\(\s*['"`]/i,
  /\bimport\s*\(/i,
  /\brequire\s*\(/i,
  /\bprocess\.binding\s*\(/i,
  /\bchild_process/i,
  /\bvm\.runInThisContext\s*\(/i,
  /\bvm\.runInNewContext\s*\(/i,
  /\bvm\.runInContext\s*\(/i,
];

/**
 * Validates and sanitizes a document's pageContent from LLM output.
 * Throws if dangerous dynamic code execution primitives are detected.
 * @param {Document} doc
 * @returns {Document}
 */
function validateAndSanitizeDoc(doc) {
  if (!doc || typeof doc.pageContent !== "string") {
    throw new Error("Invalid document: pageContent must be a string.");
  }
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(doc.pageContent)) {
      throw new Error(
        `Dangerous pattern detected in LLM output (matched: ${pattern}). ` +
        `Document from file "${doc.metadata?.fileName}" was rejected.`
      );
    }
  }
  // Sanitize: remove null bytes and non-printable control characters
  const sanitizedContent = doc.pageContent
    .replace(/\0/g, "")
    .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  return new Document({
    metadata: doc.metadata,
    pageContent: sanitizedContent,
  });
}

const rawDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
const safeDocs = rawDocs.map((doc) => validateAndSanitizeDoc(doc));

const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
console.log(
  JSON.stringify({
    event: "llm_interaction_start",
    model: "OpenAIEmbeddings",
    action: "SupabaseVectorStore.fromDocuments",
    documentCount: filteredDocs.length,
    timestamp: new Date().toISOString(),
  })
);
const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
const MODEL_ID = "text-embedding-ada-002"; // OpenAIEmbeddings default model
const inputHash = crypto
  .createHash("sha256")
  .update(JSON.stringify(filteredDocs.map((d) => d.pageContent)))
  .digest("hex");
const principal = process.env.AUDIT_PRINCIPAL || process.env.USER || "unknown";
const auditLogPath = process.env.AUDIT_LOG_PATH || "audit_trail.jsonl";

const auditRecordStart = {
  event: "embedding_operation_start",
  timestamp: new Date().toISOString(),
  principal,
  model_id: MODEL_ID,
  input_document_count: filteredDocs.length,
  input_hash_sha256: inputHash,
  target_table: "documents",
  supabase_url: process.env.SUPABASE_URL,
};
appendFileSync(auditLogPath, JSON.stringify(auditRecordStart) + "\n", "utf8");
console.log("[AUDIT]", JSON.stringify(auditRecordStart));

try {
  await SupabaseVectorStore.fromDocuments(
    filteredDocs,
    new OpenAIEmbeddings({
    openAIApiKey: process.env.OPENAI_API_KEY,
    modelName: "text-embedding-ada-002", // Pinned model version — required by model registry policy
  }),
    {
      client,
      tableName: "documents",
    }
  );

  const auditRecordEnd = {
    event: "embedding_operation_success",
    timestamp: new Date().toISOString(),
    principal,
    model_id: MODEL_ID,
    input_hash_sha256: inputHash,
    target_table: "documents",
  };
  appendFileSync(auditLogPath, JSON.stringify(auditRecordEnd) + "\n", "utf8");
  console.log("[AUDIT]", JSON.stringify(auditRecordEnd));
} catch (err) {
  const auditRecordError = {
    event: "embedding_operation_failure",
    timestamp: new Date().toISOString(),
    principal,
    model_id: MODEL_ID,
    input_hash_sha256: inputHash,
    target_table: "documents",
    error: err.message,
  };
  appendFileSync(auditLogPath, JSON.stringify(auditRecordError) + "\n", "utf8");
  console.error("[AUDIT]", JSON.stringify(auditRecordError));
  throw err;
}
console.log(
  JSON.stringify({
    event: "llm_interaction_end",
    model: "OpenAIEmbeddings",
    action: "SupabaseVectorStore.fromDocuments",
    status: "success",
    documentCount: filteredDocs.length,
    timestamp: new Date().toISOString(),
  })
);
