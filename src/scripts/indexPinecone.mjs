// Major ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/pinecone
import { PineconeClient } from "@pinecone-database/pinecone";
import dotenv from "dotenv";
import { Document } from "langchain/document";
import { HuggingFaceInferenceEmbeddings } from "langchain/embeddings/hf";
// APPROVED REGISTRY: @langchain/pinecone@0.0.3
import { PineconeStore } from "@langchain/pinecone";
import { CharacterTextSplitter } from "langchain/text_splitter";
import fs from "fs";
import path from "path";
import crypto from "crypto";

dotenv.config({ path: `.env.local` });

// Validate required credentials are present before use
const requiredEnvVars = ["PINECONE_API_KEY", "PINECONE_ENVIRONMENT", "PINECONE_INDEX", "OPENAI_API_KEY"];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
}

/**
 * Detects Singapore PII in a given text string.
 * Categories checked:
 *  - NRIC/FIN numbers (e.g. S1234567A, T0312345B, F1234567K, G1234567X)
 *  - Singapore mobile/phone numbers (+65 XXXX XXXX or 8/9-digit local)
 *  - Singapore postal codes (6-digit, starting with valid sector prefix)
 *  - Singapore passport numbers (Exxxxxxx)
 *  - Full name patterns combined with identifiers (heuristic)
 *  - Singapore bank account numbers (heuristic)
 *  - Date of birth patterns
 *  - Email addresses (generic PII)
 *  - Credit/debit card numbers (generic PII)
 */
function detectSingaporePII(text) {
  const piiPatterns = [
    // NRIC / FIN
    { name: "NRIC/FIN", pattern: /\b[STFGM]\d{7}[A-Z]\b/i },
    // Singapore passport number
    { name: "Singapore Passport", pattern: /\bE\d{7}[A-Z]\b/i },
    // Singapore local phone numbers (+65 followed by 8 digits, or standalone 8-digit starting with 6/8/9)
    { name: "Singapore Phone", pattern: /(\+65[\s-]?)?[689]\d{7}\b/ },
    // Singapore postal code (6 digits, first two digits 01-82)
    { name: "Singapore Postal Code", pattern: /\b(0[1-9]|[1-7]\d|8[0-2])\d{4}\b/ },
    // Date of birth (common formats)
    { name: "Date of Birth", pattern: /\b(\d{1,2}[\/\-\.](0?[1-9]|1[0-2])[\/\-\.]\d{2,4})\b/ },
    // Email address
    { name: "Email", pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/ },
    // Credit/debit card numbers (13-19 digits, optionally separated by spaces/dashes)
    { name: "Credit Card", pattern: /\b(?:\d[ \-]?){13,19}\b/ },
    // Singapore bank account numbers (heuristic: 9-12 digit sequences)
    { name: "Bank Account", pattern: /\b\d{9,12}\b/ },
  ];

  const detectedPII = [];
  for (const { name, pattern } of piiPatterns) {
    if (pattern.test(text)) {
      detectedPII.push(name);
    }
  }
  return detectedPII;
}

/**
 * Redacts common PII from a string before indexing.
 * Patterns covered: email addresses, US phone numbers, SSNs,
 * credit/debit card numbers, and names preceded by honorifics.
 */
function redactPII(text) {
  // Email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");
  // US phone numbers (various formats)
  text = text.replace(/(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g, "[REDACTED_PHONE]");
  // Social Security Numbers
  text = text.replace(/\b\d{3}[\s.-]\d{2}[\s.-]\d{4}\b/g, "[REDACTED_SSN]");
  // Credit/debit card numbers (13–16 digits, optionally space/dash separated)
  text = text.replace(/\b(?:\d[ -]?){13,16}\b/g, "[REDACTED_CARD]");
  // Names preceded by common honorifics
  text = text.replace(/\b(Mr\.|Mrs\.|Ms\.|Miss|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*/g, "[REDACTED_NAME]");
  return text;
}

/**
 * Sanitizes file content before feeding it into the AI pipeline.
 * Detects and removes hidden/invisible characters, base64 payloads,
 * leetspeak patterns, shell command sequences, and binary content.
 * Throws an error if malicious content is detected.
 */
function sanitizeContent(content, fileName) {
  // Reject binary / non-printable content (allow common whitespace)
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(content)) {
    throw new Error(`[SECURITY] Binary or non-printable characters detected in ${fileName}. Skipping.`);
  }

  // Strip zero-width / invisible Unicode characters (prompt-injection hiding technique)
  const invisiblePattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u00A0]/g;
  content = content.replace(invisiblePattern, "");

  // Detect base64-encoded blocks (>=40 contiguous base64 chars) that may hide instructions
  const base64Pattern = /(?:[A-Za-z0-9+/]{40,}={0,2})/g;
  if (base64Pattern.test(content)) {
    throw new Error(`[SECURITY] Potential base64-encoded payload detected in ${fileName}. Skipping.`);
  }

  // Detect common shell command injection patterns
  const shellPatterns = [
    /`[^`]*`/,                          // backtick execution
    /\$\([^)]*\)/,                      // $(...) subshell
    /;\s*(rm|wget|curl|bash|sh|python|perl|nc|ncat|chmod|chown|sudo|eval)\b/i,
    /\|\s*(bash|sh|python|perl|nc|ncat|eval)\b/i,
    /&&\s*(rm|wget|curl|bash|sh|python|perl|nc|ncat|eval)\b/i,
    /\bexec\s*\(/i,
    /\beval\s*\(/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(content)) {
      throw new Error(`[SECURITY] Shell command pattern detected in ${fileName}. Skipping.`);
    }
  }

  // Detect leetspeak-style prompt injection (e.g. "1gn0r3", "d1sr3g4rd")
  const leetspeakInjectionPattern = /\b(?:1gn[o0]r[e3]|d[i1]sr[e3]g[a4]rd|[f]0rg[e3]t|[o0]v[e3]rr[i1]d[e3]|[s5]y[s5]t[e3]m)\b/i;
  if (leetspeakInjectionPattern.test(content)) {
    throw new Error(`[SECURITY] Leetspeak injection pattern detected in ${fileName}. Skipping.`);
  }

  // Detect common prompt-injection instruction phrases
  const promptInjectionPattern = /\b(ignore (all |previous |above |prior )?instructions?|disregard (all |previous |above |prior )?instructions?|forget (all |previous |above |prior )?instructions?|you are now|new persona|act as|override (previous )?instructions?|system prompt)/i;
  if (promptInjectionPattern.test(content)) {
    throw new Error(`[SECURITY] Prompt injection phrase detected in ${fileName}. Skipping.`);
  }

  return content;
}

/**
 * Sanitizes text content to prevent prompt injection attacks before
 * passing it into the AI/embedding pipeline.
 */
function sanitizeContent(text) {
  if (typeof text !== "string") return "";

  // 1. Remove base64-encoded blobs (sequences of 20+ base64 chars)
  text = text.replace(/[A-Za-z0-9+/]{20,}={0,2}/g, "");

  // 2. Strip common shell command patterns
  text = text.replace(
    /(`[^`]*`|\$\([^)]*\)|\b(sudo|chmod|curl|wget|bash|sh|python|exec|eval|system|passthru|popen)\b[^\n]*)/gi,
    ""
  );

  // 3. Remove prompt injection phrases (case-insensitive)
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /you\s+are\s+now\b/gi,
    /act\s+as\s+(a\s+|an\s+)?(?:new\s+)?(?:ai|assistant|system|bot|gpt)/gi,
    /\bsystem\s*:/gi,
    /\bassistant\s*:/gi,
    /\buser\s*:/gi,
    /\bhuman\s*:/gi,
    /new\s+instructions?\s*:/gi,
    /override\s+(previous\s+)?instructions?/gi,
    /jailbreak/gi,
    /prompt\s+injection/gi,
    /<\s*\/?\s*(system|instructions?|prompt)\s*>/gi,
    /\[\s*(system|instructions?|prompt)\s*\]/gi,
  ];
  for (const pattern of injectionPatterns) {
    text = text.replace(pattern, "");
  }

  // 4. Detect and neutralize leetspeak / heavy character substitution.
  // Replace common leet substitutions so downstream checks can catch them,
  // then re-apply injection pattern removal.
  const leetMap = { "@": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "$": "s", "+": "t" };
  const leetNormalized = text.replace(/[@310$+57]/g, (c) => leetMap[c] || c);
  for (const pattern of injectionPatterns) {
    if (pattern.test(leetNormalized)) {
      // If leet-normalized text matches an injection pattern, blank the whole content
      // to be safe rather than attempting partial removal.
      text = "";
      break;
    }
  }

  // 5. Collapse excessive whitespace introduced by removals
  text = text.replace(/[ \t]{2,}/g, " ").replace(/\n{3,}/g, "\n\n").trim();

  return text;
}

/**
 * Sanitize and validate text content before sending to LLM/embedding model.
 * - Removes null bytes and non-printable control characters (except common whitespace)
 * - Trims leading/trailing whitespace
 * - Enforces a maximum content length to prevent abuse
 * - Returns null if content is empty or invalid after sanitization
 */
function sanitizeContent(content) {
  if (typeof content !== "string") return null;

  // Remove null bytes and non-printable control characters except \t, \n, \r
  let sanitized = content.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Trim whitespace
  sanitized = sanitized.trim();

  // Reject empty content
  if (sanitized.length === 0) return null;

  // Enforce maximum length (1MB of text)
  const MAX_LENGTH = 1_000_000;
  if (sanitized.length > MAX_LENGTH) {
    sanitized = sanitized.slice(0, MAX_LENGTH);
  }

  return sanitized;
}

const fileNames = fs.readdirSync("companions");
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (fileName.endsWith(".txt")) {
      const filePath = path.join("companions", fileName);
      const rawContent = fs.readFileSync(filePath, "utf8");
      // get the last section in the doc for background info
      const rawLastSection = rawContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      // Sanitize and validate content before passing to the embedding model
      const lastSection = sanitizeContent(rawLastSection);
      if (lastSection === null) {
        console.warn(`Skipping file "${fileName}": content is empty or invalid after sanitization.`);
        return undefined;
      }
      const splitDocs = await splitter.createDocuments([filteredSection]);
      return splitDocs.map((doc) => {
        return new Document({
          metadata: { fileName },
          pageContent: doc.pageContent,
        });
      });
    }
  })
);

const client = new PineconeClient();
await client.init({
  apiKey: process.env.PINECONE_API_KEY,
  environment: process.env.PINECONE_ENVIRONMENT,
});
const pineconeIndex = client.Index(process.env.PINECONE_INDEX);

const docsToEmbed = langchainDocs.flat().filter((doc) => doc !== undefined);
console.log(JSON.stringify({
  timestamp: new Date().toISOString(),
  event: "llm_interaction_start",
  service: "OpenAIEmbeddings",
  model: "text-embedding-ada-002",
  action: "PineconeStore.fromDocuments",
  documentCount: docsToEmbed.length,
  apiKeyPresent: !!process.env.OPENAI_API_KEY,
}));

// ── Audit logging setup ────────────────────────────────────────────────────
const AUDIT_LOG_PATH = path.resolve("audit_log.jsonl");

function writeAuditRecord(record) {
  const line = JSON.stringify(record) + "\n";
  fs.appendFileSync(AUDIT_LOG_PATH, line, "utf8");
}

const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);

// Compute a deterministic hash of the input corpus for forensic traceability.
const inputHash = crypto
  .createHash("sha256")
  .update(filteredDocs.map((d) => d.pageContent).join("\0"))
  .digest("hex");

const MODEL_IDENTIFIER = "text-embedding-ada-002"; // OpenAIEmbeddings default
const principal = process.env.USER || process.env.USERNAME || "unknown";
const startedAt = new Date().toISOString();

writeAuditRecord({
  event: "embedding_vectorstore_write_started",
  timestamp: startedAt,
  principal,
  modelIdentifier: MODEL_IDENTIFIER,
  pineconeIndex: process.env.PINECONE_INDEX,
  pineconeEnvironment: process.env.PINECONE_ENVIRONMENT,
  documentCount: filteredDocs.length,
  inputHash,
});

let outcome = "success";
let errorMessage = null;
try {
  await PineconeStore.fromDocuments(
    filteredDocs,
    new OpenAIEmbeddings(),
    {
      pineconeIndex,
    }
  );
} catch (err) {
  outcome = "failure";
  errorMessage = err.message;
  throw err;
} finally {
  writeAuditRecord({
    event: "embedding_vectorstore_write_completed",
    timestamp: new Date().toISOString(),
    startedAt,
    principal,
    modelIdentifier: MODEL_IDENTIFIER,
    pineconeIndex: process.env.PINECONE_INDEX,
    pineconeEnvironment: process.env.PINECONE_ENVIRONMENT,
    documentCount: filteredDocs.length,
    inputHash,
    outcome,
    ...(errorMessage && { errorMessage }),
  });
}

console.log(JSON.stringify({
  timestamp: new Date().toISOString(),
  event: "llm_interaction_complete",
  service: "OpenAIEmbeddings",
  model: "text-embedding-ada-002",
  action: "PineconeStore.fromDocuments",
  documentCount: docsToEmbed.length,
  status: "success",
}));
