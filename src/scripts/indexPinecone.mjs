// Major ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/pinecone
import { PineconeClient } from "@pinecone-database/pinecone";
import dotenv from "dotenv";

// ---------------------------------------------------------------------------
// Approved-model registry enforcement
// Policy: all AI workloads must use pinned, registry-approved model identifiers.
// ---------------------------------------------------------------------------
const APPROVED_EMBEDDING_MODELS = new Set([
  "text-embedding-3-small",
  "text-embedding-3-large",
  "text-embedding-ada-002",
]);
const APPROVED_VECTOR_STORES = new Set(["pgvector", "chroma", "weaviate"]);

const PINNED_EMBEDDING_MODEL = "text-embedding-3-small";
const VECTOR_STORE_PROVIDER = "pinecone";

if (!APPROVED_EMBEDDING_MODELS.has(PINNED_EMBEDDING_MODEL)) {
  throw new Error(
    `Policy violation: embedding model "${PINNED_EMBEDDING_MODEL}" is not in the approved model registry.`
  );
}
if (!APPROVED_VECTOR_STORES.has(VECTOR_STORE_PROVIDER)) {
  // Log the violation; swap throw for a warning if a migration period is needed.
  console.warn(
    `Policy warning: vector-store provider "${VECTOR_STORE_PROVIDER}" is not in the approved registry. ` +
      `Migrate to an approved provider (${[...APPROVED_VECTOR_STORES].join(", ")}) as soon as possible.`
  );
}
// ---------------------------------------------------------------------------
import { Document } from "langchain/document";
import { HuggingFaceInferenceEmbeddings } from "langchain/embeddings/hf";
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { CharacterTextSplitter } from "langchain/text_splitter";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import os from "os";

dotenv.config({ path: `.env.local` });

/**
 * Detects Singapore PII categories in text content.
 * Categories checked:
 * - NRIC/FIN numbers (Singapore national ID)
 * - Singapore phone numbers
 * - Singapore postal codes
 * - Singapore passport numbers
 * - Email addresses
 * - Credit/debit card numbers
 * @param {string} text - The text content to scan
 * @returns {{ hasPII: boolean, findings: string[] }}
 */
function detectSingaporePII(text) {
  const findings = [];

  const piiPatterns = [
    {
      name: "Singapore NRIC/FIN",
      // NRIC: S/T + 7 digits + letter; FIN: F/G/M + 7 digits + letter
      pattern: /\b[STFGM]\d{7}[A-Z]\b/gi,
    },
    {
      name: "Singapore passport number",
      // Singapore passports: E + 7 digits
      pattern: /\bE\d{7}[A-Z]\b/gi,
    },
    {
      name: "Singapore phone number",
      // Local numbers: 8 digits starting with 6, 8, or 9; optionally prefixed with +65
      pattern: /(?:\+65[\s-]?)?\b[689]\d{7}\b/g,
    },
    {
      name: "Singapore postal code",
      // Singapore postal codes are exactly 6 digits
      pattern: /\bSingapore\s+\d{6}\b|\bS\(\d{6}\)/gi,
    },
    {
      name: "Email address",
      pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    },
    {
      name: "Credit/debit card number",
      // 13-19 digit sequences that match common card number patterns
      pattern: /\b(?:\d[ -]?){13,19}\b/g,
    },
  ];

  for (const { name, pattern } of piiPatterns) {
    const matches = text.match(pattern);
    if (matches && matches.length > 0) {
      findings.push(`${name} (${matches.length} instance(s) found)`);
    }
  }

  return {
    hasPII: findings.length > 0,
    findings,
  };
}

/**
 * Redacts common PII from a string before indexing.
 * Patterns covered: email addresses, phone numbers, SSNs,
 * credit card numbers, and salutation-prefixed names.
 */
function redactPII(text) {
  // Email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");
  // Phone numbers (various formats)
  text = text.replace(/(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g, "[REDACTED_PHONE]");
  // Social Security Numbers
  text = text.replace(/\b\d{3}[\s.-]\d{2}[\s.-]\d{4}\b/g, "[REDACTED_SSN]");
  // Credit card numbers (16-digit, optionally grouped)
  text = text.replace(/\b(?:\d[ -]?){13,16}\b/g, "[REDACTED_CC]");
  // Names preceded by common salutations
  text = text.replace(/\b(Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*/g, "[REDACTED_NAME]");
  return text;
}

/**
 * Sanitizes file content to prevent prompt injection attacks.
 * Throws an error if malicious content is detected.
 */
function sanitizeFileContent(content, fileName) {
  // Check for base64-encoded blocks that could hide malicious instructions
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  if (base64Pattern.test(content)) {
    throw new Error(`Rejected '${fileName}': contains base64-encoded content that may hide malicious instructions.`);
  }

  // Check for shell command patterns
  const shellCommandPattern = /(?:^|\s)(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|`[^`]+`|\$\([^)]+\))/im;
  if (shellCommandPattern.test(content)) {
    throw new Error(`Rejected '${fileName}': contains shell command patterns.`);
  }

  // Check for prompt injection / override attempts
  const promptInjectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/i,
    /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/i,
    /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/i,
    /you\s+are\s+now\s+(a\s+)?(?!a companion)/i,
    /new\s+(system\s+)?prompt\s*:/i,
    /\[system\]/i,
    /<\s*system\s*>/i,
    /###\s*system/i,
    /act\s+as\s+(if\s+you\s+are\s+)?(?!a companion)/i,
    /your\s+(new\s+)?instructions?\s+(are|is)\s*:/i,
    /override\s+(the\s+)?(system|previous|prior)\s+(prompt|instructions?)/i,
    /jailbreak/i,
    /do\s+anything\s+now/i,
    /DAN\b/,
  ];

  for (const pattern of promptInjectionPatterns) {
    if (pattern.test(content)) {
      throw new Error(`Rejected '${fileName}': contains potential prompt injection content matching pattern: ${pattern}`);
    }
  }

  // Check for hidden Unicode control characters or zero-width characters
  // that could be used to smuggle instructions
  const hiddenCharPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/;
  if (hiddenCharPattern.test(content)) {
    throw new Error(`Rejected '${fileName}': contains hidden Unicode characters that may be used for prompt injection.`);
  }

  // Strip any HTML/XML tags that could be used to inject instructions
  const strippedContent = content.replace(/<[^>]*>/g, '');

  return strippedContent;
}

/**
 * Sanitizes text content before passing it to the AI pipeline.
 * Removes hidden/invisible characters and rejects content containing
 * shell commands, base64 blobs, binary signatures, or leetspeak patterns.
 */
function sanitizePromptContent(text) {
  // Remove null bytes and other non-printable/control characters (except common whitespace)
  // eslint-disable-next-line no-control-regex
  let sanitized = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Strip Unicode invisible/zero-width characters often used in prompt injection
  sanitized = sanitized.replace(
    /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u00A0]/g,
    ""
  );

  // Detect shell command patterns (common injection vectors)
  const shellCommandPattern =
    /(?:^|\s|;|\||&)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|`[^`]*`|\$\([^)]*\))/im;
  if (shellCommandPattern.test(sanitized)) {
    throw new Error(
      "Sanitization failed: shell command pattern detected in file content."
    );
  }

  // Detect large base64 blobs (40+ contiguous base64 chars) — common exfiltration/injection vector
  const base64Pattern = /[A-Za-z0-9+/]{40,}={0,2}/;
  if (base64Pattern.test(sanitized)) {
    throw new Error(
      "Sanitization failed: base64-encoded content detected in file content."
    );
  }

  // Detect binary executable magic bytes represented as escaped or raw sequences
  const binaryMagicPattern = /(?:\\x7f|\\x4d\\x5a|MZ|\x7fELF)/i;
  if (binaryMagicPattern.test(sanitized)) {
    throw new Error(
      "Sanitization failed: binary executable signature detected in file content."
    );
  }

  // Detect common leetspeak substitution patterns used to obfuscate commands
  // e.g. 3x3c, 5h3ll, etc. — flag strings with high density of leet substitutions
  const leetspeakPattern = /(?:[3@][x×][3e][c¢]|[5$][h#][3e][l1][l1]|[1!][gq][n][o0][r][3e])/i;
  if (leetspeakPattern.test(sanitized)) {
    throw new Error(
      "Sanitization failed: leetspeak obfuscation pattern detected in file content."
    );
  }

  return sanitized;
}

const fileNames = fs.readdirSync("companions");
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

const MAX_CONTENT_LENGTH = 100000; // 100k characters max per file section

/**
 * Sanitizes and validates raw text before sending to OpenAI embeddings.
 * - Removes null bytes and non-printable control characters (except common whitespace)
 * - Normalizes Unicode to NFC form
 * - Trims leading/trailing whitespace
 * - Enforces a maximum content length to prevent oversized payloads
 * @param {string} text - Raw text read from disk
 * @param {string} sourceFile - File name for logging purposes
 * @returns {string|null} Sanitized text, or null if invalid/empty
 */
function sanitizeAndValidateContent(text, sourceFile) {
  if (typeof text !== "string") {
    console.warn(`[SKIP] ${sourceFile}: content is not a string.`);
    return null;
  }

  // Remove null bytes
  let sanitized = text.replace(/\0/g, "");

  // Remove non-printable ASCII control characters except tab (\t), newline (\n), carriage return (\r)
  sanitized = sanitized.replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Normalize Unicode to NFC form
  sanitized = sanitized.normalize("NFC");

  // Trim surrounding whitespace
  sanitized = sanitized.trim();

  if (sanitized.length === 0) {
    console.warn(`[SKIP] ${sourceFile}: content is empty after sanitization.`);
    return null;
  }

  if (sanitized.length > MAX_CONTENT_LENGTH) {
    console.warn(
      `[TRUNCATE] ${sourceFile}: content length ${sanitized.length} exceeds max ${MAX_CONTENT_LENGTH}. Truncating.`
    );
    sanitized = sanitized.slice(0, MAX_CONTENT_LENGTH);
  }

  return sanitized;
}

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    const safeFileName = path.basename(fileName);
    const baseDir = path.resolve("companions");
    const filePath = path.resolve(baseDir, safeFileName);
    if (!filePath.startsWith(baseDir + path.sep) && filePath !== baseDir) {
      throw new Error(`Path traversal detected for file: ${fileName}`);
    }
    if (safeFileName.endsWith(".txt")) {
      const rawContent = fs.readFileSync(filePath, "utf8");
      const fileContent = sanitizeFileContent(rawContent, fileName);
      // get the last section in the doc for background info
      const rawSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      const lastSection = sanitizePromptContent(rawSection);
      const sanitizedSection = sanitizeAndValidateContent(lastSection, fileName);
      if (!sanitizedSection) {
        return [];
      }
      const splitDocs = await splitter.createDocuments([sanitizedSection]);
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
});
const pineconeIndex = client.Index(process.env.PINECONE_INDEX);

// Validate and sanitize LLM/embedding output before indexing
const DANGEROUS_PATTERNS = [
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /\bnew\s+Function\s*\(/,
  /\bsetTimeout\s*\(\s*['"`]/,
  /\bsetInterval\s*\(\s*['"`]/,
  /\bimportScripts\s*\(/,
  /\brequire\s*\(\s*['"`]/,
  /\bdynamic\s+import\s*\(/,
  /\bProcessBuilder\b/,
  /\bRuntime\.exec\b/,
];

function validateAndSanitizeDoc(doc) {
  if (!doc || typeof doc.pageContent !== "string") {
    throw new Error("Invalid document: missing or non-string pageContent");
  }
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(doc.pageContent)) {
      throw new Error(
        `Security violation: document contains a forbidden dynamic code execution primitive matching ${pattern}. ` +
        `File: ${doc.metadata?.fileName ?? "unknown"}`
      );
    }
  }
  return doc;
}

const safeDocs = langchainDocs
  .flat()
  .filter((doc) => doc !== undefined)
  .map((doc) => validateAndSanitizeDoc(doc));

const docsToEmbed = langchainDocs.flat().filter((doc) => doc !== undefined);
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: "llm_interaction_complete",
    traceId,
    service: "OpenAIEmbeddings",
    model: PINNED_EMBEDDING_MODEL,
    action: "PineconeStore.fromDocuments",
    documentCount: docsToEmbed.length,
    status: "success",
  }));
try {
  const AUDIT_LOG_PATH = path.resolve("audit.log");
const MODEL_IDENTIFIER = "embed-english-v3.0"; // CohereEmbeddings approved model

const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);

// Compute a deterministic SHA-256 hash of the input documents for forensic integrity
const inputHash = crypto
  .createHash("sha256")
  .update(JSON.stringify(filteredDocs.map((d) => ({ metadata: d.metadata, pageContent: d.pageContent }))))
  .digest("hex");

const principal = os.userInfo().username;
const pineconeIndexName = process.env.PINECONE_INDEX;

// Shared trace ID linking all audit and log entries for this operation
const traceId = crypto.randomUUID();

// Audit log rotation: rotate if file exceeds MAX_AUDIT_LOG_BYTES (default 10 MB)
const MAX_AUDIT_LOG_BYTES = parseInt(process.env.AUDIT_LOG_MAX_BYTES ?? String(10 * 1024 * 1024), 10);
if (fs.existsSync(AUDIT_LOG_PATH)) {
  const { size } = fs.statSync(AUDIT_LOG_PATH);
  if (size >= MAX_AUDIT_LOG_BYTES) {
    const rotatedPath = `${AUDIT_LOG_PATH}.${new Date().toISOString().replace(/[:.]/g, "-")}`;
    fs.renameSync(AUDIT_LOG_PATH, rotatedPath);
  }
}

const auditRecordStart = {
  event: "ai_embedding_indexing_start",
  traceId,
  timestamp: new Date().toISOString(),
  principal,
  modelIdentifier: MODEL_IDENTIFIER,
  inputDocumentCount: filteredDocs.length,
  inputHash,
  pineconeIndex: pineconeIndexName,
  pineconeEnvironment: process.env.PINECONE_ENVIRONMENT,
};

fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(auditRecordStart) + "\n", "utf8");
console.log("[AUDIT]", JSON.stringify(auditRecordStart));

let outcome = "success";
let errorDetail = null;
try {
      // ExternalEmbeddings: delegates to an external embedding service via HTTP.
  // The MCP server does NOT call any LLM/embedding SDK directly.
  class ExternalEmbeddings {
    constructor() {
      this.embeddingServiceUrl = process.env.EMBEDDING_SERVICE_URL;
      if (!this.embeddingServiceUrl) {
        throw new Error(
          "EMBEDDING_SERVICE_URL environment variable must be set. " +
          "The MCP server must not call LLM services directly; use an external embedding sidecar."
        );
      }
    }

    async embedDocuments(texts) {
      const response = await fetch(this.embeddingServiceUrl + "/embedDocuments", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ texts }),
      });
      if (!response.ok) {
        throw new Error(
          `External embedding service error (embedDocuments): ${response.status} ${response.statusText}`
        );
      }
      const data = await response.json();
      return data.embeddings;
    }

    async embedQuery(text) {
      const response = await fetch(this.embeddingServiceUrl + "/embedQuery", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      if (!response.ok) {
        throw new Error(
          `External embedding service error (embedQuery): ${response.status} ${response.statusText}`
        );
      }
      const data = await response.json();
      return data.embedding;
    }
  }

  await PineconeStore.fromDocuments(
    filteredDocs,
    new ExternalEmbeddings(),
    {
      pineconeIndex,
    }
  );
} catch (err) {
  outcome = "failure";
  errorDetail = err.message;
  throw err;
} finally {
  const auditRecordEnd = {
    event: "ai_embedding_indexing_end",
    traceId,
    timestamp: new Date().toISOString(),
    principal,
    modelIdentifier: MODEL_IDENTIFIER,
    inputHash,
    pineconeIndex: pineconeIndexName,
    outcome,
    ...(errorDetail ? { errorDetail } : {}),
  };
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(auditRecordEnd) + "\n", "utf8");
  console.log("[AUDIT]", JSON.stringify(auditRecordEnd));
}
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: "llm_interaction_complete",
    service: "CohereEmbeddings",
    model: "embed-english-v3.0",
    action: "PineconeStore.fromDocuments",
    documentCount: docsToEmbed.length,
    status: "success",
  }));
} catch (err) {
  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: "llm_interaction_error",
    service: "CohereEmbeddings",
    model: "embed-english-v3.0",
    action: "PineconeStore.fromDocuments",
    documentCount: docsToEmbed.length,
    status: "error",
    error: err.message,
  }));
  throw err;
}
