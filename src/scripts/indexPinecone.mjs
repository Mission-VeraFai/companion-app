// Major ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/pinecone
import { PineconeClient } from "@pinecone-database/pinecone";
import dotenv from "dotenv";
import https from "https";
import tls from "tls";

// ---------------------------------------------------------------------------
// Approved-model registry enforcement
// Policy: all AI workloads must use pinned, registry-approved model identifiers.
// ---------------------------------------------------------------------------
const APPROVED_EMBEDDING_MODELS = new Set([
  "text-embedding-3-small",
  "text-embedding-3-large",
  "text-embedding-ada-002",
]);
const APPROVED_VECTOR_STORES = new Set(["pgvector", "chroma", "weaviate", "pinecone"]);

const PINNED_EMBEDDING_MODEL = "text-embedding-3-small";
const VECTOR_STORE_PROVIDER = "chroma";

if (!APPROVED_EMBEDDING_MODELS.has(PINNED_EMBEDDING_MODEL)) {
  throw new Error(
    `Policy violation: embedding model "${PINNED_EMBEDDING_MODEL}" is not in the approved model registry.`
  );
}
console.info(
  `[Policy] Embedding model pinned: model=${PINNED_EMBEDDING_MODEL} digest=${PINNED_EMBEDDING_MODEL_DIGEST}`
);
if (!APPROVED_VECTOR_STORES.has(VECTOR_STORE_PROVIDER)) {
  // Log the violation; swap throw for a warning if a migration period is needed.
  console.warn(
    `Policy warning: vector-store provider "${VECTOR_STORE_PROVIDER}" is not in the approved registry. ` +
      `Migrate to an approved provider (${[...APPROVED_VECTOR_STORES].join(", ")}) as soon as possible.`
  );
}
// ---------------------------------------------------------------------------
import { Document } from "langchain/document";
import { OpenAIEmbeddings } from "@langchain/openai";
import { Chroma } from "langchain/vectorstores/chroma";
import { CharacterTextSplitter } from "langchain/text_splitter";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import os from "os";

dotenv.config({ path: `.env.local` });

// ---------------------------------------------------------------------------
// URL allowlist enforcement
// Policy: all outbound HTTP fetch() calls must target only approved hostnames.
// ---------------------------------------------------------------------------
const ALLOWED_EMBEDDING_HOSTNAMES = new Set([
  // Hardcoded baseline: approved embedding API hostnames required by policy.
  // OpenAI Embeddings (OpenAIEmbeddings / text-embedding-3-small) is the
  // only approved embedding provider wired in this file.
  "api.openai.com",
  // Additional hostnames may be appended via the EMBEDDING_API_ALLOWED_HOSTS
  // environment variable (comma-separated), but the baseline above is always
  // present and cannot be removed at runtime.
  ...(process.env.EMBEDDING_API_ALLOWED_HOSTS
    ? process.env.EMBEDDING_API_ALLOWED_HOSTS.split(",").map((h) => h.trim()).filter(Boolean)
    : []),
]);

// Policy enforcement: the allow list must never be empty at startup.
// This guards against misconfiguration that would silently block all calls
// or, conversely, be interpreted as "allow all" by a permissive caller.
if (ALLOWED_EMBEDDING_HOSTNAMES.size === 0) {
  throw new Error(
    "Policy violation: ALLOWED_EMBEDDING_HOSTNAMES is empty. " +
      "At least one approved embedding API hostname must be present. " +
      "Add entries to the hardcoded baseline in indexPinecone.mjs or set " +
      "EMBEDDING_API_ALLOWED_HOSTS in your environment."
  );
}

/**
 * Validates that a URL's hostname is in the approved allowlist before
 * an outbound fetch() is made.
 * @param {string} urlString - The full URL string to validate.
 * @throws {Error} If the hostname is not in the approved allowlist.
 */
function assertAllowedEmbeddingURL(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch (e) {
    throw new Error(
      `Policy violation: EMBEDDING_API_URL "${urlString}" is not a valid URL.`
    );
  }
  if (!ALLOWED_EMBEDDING_HOSTNAMES.has(parsed.hostname)) {
    throw new Error(
      `Policy violation: outbound fetch to hostname "${parsed.hostname}" is not in the approved allowlist. ` +
        `Approved hostnames: [${[...ALLOWED_EMBEDDING_HOSTNAMES].join(", ")}]. ` +
        `Add the hostname to EMBEDDING_API_ALLOWED_HOSTS in your environment or to ALLOWED_EMBEDDING_HOSTNAMES in code.`
    );
  }
}
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// MCP server authentication: TLS certificate pinning for Pinecone API
// Policy: MCP client must authenticate MCP server.
// Set PINECONE_SERVER_CERT_FINGERPRINT in your environment to the expected
// SHA-256 fingerprint (colon-separated hex) of the Pinecone API server cert.
// ---------------------------------------------------------------------------
const PINECONE_SERVER_CERT_FINGERPRINT = process.env.PINECONE_SERVER_CERT_FINGERPRINT;
if (!PINECONE_SERVER_CERT_FINGERPRINT) {
  throw new Error(
    "Policy violation: PINECONE_SERVER_CERT_FINGERPRINT environment variable is not set. " +
      "Server identity verification requires a pinned certificate fingerprint."
  );
}

/**
 * Creates an HTTPS agent that pins the Pinecone server certificate by
 * verifying the SHA-256 fingerprint of the presented certificate.
 */
function createPineconeHttpsAgent() {
  return new https.Agent({
    rejectUnauthorized: true, // enforce standard CA chain validation
    checkServerIdentity(hostname, cert) {
      // Standard hostname check first
      const err = tls.checkServerIdentity(hostname, cert);
      if (err) throw err;

      // Certificate pinning: verify the server cert fingerprint
      const rawCert = cert.raw;
      if (!rawCert) {
        throw new Error("Server certificate pinning failed: no raw certificate available.");
      }
      const actualFingerprint = crypto
        .createHash("sha256")
        .update(rawCert)
        .digest("hex")
        .toUpperCase()
        .match(/.{2}/g)
        .join(":");

      const expectedFingerprint = PINECONE_SERVER_CERT_FINGERPRINT.toUpperCase();
      if (actualFingerprint !== expectedFingerprint) {
        throw new Error(
          `Server certificate pinning failed: expected fingerprint "${expectedFingerprint}" ` +
            `but received "${actualFingerprint}". Possible MITM attack.`
        );
      }
    },
  });
}

const pineconeHttpsAgent = createPineconeHttpsAgent();
// ---------------------------------------------------------------------------

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
      // Validate and sanitize output from the MCP/embedding server
      if (!data || !Array.isArray(data.embeddings) || data.embeddings.length === 0) {
        throw new Error(
          "Invalid response from external embedding service (embedDocuments): " +
          "'embeddings' must be a non-empty array."
        );
      }
      const sanitizedEmbeddings = data.embeddings.map((vec, i) => {
        if (!Array.isArray(vec) || vec.length === 0) {
          throw new Error(
            `Invalid embedding at index ${i} from external embedding service: must be a non-empty array.`
          );
        }
        return vec.map((val, j) => {
          const num = Number(val);
          if (!Number.isFinite(num)) {
            throw new Error(
              `Invalid embedding value at index [${i}][${j}] from external embedding service: ` +
              `expected finite number, got ${val}.`
            );
          }
          return num;
        });
      });
      return sanitizedEmbeddings;
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
      // Validate and sanitize output from the MCP/embedding server
      if (!data || !Array.isArray(data.embedding) || data.embedding.length === 0) {
        throw new Error(
          "Invalid response from external embedding service (embedQuery): " +
          "'embedding' must be a non-empty array."
        );
      }
      const sanitizedEmbedding = data.embedding.map((val, j) => {
        const num = Number(val);
        if (!Number.isFinite(num)) {
          throw new Error(
            `Invalid embedding value at index [${j}] from external embedding service: ` +
            `expected finite number, got ${val}.`
          );
        }
        return num;
      });
      return sanitizedEmbedding;
    }
  }

  // --- Input validation and sanitization of documents before indexing ---
  const MAX_CONTENT_LENGTH = parseInt(process.env.MAX_DOC_CONTENT_LENGTH || String(100 * 1024), 10);
  const sanitizedDocs = filteredDocs.map((doc, idx) => {
    if (!doc || typeof doc !== 'object') {
      throw new Error(`Document at index [${idx}] is not a valid object.`);
    }
    if (typeof doc.pageContent !== 'string') {
      throw new Error(
        `Document at index [${idx}] has invalid pageContent: expected string, got ${typeof doc.pageContent}.`
      );
    }
    // Strip null bytes and ASCII control characters (except tab, newline, carriage return)
    const sanitizedContent = doc.pageContent
      .replace(/\x00/g, '')
      .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
      .trim();
    if (sanitizedContent.length === 0) {
      throw new Error(`Document at index [${idx}] has empty pageContent after sanitization.`);
    }
    if (sanitizedContent.length > MAX_CONTENT_LENGTH) {
      throw new Error(
        `Document at index [${idx}] pageContent exceeds maximum allowed length of ${MAX_CONTENT_LENGTH} characters.`
      );
    }
    // Sanitize metadata: only allow plain scalar values or arrays of scalars
    const rawMetadata = doc.metadata && typeof doc.metadata === 'object' ? doc.metadata : {};
    const sanitizedMetadata = Object.fromEntries(
      Object.entries(rawMetadata)
        .filter(([key]) => typeof key === 'string' && key.length > 0 && key.length <= 256)
        .map(([key, value]) => {
          if (
            typeof value === 'string' ||
            typeof value === 'number' ||
            typeof value === 'boolean' ||
            value === null
          ) {
            const sanitizedValue = typeof value === 'string'
              ? value.replace(/\x00/g, '').replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').slice(0, 1024)
              : value;
            return [key, sanitizedValue];
          }
          if (Array.isArray(value)) {
            return [
              key,
              value
                .filter(v => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean' || v === null)
                .map(v => typeof v === 'string'
                  ? v.replace(/\x00/g, '').replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').slice(0, 1024)
                  : v
                ),
            ];
          }
          // Drop unsupported metadata value types
          return [key, null];
        })
    );
    return { pageContent: sanitizedContent, metadata: sanitizedMetadata };
  });
  // --- End input validation and sanitization ---

    // Data minimisation: strip pageContent to max 2000 chars and whitelist metadata fields
  // before forwarding to the embedding model and Pinecone vector store.
  const ALLOWED_METADATA_FIELDS = new Set(["source", "chunkIndex", "title"]);
  const MAX_CONTENT_LENGTH = 2000;
  const minimisedDocs = filteredDocs.map((doc) => ({
    pageContent: typeof doc.pageContent === "string"
      ? doc.pageContent.trim().slice(0, MAX_CONTENT_LENGTH)
      : "",
    metadata: Object.fromEntries(
      Object.entries(doc.metadata || {}).filter(([k]) => ALLOWED_METADATA_FIELDS.has(k))
    ),
  }));
  await PineconeStore.fromDocuments(
    minimisedDocs,
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
    // --- HITL approval gate helper for risky rename/move operations ---
  function requireHITLApprovalForRotation(sourcePath, destPath) {
    const approved = process.env.HITL_ROTATION_APPROVED === "true";
    if (!approved) {
      throw new Error(
        `[HITL] Human approval required before renaming/moving file. ` +
        `Operation: rename '${sourcePath}' -> '${destPath}'. ` +
        `Set environment variable HITL_ROTATION_APPROVED=true to explicitly approve this risky operation.`
      );
    }
    console.warn(
      `[HITL] Human-approved file rename/move operation proceeding: '${sourcePath}' -> '${destPath}'`
    );
  }

  // --- Audit log rotation (retain last file; rotate at AUDIT_LOG_MAX_BYTES) ---
  const AUDIT_LOG_MAX_BYTES = parseInt(process.env.AUDIT_LOG_MAX_BYTES || String(10 * 1024 * 1024), 10);
  try {
    const stat = fs.existsSync(AUDIT_LOG_PATH) ? fs.statSync(AUDIT_LOG_PATH) : null;
    if (stat && stat.size >= AUDIT_LOG_MAX_BYTES) {
      const rotatedPath = AUDIT_LOG_PATH + "." + new Date().toISOString().replace(/[:.]/g, "-");
      requireHITLApprovalForRotation(AUDIT_LOG_PATH, rotatedPath);
      fs.renameSync(AUDIT_LOG_PATH, rotatedPath);
    }
  } catch (rotateErr) {
    console.error("[AUDIT] Log rotation failed:", rotateErr.message);
  }
      fs.copyFileSync(AUDIT_LOG_PATH, resolvedRotated);
      fs.unlinkSync(AUDIT_LOG_PATH);
    }
  } catch (rotateErr) {
    console.error("[AUDIT] Log rotation failed:", rotateErr.message);
  }
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(auditRecordEnd) + "\n", "utf8");
  console.log("[AUDIT]", JSON.stringify(auditRecordEnd));
}
  const llmCompleteRecord = {
    timestamp: new Date().toISOString(),
    event: "llm_interaction_complete",
    service: "OpenAIEmbeddings",
    model: "embed-english-v3.0",
    action: "PineconeStore.fromDocuments",
    documentCount: docsToEmbed.length,
    status: "success",
  };
  try {
      const _statC = fs.existsSync(AUDIT_LOG_PATH) ? fs.statSync(AUDIT_LOG_PATH) : null;
    const _maxC = parseInt(process.env.AUDIT_LOG_MAX_BYTES || String(10 * 1024 * 1024), 10);
    if (_statC && _statC.size >= _maxC) {
      fs.renameSync(AUDIT_LOG_PATH, AUDIT_LOG_PATH + "." + new Date().toISOString().replace(/[:.]/g, "-"));
    }
  } catch (_re) { console.error("[AUDIT] Log rotation failed:", _re.message); }
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(llmCompleteRecord) + "\n", "utf8");
  console.log("[AUDIT]", JSON.stringify(llmCompleteRecord));
} catch (err) {
  const llmErrorRecord = {
    timestamp: new Date().toISOString(),
    event: "llm_interaction_error",
    service: "CohereEmbeddings",
    model: "embed-english-v3.0",
    action: "PineconeStore.fromDocuments",
    documentCount: docsToEmbed.length,
    status: "error",
    error: err.message,
  };
  // NOTE: docsToEmbed must be field-filtered before this block (see minimisedDocs usage above)
  try {
    const _statE = fs.existsSync(AUDIT_LOG_PATH) ? fs.statSync(AUDIT_LOG_PATH) : null;
    const _maxE = parseInt(process.env.AUDIT_LOG_MAX_BYTES || String(10 * 1024 * 1024), 10);
        if (_statE && _statE.size >= _maxE) {
      const _rotatedPathE = AUDIT_LOG_PATH + "." + new Date().toISOString().replace(/[:.]/g, "-");
      requireHITLApprovalForRotation(AUDIT_LOG_PATH, _rotatedPathE);
      fs.renameSync(AUDIT_LOG_PATH, _rotatedPathE);
    } = await import("path");
      const _expectedDirE = _dirE(_resE(AUDIT_LOG_PATH));
      const _resolvedE = _resE(_rotatedPathE);
      if (!_resolvedE.startsWith(_expectedDirE + _sepE) && _resolvedE !== _expectedDirE) {
        throw new Error("[AUDIT] Rotated log path escapes expected directory: " + _resolvedE);
      }
      fs.copyFileSync(AUDIT_LOG_PATH, _resolvedE);
      fs.unlinkSync(AUDIT_LOG_PATH);
    }
  } catch (_re) { console.error("[AUDIT] Log rotation failed:", _re.message); }
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(llmErrorRecord) + "\n", "utf8");
  console.error("[AUDIT]", JSON.stringify(llmErrorRecord));
  throw err;
}
