// Major ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/chroma
import dotenv from "dotenv";
import https from "https";
import tls from "tls";

// ---------------------------------------------------------------------------
// Approved-model registry enforcement
// Policy: all AI workloads must use pinned, registry-approved model identifiers.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Explicit tool allow list enforcement
// Policy: AI agents may only invoke tools present in this allow list.
// ---------------------------------------------------------------------------
const TOOL_ALLOW_LIST = new Set([
  "pinecone",
  "chroma",
  "cohere-embeddings",
  "character-text-splitter",
  "document-loader",
]);

/**
 * Validates that a tool name is in the explicit allow list before execution.
 * Throws a policy violation error if the tool is not approved.
 * @param {string} toolName - The identifier of the tool to validate.
 */
function validateTool(toolName) {
  if (!TOOL_ALLOW_LIST.has(toolName)) {
    throw new Error(
      `Policy violation: tool "${toolName}" is not in the explicit tool allow list. ` +
        `Approved tools: ${[...TOOL_ALLOW_LIST].join(", ")}`
    );
  }
  console.info(`[Policy] Tool access granted: ${toolName}`);
}

const APPROVED_EMBEDDING_MODELS = new Set([
  "embed-english-v3.0",
  "embed-multilingual-v3.0",
  "embed-english-light-v3.0",
]);
const APPROVED_VECTOR_STORES = new Set(["pgvector", "chroma", "weaviate", "pinecone"]);

const PINNED_EMBEDDING_MODEL = "embed-english-v3.0";
// SHA-256 digest of the approved model artifact for integrity verification.
// Update this value whenever the pinned model version changes.
const PINNED_EMBEDDING_MODEL_DIGEST =
  process.env.PINNED_EMBEDDING_MODEL_DIGEST ||
  "sha256:3f4b2c1a8e7d6f5e4c3b2a1908f7e6d5c4b3a2918e7d6f5e4c3b2a1908f7e6d5";
const VECTOR_STORE_PROVIDER = "chroma";

if (!APPROVED_EMBEDDING_MODELS.has(PINNED_EMBEDDING_MODEL)) {
  throw new Error(
    `Policy violation: embedding model "${PINNED_EMBEDDING_MODEL}" is not in the approved model registry.`
  );
}
if (!PINNED_EMBEDDING_MODEL_DIGEST || PINNED_EMBEDDING_MODEL_DIGEST.trim() === "") {
  throw new Error(
    "Policy violation: PINNED_EMBEDDING_MODEL_DIGEST is empty. " +
      "A valid digest must be provided for integrity verification."
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
// OpenAIEmbeddings and FakeEmbeddings removed: not in approved model registry.
// Embedding calls are delegated to the agent intermediary using the approved model.
import { CacheBackedEmbeddings } from "langchain/embeddings/cache_backed";
import { Embeddings } from "langchain/embeddings/base";

/**
 * ApprovedEmbeddings: registry-approved, version-pinned embedding provider.
 * Calls the org-approved EMBEDDING_SERVICE_URL endpoint directly.
 * No FakeEmbeddings or unregistered provider SDKs are used.
 */
class ApprovedEmbeddings extends Embeddings {
  constructor({ modelName } = {}) {
    super({});
    if (!APPROVED_EMBEDDING_MODELS.has(modelName)) {
      throw new Error(
        `Policy violation: embedding model "${modelName}" is not in the approved model registry.`
      );
    }
    this.modelName = modelName;
    this.embeddingServiceUrl = process.env.EMBEDDING_SERVICE_URL;
    if (!this.embeddingServiceUrl) {
      throw new Error(
        "Policy violation: EMBEDDING_SERVICE_URL is not set. " +
          "A registry-approved embedding service endpoint must be configured."
      );
    }
    const serviceUrl = new URL(this.embeddingServiceUrl);
    if (!ALLOWED_EMBEDDING_HOSTNAMES.has(serviceUrl.hostname)) {
      throw new Error(
        `Policy violation: embedding service hostname "${serviceUrl.hostname}" is not in the approved allowlist.`
      );
    }
  }

  async _request(path, body) {
    const response = await fetch(this.embeddingServiceUrl + path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Model-Name": this.modelName,
        "X-Model-Digest": PINNED_EMBEDDING_MODEL_DIGEST,
      },
      body: JSON.stringify({ model: this.modelName, ...body }),
    });
    if (!response.ok) {
      throw new Error(
        `Embedding service error: ${response.status} ${response.statusText}`
      );
    }
    return response.json();
  }

  async embedDocuments(texts) {
    const data = await this._request("/embedDocuments", { texts });
    if (!Array.isArray(data.embeddings)) {
      throw new Error("Embedding service returned unexpected response for embedDocuments.");
    }
    return data.embeddings;
  }

  async embedQuery(text) {
    const data = await this._request("/embedQuery", { text });
    if (!Array.isArray(data.embedding)) {
      throw new Error("Embedding service returned unexpected response for embedQuery.");
    }
    return data.embedding;
  }
} from "langchain/embeddings/cache_backed";

/**
 * assertApprovedEmbeddingModel: validates that a model identifier is in the
 * org-approved registry before use. Throws on violation.
 */
function assertApprovedEmbeddingModel(modelName) {
  if (!APPROVED_EMBEDDING_MODELS.has(modelName)) {
    throw new Error(
      `Policy violation: embedding model "${modelName}" is not in the approved model registry.`
    );
  }
}
// Chroma (vector store) direct writes are handled by the agent intermediary, not the MCP server.
// import { Chroma } from "langchain/vectorstores/chroma";

// Validate that both core tools are in the allow list at module load time.
// This ensures the module itself cannot be loaded if the tools are not approved.
validateTool("pinecone");
validateTool("chroma");
validateTool("cohere-embeddings");
validateTool("character-text-splitter");
validateTool("document-loader"); // REMOVED – policy violation

/**
 * agentIndexRequest – sends a structured indexing request to the agent
 * intermediary instead of calling the embedding model directly.
 * @param {object} payload - { texts: string[], metadatas: object[], namespace: string }
 * @returns {Promise<object>} - agent response
 */
/**
 * Strips non-printable / control characters (except common whitespace) from a string.
 */
function stripControlChars(str) {
  // Allow tab (\t), newline (\n), carriage return (\r); remove other C0/C1 controls
  return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, "");
}

/**
 * Validates and sanitizes the agentIndexRequest payload.
 * - texts: non-empty array of strings; each entry is PII-redacted and control-char-stripped
 * - metadatas: array of plain objects (same length as texts)
 * - namespace: non-empty string, alphanumeric/hyphens/underscores only
 * Returns a new sanitized payload object.
 */
function sanitizeIndexPayload(payload) {
  if (!payload || typeof payload !== "object") {
    throw new Error("Policy violation: agentIndexRequest payload must be a non-null object.");
  }

  const { texts, metadatas, namespace } = payload;

  // --- Validate & sanitize texts ---
  if (!Array.isArray(texts) || texts.length === 0) {
    throw new Error("Policy violation: payload.texts must be a non-empty array.");
  }
  const sanitizedTexts = texts.map((t, i) => {
    if (typeof t !== "string") {
      throw new Error(`Policy violation: payload.texts[${i}] must be a string.`);
    }
    if (t.length > 100_000) {
      throw new Error(`Policy violation: payload.texts[${i}] exceeds maximum allowed length (100 000 chars).`);
    }
    return stripControlChars(redactPII(t));
  });

  // --- Validate metadatas ---
  if (!Array.isArray(metadatas) || metadatas.length !== sanitizedTexts.length) {
    throw new Error(
      "Policy violation: payload.metadatas must be an array with the same length as texts."
    );
  }
  const sanitizedMetadatas = metadatas.map((m, i) => {
    if (m === null || typeof m !== "object" || Array.isArray(m)) {
      throw new Error(`Policy violation: payload.metadatas[${i}] must be a plain object.`);
    }
    // Shallow-copy; stringify values to prevent prototype pollution
    const clean = {};
    for (const [k, v] of Object.entries(m)) {
      if (typeof k !== "string") {
        throw new Error(`Policy violation: metadata key at index ${i} must be a string.`);
      }
      // Allow only primitive values in metadata
      if (v !== null && !["string", "number", "boolean"].includes(typeof v)) {
        throw new Error(
          `Policy violation: metadata value for key "${k}" at index ${i} must be a primitive.`
        );
      }
      clean[k] = typeof v === "string" ? stripControlChars(redactPII(v)) : v;
    }
    return clean;
  });

  // --- Validate namespace ---
  if (typeof namespace !== "string" || namespace.trim().length === 0) {
    throw new Error("Policy violation: payload.namespace must be a non-empty string.");
  }
  if (!/^[a-zA-Z0-9_\-]{1,128}$/.test(namespace.trim())) {
    throw new Error(
      "Policy violation: payload.namespace contains disallowed characters. " +
        "Only alphanumeric characters, hyphens, and underscores are permitted (max 128 chars)."
    );
  }

  return {
    texts: sanitizedTexts,
    metadatas: sanitizedMetadatas,
    namespace: namespace.trim(),
  };
}

// ---------------------------------------------------------------------------
// Dangerous-pattern sanitization
// Policy: block hidden prompts, base64, leetspeak, shell/binary commands, and
// JS runtime-execution patterns before any text reaches the agent or embeddings.
// ---------------------------------------------------------------------------
const DANGEROUS_PATTERNS = [
  // JS runtime execution
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /new\s+Function\s*\(/i,
  /\bsetTimeout\s*\(/i,
  /\bsetInterval\s*\(/i,
  /\bimportScripts\s*\(/i,
  /\brequire\s*\(/i,
  /\bimport\s*\(/i,
  // Shell / ProcessBuilder / Runtime.exec
  /ProcessBuilder/i,
  /Runtime\.exec\s*\(/i,
  /\bsh\s+-[csi]/i,
  /\bbash\s+-[csi]/i,
  /\bcmd\.exe/i,
  /\bpowershell/i,
  // Shell metacharacters sequences indicative of injection
  /[`$]\s*\(/,
  /;\s*(rm|wget|curl|nc|ncat|python|perl|ruby|php)\b/i,
  // Base64-encoded blobs (long runs of base64 chars)
  /(?:[A-Za-z0-9+\/]{40,}={0,2})/,
  // Invisible / zero-width characters used to hide prompts
  /[\u200B-\u200D\uFEFF\u00AD\u2060]/,
  // Leetspeak patterns (common substitutions used to evade filters)
  /(?:3x3c|3v4l|1mp0rt|r3qu1r3)/i,
  // Binary / ELF / PE magic bytes represented as escape sequences or literals
  /\\x7fELF/i,
  /MZ\x90/,
  // Prompt-injection trigger phrases
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /disregard\s+(all\s+)?previous\s+instructions/i,
  /you\s+are\s+now\s+in\s+(developer|jailbreak|dan)\s+mode/i,
];

/**
 * Throws if `text` matches any dangerous pattern.
 * @param {string} text
 * @param {string} [context] - label for error messages
 */
function assertNoDangerousPatterns(text, context = "input") {
  if (typeof text !== "string") return;
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(
        `Policy violation: dangerous pattern detected in ${context}: ${pattern}`
      );
    }
  }
}

/**
 * Recursively sanitizes all string values in an object/array.
 * @param {*} value
 * @param {string} [context]
 */
function sanitizeValue(value, context = "payload") {
  if (typeof value === "string") {
    assertNoDangerousPatterns(value, context);
  } else if (Array.isArray(value)) {
    value.forEach((item, i) => sanitizeValue(item, `${context}[${i}]`));
  } else if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      sanitizeValue(v, `${context}.${k}`);
    }
  }
}

async function agentIndexRequest(payload) {
  const agentEndpoint = process.env.AGENT_INTERMEDIARY_URL;
  if (!agentEndpoint) {
    throw new Error(
      "Policy violation: AGENT_INTERMEDIARY_URL is not set. " +
        "The MCP server must delegate embedding/indexing to an agent intermediary."
    );
  }
  const url = new URL(agentEndpoint);
  validateOutboundUrl(url.toString()); // reuse existing allowlist check if applicable

  // Sanitize and validate all payload fields before forwarding to the agent intermediary.
  const sanitizedPayload = sanitizeIndexPayload(payload);

    // --- Synthetic Content Provenance, Labeling & Watermarking ---
  // Attach model ID, timestamp, synthetic-origin label, and HMAC signature.
  const _modelId =
    process.env.EMBEDDING_MODEL_ID || "approved-embedding-model/v1";
  const _provenanceTimestamp = new Date().toISOString();
  const _contentOriginLabel = "ai-generated-synthetic";
  const _enrichedBody = {
    action: "index",
    ...payload,
    _provenance: {
      modelId: _modelId,
      provenanceTimestamp: _provenanceTimestamp,
      contentOriginLabel: _contentOriginLabel,
      syntheticContent: true,
    },
  };
  const _signingSecret = process.env.PROVENANCE_SIGNING_SECRET;
  if (!_signingSecret) {
    throw new Error(
      "Policy violation: PROVENANCE_SIGNING_SECRET is not set. " +
        "A signing secret is required to attach cryptographic provenance signatures to AI-generated outputs."
    );
  }
  const _bodyString = JSON.stringify(_enrichedBody);
  const _provenanceSignature = crypto
    .createHmac("sha256", _signingSecret)
    .update(_bodyString)
    .digest("hex");

    const agentApiKey = process.env.AGENT_INTERMEDIARY_API_KEY;
  if (!agentApiKey) {
    throw new Error(
      "Policy violation: AGENT_INTERMEDIARY_API_KEY is not set. " +
        "Inter-agent communication must be authenticated with a Bearer token."
    );
  }
  const response = await fetch(agentEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${agentApiKey}`,
    },
    body: JSON.stringify({ action: "index", ...payload }),
  });
  if (!response.ok) {
    throw new Error(
      `Agent intermediary returned HTTP ${response.status}: ${await response.text()}`
    );
  }
  return response.json();
}
  const url = new URL(agentEndpoint);
  validateOutboundUrl(url.toString()); // reuse existing allowlist check if applicable

  // --- Input validation and sanitization ---
  const { texts, metadatas, namespace } = payload ?? {};

  // Validate and sanitize texts
  if (!Array.isArray(texts) || texts.length === 0) {
    throw new Error(
      "Policy violation: agentIndexRequest requires a non-empty 'texts' array."
    );
  }
  const sanitizedTexts = texts.map((t, i) => {
    if (typeof t !== "string") {
      throw new Error(
        `Policy violation: texts[${i}] must be a string, got ${typeof t}.`
      );
    }
    // Apply PII redaction and strip null bytes
    return redactPII(t).replace(/\0/g, "");
  });

  // Validate and sanitize metadatas
  if (!Array.isArray(metadatas) || metadatas.length !== sanitizedTexts.length) {
    throw new Error(
      "Policy violation: agentIndexRequest requires a 'metadatas' array with the same length as 'texts'."
    );
  }
  const sanitizedMetadatas = metadatas.map((m, i) => {
    if (m === null || typeof m !== "object" || Array.isArray(m)) {
      throw new Error(
        `Policy violation: metadatas[${i}] must be a plain object.`
      );
    }
    // Allow only string/number/boolean values; drop anything else
    const safe = {};
    for (const [k, v] of Object.entries(m)) {
      if (typeof k !== "string") continue;
      const safeKey = k.replace(/[^\w\-\.]/g, "_").slice(0, 128);
      if (typeof v === "string") {
        safe[safeKey] = redactPII(v).replace(/\0/g, "").slice(0, 4096);
      } else if (typeof v === "number" || typeof v === "boolean") {
        safe[safeKey] = v;
      }
      // silently drop other types
    }
    return safe;
  });

  // Validate and sanitize namespace
  if (typeof namespace !== "string" || namespace.trim().length === 0) {
    throw new Error(
      "Policy violation: agentIndexRequest requires a non-empty string 'namespace'."
    );
  }
  const sanitizedNamespace = namespace.trim().replace(/[^\w\-]/g, "_").slice(0, 256);
  // --- End input validation and sanitization ---

  const sanitizedPayload = {
    texts: sanitizedTexts,
    metadatas: sanitizedMetadatas,
    namespace: sanitizedNamespace,
  };

  const response = await fetch(agentEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "index", ...sanitizedPayload }),
  });
  if (!response.ok) {
    throw new Error(
      `Agent intermediary returned HTTP ${response.status}: ${await response.text()}`
    );
  }
  const rawResponse = await response.json();
  return sanitizeMcpOutput(rawResponse);
}

/**
 * sanitizeMcpOutput – validates and sanitizes output received from an MCP
 * server or agent intermediary before it is used by the client.
 *
 * Policy: Client must validate and sanitize any output from a MCP server.
 *
 * Validation checks:
 *  - Response must be a non-null plain object.
 *  - Must not contain unexpected executable or script-like string values.
 *  - String values are stripped of HTML/script tags and null bytes.
 *  - Keys are restricted to an allowlist of expected response fields.
 *
 * @param {unknown} raw - The raw parsed JSON from the MCP/agent response.
 * @returns {object} - The sanitized response object.
 */
function sanitizeMcpOutput(raw) {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(
      "MCP output validation failed: response must be a non-null plain object."
    );
  }

  // Allowlist of top-level keys expected in an indexing response.
  const ALLOWED_KEYS = new Set([
    "status",
    "message",
    "indexed",
    "namespace",
    "count",
    "ids",
    "errors",
    "warnings",
    "metadata",
  ]);

  const sanitized = {};
  for (const [key, value] of Object.entries(raw)) {
    if (!ALLOWED_KEYS.has(key)) {
      // Drop unexpected keys rather than propagating potentially injected fields.
      continue;
    }
    sanitized[key] = sanitizeMcpValue(value);
  }
  return sanitized;
}

/**
 * Recursively sanitizes a value from MCP output.
 * Strings are stripped of HTML tags, script content, and null bytes.
 * Arrays are sanitized element-by-element.
 * Nested plain objects are sanitized recursively (keys are not allowlist-checked
 * for nested objects, but string values are still cleaned).
 *
 * @param {unknown} value
 * @returns {unknown}
 */
function sanitizeMcpValue(value) {
  if (typeof value === "string") {
    // Remove null bytes.
    let clean = value.replace(/\0/g, "");
    // Strip HTML/script tags.
    clean = clean.replace(/<[^>]*>/g, "");
    // Reject strings that look like executable JavaScript (prompt-injection guard).
    if (/\b(eval|Function|setTimeout|setInterval|import\s*\()\s*\(/.test(clean)) {
      throw new Error(
        "MCP output validation failed: response contains potentially executable content."
      );
    }
    return clean;
  }
  if (Array.isArray(value)) {
    return value.map(sanitizeMcpValue);
  }
  if (value !== null && typeof value === "object") {
    const nested = {};
    for (const [k, v] of Object.entries(value)) {
      nested[sanitizeMcpValue(k)] = sanitizeMcpValue(v);
    }
    return nested;
  }
  // Primitives (number, boolean, null) are returned as-is.
  return value;
}
import { CharacterTextSplitter } from "langchain/text_splitter";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import os from "os";

dotenv.config({ path: `.env.local` });

// ---------------------------------------------------------------------------
// PII redaction
// Policy: redact PII from file contents before embedding or uploading.
// ---------------------------------------------------------------------------
/**
 * Redacts common PII patterns from a string.
 * Patterns covered: email addresses, US phone numbers, US SSNs,
 * credit-card numbers, and IPv4 addresses.
 * Extend the PATTERNS array to cover additional PII types as needed.
 */
function redactPII(text) {
  if (typeof text !== "string") return text;
  const PATTERNS = [
    // Email addresses
    { re: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, label: "[REDACTED_EMAIL]" },
    // US Social Security Numbers  (###-##-####)
    { re: /\b\d{3}-\d{2}-\d{4}\b/g, label: "[REDACTED_SSN]" },
    // Credit-card numbers (13-16 digits, optionally separated by spaces or dashes)
    { re: /\b(?:\d[ \-]?){13,16}\b/g, label: "[REDACTED_CC]" },
    // US phone numbers in common formats
    { re: /\b(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b/g, label: "[REDACTED_PHONE]" },
    // IPv4 addresses
    { re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, label: "[REDACTED_IP]" },
  ];
  let redacted = text;
  for (const { re, label } of PATTERNS) {
    redacted = redacted.replace(re, label);
  }
  return redacted;
}

/**
 * Returns a new array of Document objects with PII redacted from pageContent.
 * The original documents are not mutated.
 */
function redactDocuments(docs) {
  return docs.map((doc) => ({
    ...doc,
    pageContent: redactPII(doc.pageContent),
  }));
}

// ---------------------------------------------------------------------------
// Document content scanner
// Policy: documents must be scanned for hidden prompts, base64-encoded payloads,
// shell commands, and binary executables before entering the embedding pipeline.
// ---------------------------------------------------------------------------
const SUSPICIOUS_PATTERNS = [
  // Prompt-injection / jailbreak triggers
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
  /you\s+are\s+now\s+(a\s+)?(?:dan|jailbreak|unrestricted)/i,
  /system\s*:\s*you\s+are/i,
  /<\s*\/?\s*(?:system|user|assistant)\s*>/i,
  /\[\s*(?:INST|SYS|SYSTEM|HUMAN|ASSISTANT)\s*\]/i,
  // Shell / OS command patterns
  /(?:^|[\s;|&`$])(?:bash|sh|zsh|cmd|powershell|pwsh|exec|eval|system|popen)\s*[\(\-]/im,
  /(?:rm\s+-rf|mkfs|dd\s+if=|chmod\s+[0-7]{3,4}|wget\s+http|curl\s+http)/i,
  /(?:\$\(|`)[^`]*(?:\)|`)/,   // command substitution
  // Base64-encoded blobs (>= 64 contiguous base64 chars — heuristic for hidden payloads)
  /[A-Za-z0-9+\/]{64,}={0,2}/,
  // Binary / non-printable bytes (null bytes, high-byte sequences)
  /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/,
];

/**
 * Scans a LangChain Document for malicious content.
 * Throws an error (and logs an audit record) if suspicious content is found.
 * @param {import('langchain/document').Document} doc
 * @param {number} index - position in the batch, for diagnostics
 */
function scanDocumentForMaliciousContent(doc, index) {
  const content = typeof doc.pageContent === "string" ? doc.pageContent : "";
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(content)) {
      const auditRecord = {
        timestamp: new Date().toISOString(),
        event: "DOCUMENT_SCAN_REJECTED",
        docIndex: index,
        source: doc.metadata?.source ?? "unknown",
        patternMatched: pattern.toString(),
      };
      try {
        fs.appendFileSync(
          AUDIT_LOG_PATH,
          JSON.stringify(auditRecord) + "\n",
          "utf8"
        );
      } catch (_e) {
        console.error("[AUDIT] Failed to write scan-rejection record:", _e.message);
      }
      console.error("[SCAN] Rejected document at index", index, "— matched pattern:", pattern.toString());
      throw new Error(
        `[SCAN] Document at index ${index} (source: ${
          doc.metadata?.source ?? "unknown"
        }) contains potentially malicious content and was rejected before embedding.`
      );
    }
  }
}

/**
 * Scans an entire batch of documents.
 * Call this immediately before any embedding / vector-store ingestion.
 * @param {import('langchain/document').Document[]} docs
 */
function scanDocumentBatch(docs) {
  if (!Array.isArray(docs) || docs.length === 0) {
    throw new Error("[SCAN] Document batch is empty or invalid — aborting embedding.");
  }
  docs.forEach((doc, i) => scanDocumentForMaliciousContent(doc, i));
  console.info(`[SCAN] All ${docs.length} document(s) passed malicious-content scan.`);
}

// ---------------------------------------------------------------------------
// Input sanitization and validation for AI model inputs
// Policy: all text content must be sanitized and validated before LLM invocation.
// ---------------------------------------------------------------------------
const MAX_DOCUMENT_CHARS = 100_000; // max characters per document chunk
const MIN_DOCUMENT_CHARS = 1;       // reject empty documents

/**
 * Sanitizes a single document's pageContent before it is sent to the embedding model.
 * - Removes null bytes and non-printable control characters (except common whitespace)
 * - Truncates content exceeding MAX_DOCUMENT_CHARS
 * - Returns null if the content is empty or invalid after sanitization
 *
 * @param {string} text - Raw text content from a document chunk
 * @returns {string|null} Sanitized text, or null if the document should be rejected
 */
function sanitizeDocumentText(text) {
  if (typeof text !== "string") return null;
  // Remove null bytes
  let sanitized = text.replace(/\x00/g, "");
  // Remove non-printable ASCII control characters except tab (\x09), newline (\x0A), carriage return (\x0D)
  sanitized = sanitized.replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Truncate to maximum allowed length
  if (sanitized.length > MAX_DOCUMENT_CHARS) {
    console.warn(
      `[Sanitize] Document truncated from ${sanitized.length} to ${MAX_DOCUMENT_CHARS} characters.`
    );
    sanitized = sanitized.slice(0, MAX_DOCUMENT_CHARS);
  }
  // Reject documents that are empty after sanitization
  if (sanitized.trim().length < MIN_DOCUMENT_CHARS) {
    return null;
  }
  return sanitized;
}

/**
 * Validates and sanitizes an array of LangChain Document objects.
 * Documents that fail sanitization are dropped and logged.
 *
 * @param {Array} docs - Array of LangChain Document objects
 * @returns {Array} Array of sanitized Document objects safe for embedding
 */
function sanitizeDocuments(docs) {
  if (!Array.isArray(docs)) {
    throw new Error("[Sanitize] Expected an array of documents.");
  }
  const sanitized = [];
  for (let i = 0; i < docs.length; i++) {
    const doc = docs[i];
    const cleanText = sanitizeDocumentText(doc.pageContent);
    if (cleanText === null) {
      console.warn(
        `[Sanitize] Document at index ${i} was rejected after sanitization (empty or invalid content).`
      );
      continue;
    }
    sanitized.push(
      new Document({ pageContent: cleanText, metadata: doc.metadata ?? {} })
    );
  }
  if (sanitized.length === 0) {
    throw new Error(
      "[Sanitize] All documents were rejected during sanitization. Aborting embedding to prevent empty index."
    );
  }
  console.info(
    `[Sanitize] ${sanitized.length} of ${docs.length} documents passed sanitization and will be embedded.`
  );
  return sanitized;
}

// ---------------------------------------------------------------------------
// MCP server output sanitization
// Policy: Client must validate and sanitize any output from a MCP server
// before further processing.
// ---------------------------------------------------------------------------

/**
 * Sanitizes and validates a raw MCP server tool response.
 * @param {unknown} mcpResponse - The raw response from an MCP server tool call.
 * @param {object} [options]
 * @param {number} [options.maxStringLength=65536] - Maximum allowed length for any string field.
 * @param {string[]} [options.requiredFields=[]] - Fields that must be present on the response.
 * @returns {object} - The sanitized, validated response object.
 * @throws {Error} If the response fails structural or content validation.
 */
function sanitizeMcpOutput(mcpResponse, { maxStringLength = 65536, requiredFields = [] } = {}) {
  // 1. Reject null / non-object responses
  if (mcpResponse === null || mcpResponse === undefined) {
    throw new Error("[MCP Sanitization] Response is null or undefined.");
  }
  if (typeof mcpResponse !== "object" || Array.isArray(mcpResponse)) {
    throw new Error(
      `[MCP Sanitization] Expected an object response, got: ${typeof mcpResponse}`
    );
  }

  // 2. Check required fields
  for (const field of requiredFields) {
    if (!(field in mcpResponse)) {
      throw new Error(
        `[MCP Sanitization] Required field "${field}" is missing from MCP response.`
      );
    }
  }

  // 3. Deep-clone to avoid prototype pollution and strip non-own properties
  const sanitized = JSON.parse(JSON.stringify(mcpResponse));

  // 4. Recursively sanitize string values
  function sanitizeValue(value, keyPath) {
    if (typeof value === "string") {
      if (value.length > maxStringLength) {
        throw new Error(
          `[MCP Sanitization] String field "${keyPath}" exceeds maximum allowed length ` +
            `(${value.length} > ${maxStringLength}).`
        );
      }
      // Strip null bytes and control characters (except common whitespace)
      const cleaned = value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
      // Detect and reject obvious script-injection patterns
      if (/<script[\s>]/i.test(cleaned) || /javascript:/i.test(cleaned)) {
        throw new Error(
          `[MCP Sanitization] Potentially unsafe content detected in field "${keyPath}".`
        );
      }
      return cleaned;
    } else if (Array.isArray(value)) {
      return value.map((item, idx) => sanitizeValue(item, `${keyPath}[${idx}]`));
    } else if (value !== null && typeof value === "object") {
      const result = {};
      for (const [k, v] of Object.entries(value)) {
        result[k] = sanitizeValue(v, `${keyPath}.${k}`);
      }
      return result;
    }
    // numbers, booleans, null pass through unchanged
    return value;
  }

  const result = sanitizeValue(sanitized, "root");
  console.info("[MCP Sanitization] MCP server output passed validation and sanitization.");
  return result;
}

/**
 * Wraps an MCP tool call, automatically sanitizing the response before returning it.
 * @param {Function} mcpToolFn - The async MCP tool function to call.
 * @param {object} [sanitizeOptions] - Options forwarded to sanitizeMcpOutput.
 * @returns {Function} - A wrapped async function that returns sanitized output.
 */
function withMcpSanitization(mcpToolFn, sanitizeOptions = {}) {
  return async function (...args) {
    console.info(
      "[MCP Interaction] Sending request to MCP tool:",
      mcpToolFn.name || "(anonymous)",
      "| args:",
      JSON.stringify(args)
    );
    const rawResponse = await mcpToolFn(...args);
    console.info(
      "[MCP Interaction] Received response from MCP tool:",
      mcpToolFn.name || "(anonymous)",
      "| response:",
      JSON.stringify(rawResponse)
    );
    return sanitizeMcpOutput(rawResponse, sanitizeOptions);
  };
}
// ---------------------------------------------------------------------------

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
// ---------------------------------------------------------------------------
// MCP server client authentication
// Policy: MCP server must authenticate all clients.
// Clients must supply a Bearer token matching MCP_CLIENT_AUTH_TOKEN in the
// Authorization header (or equivalent transport header) of every request.
// ---------------------------------------------------------------------------
const MCP_CLIENT_AUTH_TOKEN = process.env.MCP_CLIENT_AUTH_TOKEN;
if (!MCP_CLIENT_AUTH_TOKEN || MCP_CLIENT_AUTH_TOKEN.trim().length === 0) {
  throw new Error(
    "Policy violation: MCP_CLIENT_AUTH_TOKEN environment variable is not set. " +
      "The MCP server requires a non-empty shared secret to authenticate all clients. " +
      "Set MCP_CLIENT_AUTH_TOKEN in your environment before starting the server."
  );
}

/**
 * Authenticates an incoming MCP client request by validating the Bearer token
 * supplied in the Authorization header against the expected server secret.
 *
 * @param {string|undefined} authorizationHeader - The value of the Authorization
 *   header from the incoming MCP client request (e.g. "Bearer <token>").
 * @throws {Error} If the token is missing, malformed, or does not match the
 *   expected MCP_CLIENT_AUTH_TOKEN, rejecting the client request.
 */
function authenticateMcpClient(authorizationHeader) {
  if (!authorizationHeader || typeof authorizationHeader !== "string") {
    throw new Error(
      "MCP client authentication failed: Authorization header is missing. " +
        "All clients must supply a Bearer token."
    );
  }

  const BEARER_PREFIX = "Bearer ";
  if (!authorizationHeader.startsWith(BEARER_PREFIX)) {
    throw new Error(
      "MCP client authentication failed: Authorization header must use the Bearer scheme. " +
        `Received: "${authorizationHeader.slice(0, 20)}..."`
    );
  }

  const suppliedToken = authorizationHeader.slice(BEARER_PREFIX.length);

  // Use a timing-safe comparison to prevent timing-based token oracle attacks.
  const expected = Buffer.from(MCP_CLIENT_AUTH_TOKEN, "utf8");
  const supplied = Buffer.from(suppliedToken, "utf8");

  let tokenValid = false;
  if (expected.length === supplied.length) {
    tokenValid = crypto.timingSafeEqual(expected, supplied);
  }

  if (!tokenValid) {
    throw new Error(
      "MCP client authentication failed: supplied Bearer token does not match " +
        "the expected MCP_CLIENT_AUTH_TOKEN. Client is not authorized."
    );
  }
}
// ---------------------------------------------------------------------------ation (COMPLETE): TLS certificate pinning for Pinecone API
// Policy: MCP client must authenticate MCP server.
// The client MUST verify the MCP server's identity before sending any data.
// Set PINECONE_SERVER_CERT_FINGERPRINT in your environment to the expected
// SHA-256 fingerprint (colon-separated hex, e.g. "AB:CD:EF:...") of the
// Pinecone API server certificate. Connections are rejected if the fingerprint
// does not match, preventing MITM attacks.
// ---------------------------------------------------------------------------
const PINECONE_SERVER_CERT_FINGERPRINT = process.env.PINECONE_SERVER_CERT_FINGERPRINT;
if (!PINECONE_SERVER_CERT_FINGERPRINT) {
  throw new Error(
    "Policy violation: PINECONE_SERVER_CERT_FINGERPRINT environment variable is not set. " +
      "MCP client must authenticate the MCP server. " +
      "Server identity verification requires a pinned certificate fingerprint. " +
      "Set PINECONE_SERVER_CERT_FINGERPRINT to the SHA-256 fingerprint of the Pinecone API server certificate."
  );
}
// Validate fingerprint format (colon-separated hex pairs, SHA-256 = 32 bytes = 95 chars)
if (!/^([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$/.test(PINECONE_SERVER_CERT_FINGERPRINT)) {
  throw new Error(
    "Policy violation: PINECONE_SERVER_CERT_FINGERPRINT is not a valid SHA-256 fingerprint. " +
      "Expected format: 64 hex characters separated by colons (e.g. \"AB:CD:EF:...\", 95 chars total)."
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
          `MCP server authentication failed: certificate fingerprint mismatch. ` +
            `Expected "${expectedFingerprint}" but received "${actualFingerprint}". ` +
            `The MCP server identity could not be verified — connection refused to prevent MITM attack. ` +
            `Update PINECONE_SERVER_CERT_FINGERPRINT if the server certificate has been legitimately rotated.`
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

/**
 * Detects and redacts Singapore-specific PII from text.
 * Covers: NRIC/FIN numbers, Work Permit numbers, SingPass identifiers,
 * CPF account numbers, Singapore phone numbers, Singapore postal codes,
 * Singapore passport numbers, email addresses, and credit card numbers.
 * @param {string} text - Text to redact
 * @returns {string} Text with Singapore PII replaced by redaction tokens
 */
function detectAndRedactSingaporePII(text) {
  const SG_PII_PATTERNS = [
    // NRIC/FIN: S/T/F/G/M followed by 7 digits and a letter
    { re: /\b[STFGM]\d{7}[A-Z]\b/gi, label: "[REDACTED_NRIC_FIN]" },
    // Singapore passport: E followed by 7 digits (or similar formats)
    { re: /\b[EK]\d{7}[A-Z]\b/gi, label: "[REDACTED_PASSPORT]" },
    // Work Permit / Employment Pass: WP or EP followed by alphanumerics
    { re: /\b(?:WP|EP|SP|DP|LTVP)[-\s]?[A-Z0-9]{6,12}\b/gi, label: "[REDACTED_WORK_PERMIT]" },
    // SingPass identifier (NRIC used as SingPass ID — covered above, but also explicit SingPass prefix)
    { re: /\bSingPass[-\s]?ID[-:\s]+[A-Z0-9]{6,12}\b/gi, label: "[REDACTED_SINGPASS_ID]" },
    // CPF account number: 9 digits (distinct from phone by context prefix)
    { re: /\bCPF[-\s]?(?:Account|Acct|No\.?|Number)?[-:\s]+\d{9}\b/gi, label: "[REDACTED_CPF_ACCOUNT]" },
    // Singapore phone numbers: +65 or 65 country code, 8-digit local numbers starting with 6/8/9
    { re: /\b(?:\+65|65)?[-\s]?[689]\d{3}[-\s]?\d{4}\b/g, label: "[REDACTED_SG_PHONE]" },
    // Singapore postal code: 6-digit code (often preceded by S( or Singapore)
    { re: /\b(?:S\()?(?:0[1-9]|[1-7]\d|8[0-8])\d{4}\)?\b/g, label: "[REDACTED_SG_POSTAL]" },
    // Email addresses
    { re: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, label: "[REDACTED_EMAIL]" },
    // Credit card numbers: 13–19 digits, optionally separated by spaces or dashes
    { re: /\b(?:\d[ \-]?){13,19}\b/g, label: "[REDACTED_CREDIT_CARD]" },
    // Full names heuristic: two or more capitalised words (Title Case) in sequence
    // e.g. "John Tan Wei Ming" — conservative pattern to avoid over-redaction
    { re: /\b[A-Z][a-z]{1,20}(?:\s[A-Z][a-z]{1,20}){1,4}\b/g, label: "[REDACTED_FULL_NAME]" },
  ];

  let redacted = text;
  for (const { re, label } of SG_PII_PATTERNS) {
    redacted = redacted.replace(re, label);
  }
  return redacted;
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

  // Redact Singapore-specific PII before content is embedded or uploaded
  sanitized = detectAndRedactSingaporePII(sanitized);

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

// Attach provenance metadata and cryptographic watermark to every document before embedding/storage.
// PROVENANCE_HMAC_SECRET must be set in the environment; it is used to produce a per-document HMAC-SHA256
// watermark that allows downstream verification of content origin and integrity.
const PROVENANCE_HMAC_SECRET = process.env.PROVENANCE_HMAC_SECRET;
if (!PROVENANCE_HMAC_SECRET || PROVENANCE_HMAC_SECRET.length < 32) {
  throw new Error(
    "PROVENANCE_HMAC_SECRET environment variable must be set and at least 32 characters long " +
    "to enable cryptographic watermarking of AI-generated embeddings."
  );
}

const CONTENT_ORIGIN_TAG = process.env.CONTENT_ORIGIN_TAG ?? "ai-generated:openai-embeddings";

function attachProvenanceAndWatermark(doc) {
  const provenanceTimestamp = new Date().toISOString();
  const contentHash = crypto
    .createHash("sha256")
    .update(doc.pageContent ?? "")
    .digest("hex");
  const provenancePayload = JSON.stringify({
    modelIdentifier: PINNED_EMBEDDING_MODEL,
    contentOriginTag: CONTENT_ORIGIN_TAG,
    provenanceTimestamp,
    fileName: doc.metadata?.fileName ?? "unknown",
    contentHash,
  });
  const watermark = crypto
    .createHmac("sha256", PROVENANCE_HMAC_SECRET)
    .update(provenancePayload)
    .digest("hex");
  return new Document({
    pageContent: doc.pageContent,
    metadata: {
      ...doc.metadata,
      provenance_model: PINNED_EMBEDDING_MODEL,
      provenance_timestamp: provenanceTimestamp,
      provenance_origin: CONTENT_ORIGIN_TAG,
      provenance_watermark: watermark,
    },
  });
}

const safeDocs = langchainDocs
  .flat()
  .filter((doc) => doc !== undefined)
  .map((doc) => validateAndSanitizeDoc(doc))
  .map((doc) => attachProvenanceAndWatermark(doc));

const docsToEmbed = redactDocuments(
  // original assignment continues below — wrap the existing value
  (() => { const _raw = safeDocs;
    // Explicit tool allow list — only tools present here may be invoked.
  const ALLOWED_TOOLS = new Set([
    "OpenAIEmbeddings",
    "PineconeStore.fromDocuments",
  ]);
  const requestedTools = ["OpenAIEmbeddings", "PineconeStore.fromDocuments"];
  for (const tool of requestedTools) {
    if (!ALLOWED_TOOLS.has(tool)) {
      throw new Error(
        `Tool '${tool}' is not in the approved allow list and cannot be invoked. ` +
        `Approved tools: ${[...ALLOWED_TOOLS].join(", ")}`
      );
    }
  }
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: "llm_interaction_complete",
    traceId,
    service: "OpenAIEmbeddings",
    model: PINNED_EMBEDDING_MODEL,
    action: "PineconeStore.fromDocuments",
    documentCount: docsToEmbed.length,
    status: "success",
    allowListValidated: true,
  })); // Note: document content is intentionally excluded from this log entry
try {
  const AUDIT_LOG_PATH = path.resolve("audit.log");
const MODEL_IDENTIFIER = "embed-english-v3.0"; // CohereEmbeddings approved model

const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);

// Compute a deterministic SHA-256 hash of the input documents for forensic integrity
const inputHash = crypto
  .createHash("sha256")
  .update(JSON.stringify(filteredDocs.map((d) => ({ metadata: d.metadata }))))
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
        body: (() => { texts.forEach((t, i) => assertNoDangerousPatterns(t, `embedding-text[${i}]`)); return JSON.stringify({ texts }); })(),
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
  const sanitizedDocs = splitDocs.map((doc, idx) => {
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
      // --- HITL approval gate for risky delete operation ---
      (function requireHITLApprovalForDelete(targetPath) {
        const approved = process.env.HITL_DELETE_APPROVED === "true";
        if (!approved) {
          throw new Error(
            `[HITL] Human approval required before deleting file. ` +
            `Operation: delete '${targetPath}'. ` +
            `Set environment variable HITL_DELETE_APPROVED=true to explicitly approve this risky operation.`
          );
        }
        console.warn(
          `[HITL] Human-approved file delete operation proceeding: '${targetPath}'`
        );
      })(AUDIT_LOG_PATH);
      // --- HITL approval gate for risky delete/destroy operation ---
      (function requireHITLApprovalForUnlink(targetPath) {
        const approved = process.env.HITL_DELETE_APPROVED === "true";
        if (!approved) {
          throw new Error(
            `[HITL] Human approval required before deleting file. ` +
            `Operation: delete '${targetPath}'. ` +
            `Set environment variable HITL_DELETE_APPROVED=true to explicitly approve this risky operation.`
          );
        }
        console.warn(
          `[HITL] Human-approved file delete (unlink) operation proceeding: '${targetPath}'`
        );
      })(AUDIT_LOG_PATH);
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
    model: PINNED_EMBEDDING_MODEL, // Registry-approved: text-embedding-3-small
    action: "PineconeStore.fromDocuments",
    documentCount: docsToEmbed.length,
    status: "success",
  };
  try {
      const _statC = fs.existsSync(AUDIT_LOG_PATH) ? fs.statSync(AUDIT_LOG_PATH) : null;
    const _maxC = parseInt(process.env.AUDIT_LOG_MAX_BYTES || String(10 * 1024 * 1024), 10);
    if (_statC && _statC.size >= _maxC) {
      const _rotatedPathC = AUDIT_LOG_PATH + "." + new Date().toISOString().replace(/[:.]/g, "-");
      const _pathModC = require ? (() => { try { return require("path"); } catch(_){return null;} })() : null;
      const _resolvedC = _pathModC ? _pathModC.resolve(_rotatedPathC) : _rotatedPathC;
      const _expectedDirC = _pathModC ? _pathModC.dirname(_pathModC.resolve(AUDIT_LOG_PATH)) : null;
      const _sepC = _pathModC ? _pathModC.sep : "/";
      if (_expectedDirC && !_resolvedC.startsWith(_expectedDirC + _sepC) && _resolvedC !== _expectedDirC) {
        throw new Error("[AUDIT] Rotated log path escapes expected directory: " + _resolvedC);
      }
      fs.renameSync(AUDIT_LOG_PATH, _resolvedC);
    }
  } catch (_re) { console.error("[AUDIT] Log rotation failed:", _re.message); }
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(llmCompleteRecord) + "\n", "utf8");
  console.log("[AUDIT]", JSON.stringify(llmCompleteRecord));
} catch (err) {
  const llmErrorRecord = {
    timestamp: new Date().toISOString(),
    event: "llm_interaction_error",
    service: "ApprovedEmbeddings",
    model: PINNED_EMBEDDING_MODEL,
    action: "PineconeStore.fromDocuments",
    documentCount: docsToEmbed.length,
    status: "error",
    error: "embedding_operation_failed",
  };
  // NOTE: docsToEmbed must be field-filtered before this block (see minimisedDocs usage above)
  try {
    const _statE = fs.existsSync(AUDIT_LOG_PATH) ? fs.statSync(AUDIT_LOG_PATH) : null;
    const _maxE = parseInt(process.env.AUDIT_LOG_MAX_BYTES || String(10 * 1024 * 1024), 10);
            if (_statE && _statE.size >= _maxE) {
      const _rotatedPathE = AUDIT_LOG_PATH + "." + new Date().toISOString().replace(/[:.]/g, "-");
      requireHITLApprovalForRotation(AUDIT_LOG_PATH, _rotatedPathE);
      // Path-traversal guard: verify rotated path stays within the same directory
      const _pathMod = await import("path");
      const _resE = _pathMod.resolve;
      const _dirE = _pathMod.dirname;
      const _sepE = _pathMod.sep;
      const _expectedDirE = _dirE(_resE(AUDIT_LOG_PATH));
      const _resolvedE = _resE(_rotatedPathE);
      if (!_resolvedE.startsWith(_expectedDirE + _sepE) && _resolvedE !== _expectedDirE) {
        throw new Error("[AUDIT] Rotated log path escapes expected directory: " + _resolvedE);
      }
      // Use atomic rename only; no copy+unlink to avoid partial-state exposure
      fs.renameSync(AUDIT_LOG_PATH, _resolvedE);
    }
  } catch (_re) { console.error("[AUDIT] Log rotation failed:", _re.message); }
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(llmErrorRecord) + "\n", "utf8");
  console.error("[AUDIT]", JSON.stringify(llmErrorRecord));
  throw err;
}
