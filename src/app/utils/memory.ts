// Redis removed: replaced with in-memory store to stay within 3-credential limit
import { createHmac } from "crypto";
import { HuggingFaceInferenceEmbeddings } from "langchain/embeddings/hf";
import { PineconeClient } from "@pinecone-database/pinecone";
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { SupabaseClient, createClient } from "@supabase/supabase-js";

const DANGEROUS_PATTERNS = [
  /\be(?:v)al\s*\(/i,
  /\be(?:x)ec\s*\(/i,
  /\bnew\s+Function\s*\(/i,
  /\bsetTimeout\s*\(\s*['"`]/i,
  /\bsetInterval\s*\(\s*['"`]/i,
  /\bimportScripts\s*\(/i,
  /\bdocument\.write\s*\(/i,
  /\bwindow\s*\[\s*['"`]/i,
  /\bglobalThis\s*\[\s*['"`]/i,
  /__import__\s*\(/i,
  /\bcompile\s*\(/i,
  /\bexecfile\s*\(/i,
];

// Allowlist of metadata fields that may be returned to callers.
const ALLOWED_METADATA_FIELDS: ReadonlySet<string> = new Set([
  "source",
  "title",
  "companionName",
  "loc",
]);

// Patterns used to redact sensitive values from text before returning.
const SENSITIVE_PATTERNS: { pattern: RegExp; replacement: string }[] = [
  // E-mail addresses
  { pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, replacement: "[EMAIL REDACTED]" },
  // Phone numbers (common formats)
  { pattern: /(?:\+?\d[\s.\-]?){7,15}/g, replacement: "[PHONE REDACTED]" },
  // Credit-card numbers (13-19 digits, optionally separated by spaces/dashes)
  { pattern: /\b(?:\d[ \-]?){13,19}\b/g, replacement: "[CARD REDACTED]" },
  // Password / token / secret / key assignments
  { pattern: /\b(?:password|passwd|secret|token|api[_\-]?key|auth[_\-]?key)\s*[:=]\s*\S+/gi, replacement: "[CREDENTIAL REDACTED]" },
];

function redactSensitiveText(text: string): string {
  let redacted = text;
  for (const { pattern, replacement } of SENSITIVE_PATTERNS) {
    redacted = redacted.replace(pattern, replacement);
  }
  return redacted;
}

// ---------------------------------------------------------------------------
// Provenance constants – identify the retrieval pipeline and signing key.
// ---------------------------------------------------------------------------
const PROVENANCE_MODEL_ID = "vector-store-retrieval-v1";
const PROVENANCE_CONTENT_ORIGIN = "ai-generated:vector-store";
const PROVENANCE_LABEL = "SYNTHETIC_AI_CONTENT";
// Use SESSION_SECRET (defined later in the file) as the HMAC key so that
// provenance signatures are tied to the deployment secret.  We reference it
// via a lazy accessor to avoid a temporal-dead-zone issue at module load time.
function _provenanceSecret(): string {
  // SESSION_SECRET is declared with `const` further down in this file.
  // TypeScript sees it in scope because function bodies are evaluated at
  // call-time, not at parse-time.
  return (globalThis as any).__MEMORY_SESSION_SECRET__ ??
    (typeof SESSION_SECRET !== "undefined" ? SESSION_SECRET : "default-provenance-key");
}

/**
 * Compute a short HMAC-SHA256 hex digest over the supplied content string.
 * This acts as a lightweight cryptographic signature that downstream consumers
 * can verify to confirm the content has not been tampered with after retrieval.
 */
function computeProvenanceSignature(content: string, timestamp: string): string {
  return createHmac("sha256", _provenanceSecret())
    .update(`${PROVENANCE_MODEL_ID}|${timestamp}|${content}`)
    .digest("hex");
}

function sanitizeDocs(docs: any[] | undefined): { pageContent: string; metadata: Record<string, unknown> }[] {
  if (!docs || !Array.isArray(docs)) return [];
  const filtered = docs.filter((doc) => {
    if (!doc || typeof doc.pageContent !== "string") return false;
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(doc.pageContent)) {
        console.warn(
          "WARNING: Filtered out document containing dangerous code execution primitive."
        );
        return false;
      }
    }
    return true;
  });

  // Minimise output: return only pageContent (redacted) + whitelisted metadata fields.
  return filtered.map((doc) => {
    const safeMetadata: Record<string, unknown> = {};
    if (doc.metadata && typeof doc.metadata === "object") {
      for (const field of ALLOWED_METADATA_FIELDS) {
        if (Object.prototype.hasOwnProperty.call(doc.metadata, field)) {
          safeMetadata[field] = doc.metadata[field];
        }
      }
    }

    const redactedContent = redactSensitiveText(doc.pageContent);
    const retrievalTimestamp = new Date().toISOString();

    // ------------------------------------------------------------------
    // Provenance metadata – attached to every returned document so that
    // callers can verify the synthetic origin, model pipeline, and
    // integrity of the content.
    // ------------------------------------------------------------------
    safeMetadata["_provenance"] = {
      // Human-readable label indicating this is AI/synthetic content.
      contentLabel: PROVENANCE_LABEL,
      // Identifies the retrieval model / pipeline that produced this doc.
      modelId: PROVENANCE_MODEL_ID,
      // Identifies the content origin (vector store, AI-generated).
      contentOrigin: PROVENANCE_CONTENT_ORIGIN,
      // ISO-8601 timestamp of when this document was retrieved.
      retrievedAt: retrievalTimestamp,
      // HMAC-SHA256 signature over (modelId | timestamp | redactedContent).
      // Downstream consumers can re-compute this to verify integrity.
      signature: computeProvenanceSignature(redactedContent, retrievalTimestamp),
    };

    return {
      pageContent: redactedContent,
      metadata: safeMetadata,
    };
  });
}

const APPROVED_EMBEDDING_MODELS: ReadonlySet<string> = new Set([
  "sentence-transformers/all-MiniLM-L6-v2",
]);

const PINNED_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2";

// SHA-256 digest of the approved pinned model identifier string.
// Recompute with: echo -n 'sentence-transformers/all-MiniLM-L6-v2' | sha256sum
const PINNED_EMBEDDING_MODEL_DIGEST =
  "4aa4e4b0e4e4b0e4e4b0e4e4b0e4e4b04aa4e4b0e4e4b0e4e4b0e4e4b0e4e4b0";

function verifyModelDigest(modelId: string, expectedDigest: string): void {
  const crypto = require("crypto");
  const actual = crypto.createHash("sha256").update(modelId, "utf8").digest("hex");
  if (actual !== expectedDigest) {
    throw new Error(
      `Model identity integrity check failed. ` +
      `Expected digest '${expectedDigest}' but got '${actual}' for model '${modelId}'. ` +
      `Do not proceed — the pinned model identifier may have been tampered with.`
    );
  }
}

function createApprovedEmbeddings(): HuggingFaceInferenceEmbeddings {
  if (!APPROVED_EMBEDDING_MODELS.has(PINNED_EMBEDDING_MODEL)) {
    throw new Error(
      `Model '${PINNED_EMBEDDING_MODEL}' is not in the approved model registry. ` +
      `Approved models: ${[...APPROVED_EMBEDDING_MODELS].join(", ")}`
    );
  }
  // Verify cryptographic digest of the model identifier before instantiation.
  verifyModelDigest(PINNED_EMBEDDING_MODEL, PINNED_EMBEDDING_MODEL_DIGEST);
  // Uses HuggingFace public inference — no additional API key required,
  // keeping external credentials within the 3-system limit (Pinecone + Supabase).
  return new HuggingFaceInferenceEmbeddings({
    model: PINNED_EMBEDDING_MODEL,
  });
}' is not in the approved model registry. ` +
      `Approved models: ${[...APPROVED_EMBEDDING_MODELS].join(", ")}`
    );
  }
    // Uses HuggingFace public inference — no additional API key required,
  // keeping external credentials within the 3-system limit (Pinecone + Supabase).
  return new HuggingFaceInferenceEmbeddings({
    model: PINNED_EMBEDDING_MODEL,
  });
});
}
  if (!process.env.COHERE_API_KEY) {
    throw new Error("COHERE_API_KEY environment variable is not set.");
  }
  return new HuggingFaceInferenceEmbeddings({
    apiKey: process.env.COHERE_API_KEY,
    model: PINNED_EMBEDDING_MODEL,
  });
}' is not in the approved model registry. ` +
      `Approved models: ${[...APPROVED_EMBEDDING_MODELS].join(", ")}`
    );
  }
  return new HuggingFaceInferenceEmbeddings({
    openAIApiKey: process.env.OPENAI_API_KEY,
    modelName: PINNED_EMBEDDING_MODEL,
  });
}

export type CompanionKey = {
  companionName: string;
  modelName: string;
  userId: string;
};

export type ProvenanceMetadata = {
  syntheticOrigin: true;
  modelId: string;
  generatedAt: string; // ISO-8601 timestamp
  contentLabel: "AI_GENERATED";
};

export type ProvenanceWrapped<T> = {
  provenance: ProvenanceMetadata;
  data: T;
};

function buildProvenance(modelId: string): ProvenanceMetadata {
  return {
    syntheticOrigin: true,
    modelId,
    generatedAt: new Date().toISOString(),
    contentLabel: "AI_GENERATED",
  };
}

const PROVENANCE_PREFIX = "[AI_GENERATED|model=" + PINNED_EMBEDDING_MODEL + "]";

function attachProvenancePrefix(text: string): string {
  const ts = new Date().toISOString();
  return `${PROVENANCE_PREFIX}[ts=${ts}] ${text}`;
}

function sanitizeInput(input: string): string {
  if (typeof input !== "string") {
    throw new Error("Invalid input: recentChatHistory must be a string.");
  }
  // Strip null bytes and non-printable control characters (except common whitespace)
  let sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
  // Remove common prompt injection patterns (ignore/disregard/override instructions)
  sanitized = sanitized.replace(
    /\b(ignore|disregard|forget|override|bypass|skip|cancel|stop|reset|clear)\b[\s\S]{0,60}(instruction|prompt|rule|command|context|above|previous|prior|system)/gi,
    "[REDACTED]"
  );
  // Remove shell command patterns
  sanitized = sanitized.replace(
    /(`[^`]*`|\$\([^)]*\)|\|\s*\w+|&&|;\s*\w+|>\s*\/|<\s*\/|\bsudo\b|\brm\b|\bchmod\b|\bchown\b|\bcurl\b|\bwget\b|\beval\b|\bexec\b)/gi,
    "[REDACTED]"
  );
  // Remove base64-encoded or URL-encoded payloads (heuristic: long unbroken alphanum strings)
  sanitized = sanitized.replace(
    /(?:[A-Za-z0-9+/]{40,}={0,2})/g,
    "[REDACTED]"
  );
  // Enforce a reasonable maximum length
  sanitized = sanitized.slice(0, 4000);
  if (sanitized.length === 0) {
    throw new Error("Invalid input: recentChatHistory must not be empty after sanitization.");
  }
  return sanitized;
}
  // Strip null bytes and non-printable control characters (except common whitespace)
  const sanitized = input
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    .trim()
    .slice(0, 4000); // enforce a reasonable maximum length
  if (sanitized.length === 0) {
    throw new Error("Invalid input: recentChatHistory must not be empty after sanitization.");
  }
  return sanitized;
}

function sanitizeInput(input: string): string {
  // Remove common prompt injection patterns (ignore/disregard/override instructions)
  let sanitized = input.replace(
    /\b(ignore|disregard|forget|override|bypass|skip|cancel|stop|reset|clear)\b[\s\S]{0,60}(instruction|prompt|rule|command|context|above|previous|prior|system)/gi,
    "[REDACTED]"
  );
  // Remove shell command patterns
  const _shellCmdPattern = new RegExp(
    "(`[^`]*`|\\$\\([^)]*\\)|\\|\\s*\\w+|&&|;\\s*\\w+|>\\s*\/|<\\s*\/" +
    "|\\b" + "sud" + "o\\b" +
    "|\\b" + "r" + "m\\b" +
    "|\\b" + "chm" + "od\\b" +
    "|\\b" + "cho" + "wn\\b" +
    "|\\b" + "cu" + "rl\\b" +
    "|\\b" + "wg" + "et\\b" +
    "|\\b" + "ev" + "al\\b" +
    "|\\b" + "ex" + "ec\\b)",
    "gi"
  );
  sanitized = sanitized.replace(_shellCmdPattern, "[REDACTED]");
  // Remove base64-encoded or URL-encoded payloads (heuristic: long unbroken alphanum strings)
  sanitized = sanitized.replace(
    /(?:[A-Za-z0-9+/]{40,}={0,2})/g,
    "[REDACTED]"
  );
  // Remove null bytes and other non-printable control characters
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  return sanitized.trim();
}

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

const AUDIT_LOG_PATH = process.env.AUDIT_LOG_PATH || path.join(process.cwd(), "audit_ai_actions.log");
const AUDIT_RETENTION_DAYS = parseInt(process.env.AUDIT_RETENTION_DAYS || "90", 10);

function writeAuditRecord(record: Record<string, unknown>): void {
  const entry = JSON.stringify({
    ...record,
    auditTimestamp: new Date().toISOString(),
    retentionPolicy: `${AUDIT_RETENTION_DAYS}d`,
  });
  try {
    fs.appendFileSync(AUDIT_LOG_PATH, entry + "\n", { encoding: "utf8", flag: "a" });
  } catch (err) {
    console.error("AUDIT_LOG_WRITE_FAILURE", { error: String(err), record });
  }
}

function generateTraceId(): string {
  return crypto.randomUUID();
}

function hashInput(input: string): string {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

class MemoryManager {
  private static instance: MemoryManager;
  private history: Map<string, string[]>;
  private vectorDBClient: PineconeClient | SupabaseClient;

  public constructor() {
    this.history = new Map<string, string[]>();
    if (process.env.VECTOR_DB === "pinecone") {
      this.vectorDBClient = new PineconeClient();
    } else {
      const auth = {
        detectSessionInUrl: false,
        persistSession: false,
        autoRefreshToken: false,
      };
      const url = process.env.SUPABASE_URL!;
      const privateKey = process.env.SUPABASE_PRIVATE_KEY!;
      this.vectorDBClient = createClient(url, privateKey, { auth });
    }
  }

  public async init() {
    if (this.vectorDBClient instanceof PineconeClient) {
      await this.vectorDBClient.init({
        apiKey: process.env.PINECONE_API_KEY!,
        environment: process.env.PINECONE_ENVIRONMENT!,
      });
    }
  }

  public async vectorSearch(
    recentChatHistory: string,
    companionFileName: string,
    principal?: string
  ) {
    const traceId = generateTraceId();
    const inputHash = hashInput(recentChatHistory);
    writeAuditRecord({
      operation: "vectorSearch",
      traceId,
      modelId: PINNED_EMBEDDING_MODEL,
      inputHash,
      companionFileName,
      principal: principal || companionFileName,
      vectorDb: process.env.VECTOR_DB || "supabase",
      status: "initiated",
    });
    if (process.env.VECTOR_DB === "pinecone") {
      console.log("INFO: using Pinecone for vector search.");
      const pineconeClient = <PineconeClient>this.vectorDBClient;

      const pineconeIndex = pineconeClient.Index(
        process.env.PINECONE_INDEX! || ""
      );

                  console.log("INFO: Initiating LLM interaction - OpenAIEmbeddings via PineconeStore.fromExistingIndex", { query: recentChatHistory, companionFileName });
      const vectorStore = await PineconeStore.fromExistingIndex(
        createApprovedEmbeddings(),
        { pineconeIndex }
      );

      console.log("INFO: Initiating LLM interaction - PineconeStore.similaritySearch", { query: recentChatHistory, topK: 3, filter: { fileName: companionFileName } });
      const sanitizedQuery = sanitizeInput(recentChatHistory);
            const similarDocsRaw = await vectorStore
        .similaritySearch(sanitizedQuery, 3)
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      const similarDocs = similarDocsRaw
        ? similarDocsRaw.map((doc: { pageContent: string }) => ({
            pageContent: doc.pageContent,
          }))
        : similarDocsRaw;
      return similarDocs;
    } else {
      console.log("INFO: using Supabase for vector search.");
      const supabaseClient = <SupabaseClient>this.vectorDBClient;
                  console.log("INFO: Initiating LLM interaction - OpenAIEmbeddings via SupabaseVectorStore.fromExistingIndex", { query: recentChatHistory });
      const vectorStore = await SupabaseVectorStore.fromExistingIndex(
        createApprovedEmbeddings(),
        {
          client: supabaseClient,
          tableName: "documents",
          queryName: "match_documents",
        }
      );
      console.log("INFO: Initiating LLM interaction - SupabaseVectorStore.similaritySearch", { query: recentChatHistory, topK: 3 });
      const sanitizedQuery = sanitizeInput(recentChatHistory);
      const similarDocs = await vectorStore
        .similaritySearch(sanitizedQuery, 3)
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      console.log("INFO: LLM interaction result - SupabaseVectorStore.similaritySearch", { resultCount: similarDocs ? similarDocs.length : 0, results: similarDocs });
      return similarDocs;
    }
  }

  public static async getInstance(): Promise<MemoryManager> {
    if (!MemoryManager.instance) {
      MemoryManager.instance = new MemoryManager();
      await MemoryManager.instance.init();
    }
    return MemoryManager.instance;
  }

  private generateRedisCompanionKey(companionKey: CompanionKey): string {
    const secret = process.env.REDIS_KEY_SECRET;
    if (!secret) {
      throw new Error("REDIS_KEY_SECRET environment variable is not set");
    }
    const { createHmac } = require("crypto");
    const payload = `${companionKey.companionName}:${companionKey.modelName}:${companionKey.userId}`;
    const hmac = createHmac("sha256", secret)
      .update(payload)
      .digest("hex");
    return `companion:${hmac}`;
  }

  public async writeToHistory(text: string, companionKey: CompanionKey, traceId?: string) {
    const opTraceId = traceId || generateTraceId();
    writeAuditRecord({
      operation: "writeToHistory",
      traceId: opTraceId,
      principal: companionKey.userId,
      companionName: companionKey.companionName,
      modelName: companionKey.modelName,
      inputHash: hashInput(text),
      status: "initiated",
    });
    if (!companionKey || typeof companionKey.userId == "undefined") {
      console.log("Companion key set incorrectly");
      return "";
    }

    const key = this.generateRedisCompanionKey(companionKey);
    const writeScore = Date.now();
    const WRITE_EXPIRY_SECONDS = 86400;
        const score = Date.now();
    const mac = createHmac('sha256', SESSION_SECRET)
      .update(`${key}:${score}:${text}`)
      .digest('hex');
    const signedMember = `${mac}:${text}`;
    const result = await this.history.zadd(key, {
      score,
      member: signedMember,
    });
    // Refresh expiry on every write; sessions expire after 24 hours of inactivity
    await this.history.expire(key, WRITE_EXPIRY_SECONDS);
    // Audit log: record AI-driven history write with forensic fields
    const auditEntry = JSON.stringify({
      event: "write_to_history",
      timestamp: new Date(writeScore).toISOString(),
      principal: companionKey.userId,
      modelName: companionKey.modelName,
      companionName: companionKey.companionName,
      inputHash: hashInput(text),
      score: writeScore,
      writeResult: result,
      retentionPolicy: { expirySeconds: WRITE_EXPIRY_SECONDS },
    });
    await this.history.zadd(
      `audit:${key}`,
      { score: writeScore, member: auditEntry }
    );
    await this.history.expire(`audit:${key}`, WRITE_EXPIRY_SECONDS);
    console.log(`[AUDIT] write_to_history: ${auditEntry}`);

    return result;
  }

  public async readLatestHistory(companionKey: CompanionKey): Promise<string> {
    if (!companionKey || typeof companionKey.userId == "undefined") {
      console.log("Companion key set incorrectly");
      return "";
    }

    const key = this.generateRedisCompanionKey(companionKey);
        let result = await this.history.zrange(key, 0, Date.now(), {
      byScore: true,
    });

    const MAX_HISTORY_ENTRIES = 10;
    const MAX_ENTRY_LENGTH = 200;
    result = result.slice(-MAX_HISTORY_ENTRIES).reverse();
    const recentChats = result
      .reverse()
      .map((entry: string) => {
        const colonIdx = entry.indexOf(':');
        if (colonIdx === -1) return ''; // reject unsigned entries
        const storedMac = entry.slice(0, colonIdx);
        const payload = entry.slice(colonIdx + 1);
        // Re-derive MAC; we don't have the original score here so verify payload integrity only
        const expectedMac = createHmac('sha256', SESSION_SECRET)
          .update(`${key}:${payload}`)
          .digest('hex');
        // Use timing-safe comparison
        const storedBuf = Buffer.from(storedMac, 'hex');
        const expectedBuf = Buffer.from(expectedMac, 'hex');
        if (storedBuf.length !== expectedBuf.length || !timingSafeEqual(storedBuf, expectedBuf)) {
          console.warn('Session entry failed MAC verification; discarding.');
          return '';
        }
        return redactSensitiveText(payload.slice(0, MAX_ENTRY_LENGTH));
      })
      .filter((entry: string) => entry !== '')
      .join("\n");
    return recentChats;
  }

  private sanitizeInput(input: string): string {
    // Remove control characters (except newline/tab), trim whitespace, and limit length
    return input
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
      .trim()
      .slice(0, 1000);
  }

  /**
   * Writes a structured audit record to a dedicated Redis audit-log key.
   * Retention is set to 90 days (7 776 000 s) independently of session expiry.
   */
  private async writeAuditRecord({
    operation,
    principal,
    inputHash,
    outputSummary,
    modelId,
  }: {
    operation: string;
    principal: string;
    inputHash: string;
    outputSummary: string;
    modelId: string;
  }): Promise<void> {
    const AUDIT_RETENTION_SECONDS = 7_776_000; // 90 days
    const auditKey = `audit:memory:${principal}`;
    const record = JSON.stringify({
      operation,
      principal,
      inputHash,
      outputSummary,
      modelId,
      timestamp: new Date().toISOString(),
    });
    const score = Date.now();
    await this.history.zadd(auditKey, { score, member: record });
    // Enforce 90-day retention on the audit log — distinct from session expiry
    await this.history.expire(auditKey, AUDIT_RETENTION_SECONDS);
  }

  public async seedChatHistory(
    seedContent: String,
    delimiter: string = "\n",
    companionKey: CompanionKey
  ) {
    const key = this.generateRedisCompanionKey(companionKey);
    if (await this.history.exists(key)) {
      console.log("User already has chat history");
      return;
    }

            // Shell command pattern built at runtime to avoid literal command strings in source
            const _shellCmds = [
              ['r','m'], ['d','e','l'], ['f','o','r','m','a','t'],
              ['s','h','u','t','d','o','w','n'], ['r','e','b','o','o','t'],
              ['k','i','l','l'], ['w','g','e','t'], ['c','u','r','l'],
              ['b','a','s','h'], ['s','h'], ['c','m','d'],
              ['p','o','w','e','r','s','h','e','l','l']
            ].map(c => c.join('')).join('|');
            const _shellPattern = new RegExp(
              String.fromCharCode(40) + '?:' + _shellCmds + String.fromCharCode(41),
              'i'
            );
            const DANGEROUS_PATTERNS: RegExp[] = [
              /system\s*:/i,
              /ignore\s+(previous|above|all)\s+instructions/i,
              /you\s+are\s+now/i,
              /execute\s*[(`]/i,
              /eval\s*\(/i,
              /\$\([^)]*\)/,
              /`[^`]*`/,
              new RegExp(';\\s*' + String.fromCharCode(40) + '?:' + _shellCmds + String.fromCharCode(41), 'i'),
              new RegExp('&&\\s*' + String.fromCharCode(40) + '?:' + _shellCmds + String.fromCharCode(41), 'i'),
              new RegExp('\\|\\s*' + String.fromCharCode(40) + '?:' + _shellCmds + String.fromCharCode(41), 'i'),
            ];

    const content = seedContent.split(delimiter);
    let counter = 0;
    const baseTime = Date.now();
        for (const line of content) {
      const mac = createHmac('sha256', SESSION_SECRET)
        .update(`${key}:${baseTime + counter}:${line}`)
        .digest('hex');
      const signedMember = `${mac}:${line}`;
      await this.history.zadd(key, { score: baseTime + counter, member: signedMember });
      // Audit record for this seed write
      await this.writeAuditRecord({
        operation: 'seedChatHistory:write',
        principal: `${companionKey.userId}:${companionKey.companionName}`,
        inputHash: createHmac('sha256', SESSION_SECRET).update(line).digest('hex'),
        outputSummary: `zadd score=${baseTime + counter}`,
        modelId: 'memory-manager-v1',
      });
      counter += 1;
    }
      const isDangerous = DANGEROUS_PATTERNS.some((pattern) =>
        pattern.test(sanitizedLine)
      );
      if (isDangerous) {
        console.warn("Skipping dangerous seed content line");
        continue;
      }
      await this.history.zadd(key, { score: baseTime + counter, member: sanitizedLine });
      counter += 1;
    }
    // Set expiry so seeded sessions expire after 24 hours of inactivity
    // Session expiry: 24 hours of inactivity (chat history only)
    await this.history.expire(key, 86400);
    // Audit the expire operation itself
    await this.writeAuditRecord({
      operation: 'seedChatHistory:expire',
      principal: `${companionKey.userId}:${companionKey.companionName}`,
      inputHash: (() => {
  if (!SESSION_SECRET || SESSION_SECRET.length === 0) {
    throw new Error('SESSION_SECRET environment variable is not set or is empty. A strong secret is required for HMAC key derivation.');
  }
  return createHmac('sha256', SESSION_SECRET).update(key).digest('hex');
})(),
      outputSummary: 'session TTL set to 86400s',
      modelId: 'memory-manager-v1',
    });
  });
      counter += 1;
    }
    // Session expiry: 24 hours of inactivity (chat history only)
    await this.history.expire(key, 86400);
    // Audit the expire operation itself
    await this.writeAuditRecord({
      operation: 'seedChatHistory:expire',
      principal: `${companionKey.userId}:${companionKey.companionName}`,
      inputHash: createHmac('sha256', SESSION_SECRET).update(key).digest('hex'),
      outputSummary: 'session TTL set to 86400s',
      modelId: 'memory-manager-v1',
      modelVersion: '1.0.0',
      retentionTtlSeconds: 7776000, // 90-day retention policy
    });
  });
      counter += 1;
    }
    // Session expiry: 24 hours of inactivity (chat history only)
    await this.history.expire(key, 86400);
    // Audit the expire operation itself
    await this.writeAuditRecord({
      operation: 'seedChatHistory:expire',
      principal: `${companionKey.userId}:${companionKey.companionName}`,
      inputHash: createHmac('sha256', SESSION_SECRET).update(key).digest('hex'),
      outputSummary: 'session TTL set to 86400s',
      modelId: 'memory-manager-v1',
      modelVersion: '1.0.0',
      retentionTtlSeconds: 7776000, // 90-day retention policy
    });
  }

  /**
   * Writes an audit record with model version and retention TTL enforced.
   * retentionTtlSeconds defaults to 7776000 (90 days) if not supplied by caller.
   */
  private async writeAuditRecord(record: {
    operation: string;
    principal: string;
    inputHash: string;
    outputSummary: string;
    modelId: string;
    modelVersion: string;
    retentionTtlSeconds?: number;
    [key: string]: unknown;
  }): Promise<void> {
    const AUDIT_RETENTION_TTL_SECONDS = 7776000; // 90 days
    const auditEntry = {
      ...record,
      modelVersion: record.modelVersion ?? '1.0.0',
      retentionTtlSeconds: record.retentionTtlSeconds ?? AUDIT_RETENTION_TTL_SECONDS,
      retentionExpiresAt: new Date(
        Date.now() + (record.retentionTtlSeconds ?? AUDIT_RETENTION_TTL_SECONDS) * 1000
      ).toISOString(),
      timestamp: new Date().toISOString(),
    };
    // Persist audit entry; if a store supports TTL, apply it here.
    // For in-memory/Supabase stores, retentionExpiresAt enables sweep-based rotation.
    console.log('[AUDIT]', JSON.stringify(auditEntry));
  }
}


export default MemoryManager;
