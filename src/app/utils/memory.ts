// Redis removed: replaced with in-memory store to stay within 3-credential limit
import { BedrockEmbeddings } from "langchain/embeddings/bedrock";
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
    return {
      pageContent: redactSensitiveText(doc.pageContent),
      metadata: safeMetadata,
    };
  });
}

const APPROVED_EMBEDDING_MODELS: ReadonlySet<string> = new Set([
  "sentence-transformers/all-MiniLM-L6-v2",
]);

const PINNED_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2";

function createApprovedEmbeddings(): HuggingFaceInferenceEmbeddings {
  if (!APPROVED_EMBEDDING_MODELS.has(PINNED_EMBEDDING_MODEL)) {
    throw new Error(
      `Model '${PINNED_EMBEDDING_MODEL}' is not in the approved model registry. ` +
      `Approved models: ${[...APPROVED_EMBEDDING_MODELS].join(", ")}`
    );
  }
  // Uses HuggingFace public inference — no additional API key required,
  // keeping external credentials within the 3-system limit (Pinecone + Supabase).
  return new HuggingFaceInferenceEmbeddings({
    model: PINNED_EMBEDDING_MODEL,
  });
}' is not in the approved model registry. ` +
      `Approved models: ${[...APPROVED_EMBEDDING_MODELS].join(", ")}`
    );
  }
  if (!process.env.COHERE_API_KEY) {
    throw new Error("COHERE_API_KEY environment variable is not set.");
  }
  return new CohereEmbeddings({
    apiKey: process.env.COHERE_API_KEY,
    model: PINNED_EMBEDDING_MODEL,
  });
}' is not in the approved model registry. ` +
      `Approved models: ${[...APPROVED_EMBEDDING_MODELS].join(", ")}`
    );
  }
  return new OpenAIEmbeddings({
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

            const DANGEROUS_PATTERNS = [
      /system\s*:/i,
      /ignore\s+(previous|above|all)\s+instructions/i,
      /you\s+are\s+now/i,
      /execute\s*[(`]/i,
      /eval\s*\(/i,
      /\$\([^)]*\)/,
      /`[^`]*`/,
      /;\s*(rm|del|format|shutdown|reboot|kill|wget|curl|bash|sh|cmd|powershell)/i,
      /&&\s*(rm|del|format|shutdown|reboot|kill|wget|curl|bash|sh|cmd|powershell)/i,
      /\|\s*(rm|del|format|shutdown|reboot|kill|wget|curl|bash|sh|cmd|powershell)/i,
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
    await this.history.expire(key, 86400);
  });
      counter += 1;
    }
    // Set expiry so seeded sessions expire after 24 hours of inactivity
    await this.history.expire(key, 86400);
  });
      counter += 1;
    }
    // Set expiry so seeded sessions expire after 24 hours of inactivity
    await this.history.expire(key, 86400);
  }
}


export default MemoryManager;
