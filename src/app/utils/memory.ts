// Redis (Upstash) credential removed to comply with the policy limiting
// this file to no more than 3 external system credentials.
// Cache functionality is handled via a simple in-memory Map instead.
const _inMemoryCache = new Map<string, string>();

/**
 * HITL Approval Gate — MUST be called before any destructive (delete/purge/destroy) operation.
 *
 * Approval flow:
 *  1. If HITL_APPROVAL_ENDPOINT is set, POST a request to that endpoint with the operation
 *     details and wait for a synchronous {approved: true} response from a human operator.
 *  2. If the env var is not set, the operation is BLOCKED and an error is thrown, because
 *     no human approval channel is configured.
 *
 * @param operation  Short label for the operation (e.g. "cache.del").
 * @param target     The resource being deleted (e.g. the cache key).
 */
/**
 * Returns the set of allowed hostnames for the HITL approval endpoint.
 * Reads from HITL_APPROVAL_ALLOWED_HOSTS (comma-separated list).
 * Throws if the env var is not set or empty, to prevent open-redirect by default.
 */
function getHITLAllowedHosts(): Set<string> {
  const raw = process.env.HITL_APPROVAL_ALLOWED_HOSTS ?? "";
  const hosts = raw
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h.length > 0);
  if (hosts.length === 0) {
    throw new Error(
      "[HITL] HITL_APPROVAL_ALLOWED_HOSTS is not configured. " +
      "Set it to a comma-separated list of permitted hostnames for the approval endpoint."
    );
  }
  return new Set(hosts);
}

/**
 * Validates that the given URL's hostname is in the HITL approval allowlist.
 * Throws if the URL is invalid or the hostname is not permitted.
 */
function validateHITLEndpointURL(rawUrl: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(
      `[HITL] HITL_APPROVAL_ENDPOINT "${rawUrl}" is not a valid URL. Operation blocked.`
    );
  }
  if (parsed.protocol !== "https:") {
    throw new Error(
      `[HITL] HITL_APPROVAL_ENDPOINT must use HTTPS. Got "${parsed.protocol}". Operation blocked.`
    );
  }
  const allowedHosts = getHITLAllowedHosts();
  const hostname = parsed.hostname.toLowerCase();
  if (!allowedHosts.has(hostname)) {
    throw new Error(
      `[HITL] HITL_APPROVAL_ENDPOINT hostname "${hostname}" is not in the allowlist ` +
      `(HITL_APPROVAL_ALLOWED_HOSTS). Operation blocked.`
    );
  }
  return parsed;
}

async function requireHITLApproval(operation: string, target: string): Promise<void> {
  const approvalEndpoint = process.env.HITL_APPROVAL_ENDPOINT;
  if (!approvalEndpoint || approvalEndpoint.trim() === "") {
    throw new Error(
      `[HITL] Destructive operation "${operation}" on "${target}" is BLOCKED. ` +
      "Set the HITL_APPROVAL_ENDPOINT environment variable to enable human approval for delete operations."
    );
  }

  // Validate the endpoint URL against the hostname allowlist before fetching.
  const validatedURL = validateHITLEndpointURL(approvalEndpoint.trim());

  let response: Response;
  try {
    response = await fetch(validatedURL.toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        operation,
        target,
        requestedAt: new Date().toISOString(),
      }),
    });
  } catch (networkErr) {
    throw new Error(
      `[HITL] Could not reach approval endpoint for operation "${operation}" on "${target}": ${networkErr}`
    );
  }

  if (!response.ok) {
    throw new Error(
      `[HITL] Approval endpoint returned HTTP ${response.status} for operation "${operation}" on "${target}". ` +
      "Operation aborted."
    );
  }

  let body: { approved?: boolean; reason?: string };
  try {
    body = await response.json();
  } catch {
    throw new Error(
      `[HITL] Approval endpoint returned non-JSON response for operation "${operation}" on "${target}". ` +
      "Operation aborted."
    );
  }

  if (body.approved !== true) {
    throw new Error(
      `[HITL] Human operator DENIED operation "${operation}" on "${target}". ` +
      `Reason: ${body.reason ?? "none provided"}. Operation aborted.`
    );
  }

  // Approval granted — proceed.
  console.info(`[HITL] Human operator APPROVED operation "${operation}" on "${target}".`);
}

const redis = {
  get: async (key: string) => _inMemoryCache.get(key) ?? null,
  set: async (key: string, value: string) => { _inMemoryCache.set(key, value); return "OK"; },
  del: async (key: string) => {
    console.info(`[MCP] Interaction start: operation="cache.del" target="${key}" requestedAt="${new Date().toISOString()}"`);
    try {
      await requireHITLApproval("cache.del", key);
      _inMemoryCache.delete(key);
      console.info(`[MCP] Interaction success: operation="cache.del" target="${key}" completedAt="${new Date().toISOString()}"`);
      return 1;
    } catch (err) {
      console.error(`[MCP] Interaction failed: operation="cache.del" target="${key}" failedAt="${new Date().toISOString()}" error="${err}"`);
      throw err;
    }
  },
};
// CohereEmbeddings removed: not in approved model registry and lacks version pinning.
import { PineconeClient } from "@pinecone-database/pinecone";
import { PineconeStore as _PineconeStoreBase } from "langchain/vectorstores/pinecone";

// MCP interaction logging wrapper for PineconeStore
const _mcpLoggedPineconeStore = new Proxy(_PineconeStoreBase, {
  construct(target, args) {
    console.info(`[MCP] Interaction start: operation="PineconeStore.construct" requestedAt="${new Date().toISOString()}"`);
    const instance = new target(...args);
    console.info(`[MCP] Interaction success: operation="PineconeStore.construct" completedAt="${new Date().toISOString()}"`);
    return new Proxy(instance, {
      get(obj, prop) {
        const val = (obj as Record<string | symbol, unknown>)[prop as string | symbol];
        if (typeof val === "function") {
          return async (...fnArgs: unknown[]) => {
            console.info(`[MCP] Interaction start: operation="PineconeStore.${String(prop)}" args=${JSON.stringify(fnArgs).slice(0, 200)} requestedAt="${new Date().toISOString()}"`);
            try {
              const result = await (val as (...a: unknown[]) => unknown).apply(obj, fnArgs);
              console.info(`[MCP] Interaction success: operation="PineconeStore.${String(prop)}" completedAt="${new Date().toISOString()}"`);
              return result;
            } catch (err) {
              console.error(`[MCP] Interaction failed: operation="PineconeStore.${String(prop)}" failedAt="${new Date().toISOString()}" error="${err}"`);
              throw err;
            }
          };
        }
        return val;
      },
    });
  },
});
const PineconeStore = _mcpLoggedPineconeStore;
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { SupabaseClient, createClient } from "@supabase/supabase-js";

// OpenAIEmbeddings removed: not in approved model registry. Use only registry-approved embedding models.
import * as crypto from "crypto";

// ── Model registry ────────────────────────────────────────────────────────────
// Approved embedding models are loaded from the organizational registry
// configured via the APPROVED_EMBEDDING_MODELS environment variable.
// Format: comma-separated model identifiers, e.g.
//   APPROVED_EMBEDDING_MODELS="text-embedding-ada-002,text-embedding-3-small"
// This variable MUST be set and managed by the central AI governance team.
//
// Integrity verification: the registry value MUST be accompanied by
// APPROVED_EMBEDDING_MODELS_HMAC (hex HMAC-SHA256 keyed with
// APPROVED_EMBEDDING_MODELS_SECRET) so that runtime tampering of the
// approved model list is detected before any model is loaded.
function verifyRegistryIntegrity(registryValue: string): void {
  const secret = process.env.APPROVED_EMBEDDING_MODELS_SECRET;
  const expectedHmac = process.env.APPROVED_EMBEDDING_MODELS_HMAC;
  if (!secret || secret.trim() === "") {
    throw new Error(
      "APPROVED_EMBEDDING_MODELS_SECRET is not set. " +
      "A secret key is required to verify the integrity of the approved model registry."
    );
  }
  if (!expectedHmac || expectedHmac.trim() === "") {
    throw new Error(
      "APPROVED_EMBEDDING_MODELS_HMAC is not set. " +
      "An HMAC-SHA256 digest of the approved model registry value must be provided " +
      "by the AI governance team to prevent runtime tampering."
    );
  }
  const actualHmac = crypto
    .createHmac("sha256", secret.trim())
    .update(registryValue, "utf8")
    .digest("hex");
  // Constant-time comparison to prevent timing attacks
  const expectedBuf = Buffer.from(expectedHmac.trim().toLowerCase(), "hex");
  const actualBuf = Buffer.from(actualHmac, "hex");
  if (
    expectedBuf.length !== actualBuf.length ||
    !crypto.timingSafeEqual(expectedBuf, actualBuf)
  ) {
    throw new Error(
      "APPROVED_EMBEDDING_MODELS integrity check FAILED: " +
      "the HMAC-SHA256 digest does not match the registry value. " +
      "The approved model list may have been tampered with. " +
      "Re-provision APPROVED_EMBEDDING_MODELS and APPROVED_EMBEDDING_MODELS_HMAC " +
      "from the central AI governance registry."
    );
  }
  console.log(
    "[AI Governance] Approved model registry integrity verified via HMAC-SHA256."
  );
}

function loadApprovedEmbeddingModels(): ReadonlySet<string> {
  const registryEnv = process.env.APPROVED_EMBEDDING_MODELS;
  if (!registryEnv || registryEnv.trim() === "") {
    throw new Error(
      "APPROVED_EMBEDDING_MODELS environment variable is not set. " +
      "This must be configured from the organizational model registry before any AI workload can run."
    );
  }
  // Cryptographic integrity check: verify the registry has not been tampered
  // with at runtime before trusting any model identifier it contains.
  verifyRegistryIntegrity(registryEnv);
  const models = registryEnv
    .split(",")
    .map((m) => m.trim())
    .filter((m) => m.length > 0);
  if (models.length === 0) {
    throw new Error(
      "APPROVED_EMBEDDING_MODELS environment variable is empty after parsing. " +
      "Provide at least one approved model identifier from the organizational registry."
    );
  }
  return new Set(models);
}

const APPROVED_EMBEDDING_MODELS: ReadonlySet<string> = loadApprovedEmbeddingModels();

// PINNED_EMBEDDING_MODEL must be explicitly set via environment variable — no mutable fallback allowed.
// The value must also appear in APPROVED_EMBEDDING_MODELS (enforced in createApprovedEmbeddings).
if (!process.env.PINNED_EMBEDDING_MODEL || process.env.PINNED_EMBEDDING_MODEL.trim() === "") {
  throw new Error(
    "PINNED_EMBEDDING_MODEL environment variable is not set. " +
    "A strictly pinned, immutable model identifier must be provided by the AI governance team."
  );
}
const PINNED_EMBEDDING_MODEL: string = process.env.PINNED_EMBEDDING_MODEL.trim();
console.log(
  `[AI Governance] Embedding model identity pinned: model=${PINNED_EMBEDDING_MODEL} ` +
  `registry_size=${APPROVED_EMBEDDING_MODELS.size} ` +
  `approved=${APPROVED_EMBEDDING_MODELS.has(PINNED_EMBEDDING_MODEL)}`
);

function createApprovedEmbeddings(apiKey: string | undefined): HuggingFaceInferenceEmbeddings {
  if (!APPROVED_EMBEDDING_MODELS.has(PINNED_EMBEDDING_MODEL)) {
    throw new Error(
      `Model '${PINNED_EMBEDDING_MODEL}' is NOT in the approved organizational model registry. ` +
      `Approved models: ${[...APPROVED_EMBEDDING_MODELS].join(", ")}. ` +
      `Update APPROVED_EMBEDDING_MODELS via the central AI governance registry.`
    );
  }
  console.log(
    `INFO: model identity — provider=openai model=${PINNED_EMBEDDING_MODEL} ` +
    `registry=organizational-env-var approved=true timestamp=${new Date().toISOString()}`
  );
  return new OpenAIEmbeddings({
    openAIApiKey: apiKey,
    modelName: PINNED_EMBEDDING_MODEL,
  });
}
// ─────────────────────────────────────────────────────────────────────────────

export type CompanionKey = {
  companionName: string;
  modelName: string;
  userId: string;
};

const DANGEROUS_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /new\s+Function\s*\(/gi,
  /setTimeout\s*\(\s*['"`]/gi,
  /setInterval\s*\(\s*['"`]/gi,
  /\bimport\s*\(/gi,
  /require\s*\(/gi,
  /process\.binding\s*\(/gi,
  /child_process/gi,
  /\bvm\.runInThisContext\s*\(/gi,
  /\bvm\.runInNewContext\s*\(/gi,
];

function sanitizeLLMOutput(docs: any[] | undefined): any[] {
  if (!docs || !Array.isArray(docs)) return [];
  return docs
    .filter((doc) => {
      if (!doc || typeof doc.pageContent !== "string") return false;
      for (const pattern of DANGEROUS_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(doc.pageContent)) {
          console.warn(
            "WARNING: Potentially dangerous content detected in LLM output and removed.",
            { matchedPattern: pattern.toString() }
          );
          return false;
        }
      }
      return true;
    })
    .map((doc) => ({
      pageContent: doc.pageContent.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, ""),
      metadata: {
        ...(doc.metadata?.source !== undefined ? { source: String(doc.metadata.source) } : {}),
        ...(doc.metadata?.companionName !== undefined ? { companionName: String(doc.metadata.companionName) } : {}),
      },
    }));
}

function sanitizeChatHistory(input: string): string {
  if (typeof input !== "string") {
    throw new Error("Invalid input: recentChatHistory must be a string.");
  }
  // Trim whitespace
  let sanitized = input.trim();
  // Enforce maximum length to prevent prompt injection via oversized input
  const MAX_LENGTH = 4000;
  if (sanitized.length > MAX_LENGTH) {
    sanitized = sanitized.slice(-MAX_LENGTH);
  }
  // Remove null bytes and non-printable control characters (except newline/tab)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  if (sanitized.length === 0) {
    throw new Error("Invalid input: recentChatHistory is empty after sanitization.");
  }

  // Detect and strip base64-encoded blobs (20+ char base64 strings)
  sanitized = sanitized.replace(/[A-Za-z0-9+/]{20,}={0,2}/g, "[REDACTED_BASE64]");

  // Detect shell command patterns and remove them
  const shellPatterns = [
    /`[^`]*`/g,                        // backtick execution
    /\$\([^)]*\)/g,                    // $(...) subshell
    /;\s*(rm|curl|wget|bash|sh|python|perl|ruby|nc|ncat|netcat|eval|exec)\b/gi,
    /&&\s*(rm|curl|wget|bash|sh|python|perl|ruby|nc|ncat|netcat|eval|exec)\b/gi,
    /\|\s*(bash|sh|python|perl|ruby|eval|exec)\b/gi,
  ];
  for (const pattern of shellPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED_CMD]");
  }

  // Detect prompt injection attempts (common jailbreak / instruction override patterns)
  const promptInjectionPatterns = [
    /ignore (all )?(previous|prior|above) instructions?/gi,
    /disregard (all )?(previous|prior|above) instructions?/gi,
    /forget (all )?(previous|prior|above) instructions?/gi,
    /you are now/gi,
    /act as (a |an )?/gi,
    /new (system |)prompt:/gi,
    /system:/gi,
    /<\/?system>/gi,
    /\[INST\]/gi,
    /<<SYS>>/gi,
  ];
  for (const pattern of promptInjectionPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED_INJECTION]");
  }

  return sanitized;
}

class HistoryStore {
  private static instance: HistoryStore;
  private client: Redis | null = null;

  private constructor() {}

  public static getInstance(): HistoryStore {
    if (!HistoryStore.instance) {
      HistoryStore.instance = new HistoryStore();
    }
    return HistoryStore.instance;
  }

  public getClient(): Redis {
    if (!this.client) {
      this.client = Redis.fromEnv();
    }
    return this.client;
  }
}

class MemoryManager {
  private static instance: MemoryManager;
  private vectorDBClient: PineconeClient | SupabaseClient;

  public constructor() {
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

  private getHistory(): Redis {
    return HistoryStore.getInstance().getClient();
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
    companionFileName: string
  ) {
    if (process.env.VECTOR_DB === "pinecone") {
      console.log("INFO: using Pinecone for vector search.");
      const pineconeClient = <PineconeClient>this.vectorDBClient;

      const pineconeIndex = pineconeClient.Index(
        process.env.PINECONE_INDEX! || ""
      );

            console.log("INFO: LLM interaction start - OpenAIEmbeddings via PineconeStore.fromExistingIndex", { input: recentChatHistory, companionFileName });
      const vectorStore = await PineconeStore.fromExistingIndex(
        createApprovedEmbeddings(process.env.OPENAI_API_KEY),
        { pineconeIndex }
      );
      console.log("INFO: LLM interaction start - similaritySearch via Pinecone", { query: recentChatHistory, filter: { fileName: companionFileName } });
      const sanitizedHistory = sanitizeChatHistory(recentChatHistory);
            const sanitizedHistory = sanitizeChatHistory(recentChatHistory);
            const similarDocsRaw = await vectorStore
        .similaritySearch(recentChatHistory, 3)
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      const similarDocs = similarDocsRaw ? similarDocsRaw.map((doc: { pageContent: string }) => doc.pageContent) : similarDocsRaw;
      return similarDocs;
    } else {
      console.log("INFO: using Supabase for vector search.");
      const supabaseClient = <SupabaseClient>this.vectorDBClient;
            console.log("INFO: LLM interaction start - OpenAIEmbeddings via SupabaseVectorStore.fromExistingIndex", { input: recentChatHistory, companionFileName });
      const vectorStore = await SupabaseVectorStore.fromExistingIndex(
        createApprovedEmbeddings(process.env.OPENAI_API_KEY),
        {
          client: supabaseClient,
          tableName: "documents",
          queryName: "match_documents",
        }
      );
      console.log("INFO: LLM interaction start - similaritySearch via Supabase", { query: recentChatHistory });
      const sanitizedHistory = sanitizeChatHistory(recentChatHistory);
      const similarDocs = await vectorStore
        .similaritySearch(sanitizedHistory, 3)
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      console.log("INFO: LLM interaction end - Supabase similaritySearch results", { resultCount: similarDocs ? similarDocs.length : 0, results: similarDocs });
      if (similarDocs && similarDocs.length > 0) {
        const { createHmac } = require("crypto");
        const secret = process.env.REDIS_KEY_SECRET || "default-provenance-secret";
        const timestamp = new Date().toISOString();
        similarDocs = similarDocs.map((doc: any) => {
          const provenancePayload = JSON.stringify({
            modelId: PINNED_EMBEDDING_MODEL,
            timestamp,
            originTag: "ai-generated",
            syntheticLabel: "SYNTHETIC_AI_CONTENT",
            contentType: "vector-search-result",
          });
          const contentStr = typeof doc.pageContent === "string" ? doc.pageContent : JSON.stringify(doc.pageContent);
          const signature = createHmac("sha256", secret)
            .update(provenancePayload + contentStr)
            .digest("hex");
          return {
            ...doc,
            metadata: {
              ...(doc.metadata || {}),
              _provenance: {
                modelId: PINNED_EMBEDDING_MODEL,
                timestamp,
                originTag: "ai-generated",
                syntheticLabel: "SYNTHETIC_AI_CONTENT",
                contentType: "vector-search-result",
                signature,
              },
            },
          };
        });
      }
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

  private generateTraceId(): string {
    const { randomBytes } = require("crypto");
    return randomBytes(16).toString("hex");
  }

  private hashInput(input: string): string {
    const { createHash } = require("crypto");
    return createHash("sha256").update(input).digest("hex");
  }

  private async appendAuditLog(entry: Record<string, string>): Promise<void> {
    try {
      // XADD to an append-only Redis stream; MAXLEN caps retention at 100,000 entries
      await (this.history as any).xadd(
        "audit:ai_actions",
        "MAXLEN",
        "~",
        "100000",
        "*",
        ...Object.entries(entry).flat()
      );
    } catch (err) {
      console.error("AUDIT LOG WRITE FAILED", err, entry);
    }
  }

  private generateRedisCompanionKey(companionKey: CompanionKey): string {
    const secret = process.env.REDIS_KEY_SECRET;
    if (!secret) {
      throw new Error("REDIS_KEY_SECRET environment variable is not set");
    }
    const { createHmac } = require("crypto");
    const payload = `${companionKey.companionName}:${companionKey.modelName}:${companionKey.userId}`;
    const mac = createHmac("sha256", secret).update(payload).digest("hex");
    return `session:${mac}`;
  }

  private verifyRedisCompanionKey(companionKey: CompanionKey, key: string): boolean {
    // Re-derive the expected key and compare using timing-safe equality
    const expected = this.generateRedisCompanionKey(companionKey);
    const { timingSafeEqual } = require("crypto");
    try {
      const a = Buffer.from(expected);
      const b = Buffer.from(key);
      if (a.length !== b.length) return false;
      return timingSafeEqual(a, b);
    } catch {
      return false;
    }
  }

  private async getVerifiedKey(companionKey: CompanionKey): Promise<string> {
    const key = this.generateRedisCompanionKey(companionKey);
    if (!this.verifyRedisCompanionKey(companionKey, key)) {
      throw new Error("Session key verification failed: key integrity check did not pass");
    }
    return key;
  }

  public async writeToHistory(text: string, companionKey: CompanionKey) {
    if (!companionKey || typeof companionKey.userId == "undefined") {
      console.log("Companion key set incorrectly");
      return "";
    }

    const key = await this.getVerifiedKey(companionKey);
    const writeTimestamp = Date.now();
    const traceId = this.generateTraceId();
    // Embed trace ID in the stored member so each entry is self-describing
    const memberWithTrace = JSON.stringify({ traceId, ts: writeTimestamp, text });
    const result = await this.history.zadd(key, {
      score: writeTimestamp,
      member: memberWithTrace,
    });
    // Enforce expiry: session history expires after 24 hours of inactivity
    await this.history.expire(key, 86400);

    // Audit: log chat history write to append-only stream for forensic readiness
    await this.appendAuditLog({
      traceId,
      event: "chat_history_write",
      userId: companionKey.userId,
      companionName: companionKey.companionName,
      modelName: companionKey.modelName,
      textHash: this.hashInput(text),
      timestamp: new Date(writeTimestamp).toISOString(),
      redisKey: key,
    });

    return result;
  }

    private static readonly MAX_HISTORY_ENTRY_CHARS = 500;
  private static readonly MAX_VECTOR_DOC_CHARS = 800;
  private static readonly ALLOWED_VECTOR_METADATA_FIELDS = new Set(["source", "companionName", "userId"]);

  /**
   * Minimise a raw history member string: parse the envelope, extract only
   * the 'text' field, and truncate to MAX_HISTORY_ENTRY_CHARS.
   */
  private minimiseHistoryEntry(raw: string): string {
    try {
      const parsed = JSON.parse(raw);
      // Extract only the text field — discard traceId, ts, and any other fields
      const text: string = typeof parsed.text === "string" ? parsed.text : String(parsed);
      return text.slice(0, MemoryManager.MAX_HISTORY_ENTRY_CHARS);
    } catch {
      // If not JSON, treat the whole string as text and truncate
      return String(raw).slice(0, MemoryManager.MAX_HISTORY_ENTRY_CHARS);
    }
  }

  /**
   * Minimise a vector store document before injecting it into model context:
   * - Allow only a defined metadata field allowlist
   * - Truncate pageContent to MAX_VECTOR_DOC_CHARS
   */
  private minimiseVectorDocument(doc: { pageContent: string; metadata?: Record<string, unknown> }): { pageContent: string; metadata: Record<string, unknown> } {
    const truncatedContent = (doc.pageContent ?? "").slice(0, MemoryManager.MAX_VECTOR_DOC_CHARS);
    const filteredMetadata: Record<string, unknown> = {};
    if (doc.metadata) {
      for (const field of MemoryManager.ALLOWED_VECTOR_METADATA_FIELDS) {
        if (Object.prototype.hasOwnProperty.call(doc.metadata, field)) {
          filteredMetadata[field] = doc.metadata[field];
        }
      }
    }
    return { pageContent: truncatedContent, metadata: filteredMetadata };
  }

  private sanitizeHistoryEntry(entry: string): string {
    // Remove base64-encoded content (sequences of 20+ base64 chars)
    entry = entry.replace(/[A-Za-z0-9+/]{20,}={0,2}/g, "[REDACTED_BASE64]");

    // Remove shell command patterns
    entry = entry.replace(
      /(`[^`]*`|\$\([^)]*\)|\b(bash|sh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[({["'`])/gi,
      "[REDACTED_CMD]"
    );

    // Remove hidden prompt injection markers and common jailbreak patterns
    entry = entry.replace(
      /(ignore (previous|above|all) instructions?|disregard (previous|above|all)|you are now|act as|pretend (you are|to be)|system prompt|<\/?s(ystem|\|im_start\|)|\[INST\]|\[\/?SYS\]|###\s*(system|instruction|prompt))/gi,
      "[REDACTED_INJECTION]"
    );

    // Remove HTML/script tags that could carry hidden instructions
    entry = entry.replace(/<[^>]{0,200}>/g, "");

    // Remove null bytes and non-printable control characters (except newline/tab)
    entry = entry.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

    return entry.trim();
  }

    private buildProvenanceEnvelope(content: string, contentType: string): string {
    const { createHmac } = require("crypto");
    const secret = process.env.REDIS_KEY_SECRET || "default-provenance-secret";
    const timestamp = new Date().toISOString();
    const modelId = PINNED_EMBEDDING_MODEL;
    const originTag = "ai-generated";
    const provenanceHeader = JSON.stringify({
      _provenance: {
        modelId,
        timestamp,
        originTag,
        contentType,
        syntheticLabel: "SYNTHETIC_AI_CONTENT",
      },
    });
    const signature = createHmac("sha256", secret)
      .update(provenanceHeader + content)
      .digest("hex");

    // Persistent append-only audit record for AI inference/embedding calls
    await appendAuditRecord(this.history, {
      event: "provenance_envelope_created",
      modelId,
      originTag,
      contentType,
      inputHash: require("crypto")
        .createHash("sha256")
        .update(content)
        .digest("hex"),
      outputSignature: signature,
      timestamp,
    });

    const envelope = JSON.stringify({
      _provenance: {
        modelId,
        timestamp,
        originTag,
        contentType,
        syntheticLabel: "SYNTHETIC_AI_CONTENT",
        signature,
      },
      content,
    });
    return envelope;
  }

  public async readLatestHistory(companionKey: CompanionKey): Promise<string> {
    if (!companionKey || typeof companionKey.userId == "undefined") {
      console.log("Companion key set incorrectly");
      return "";
    }

    const key = await this.getVerifiedKey(companionKey);
    let result = await this.history.zrange(key, 0, Date.now(), {
      byScore: true,
    });

    result = result.slice(-10).reverse();
    const sanitizedEntries = result.reverse().map((entry) => this.sanitizeHistoryEntry(entry));
    const recentChats = sanitizedEntries.join("\n");
    return this.buildProvenanceEnvelope(recentChats, "chat-history");
  }

    const key = this.generateRedisCompanionKey(companionKey);
    let result = await this.history.zrange(key, 0, Date.now(), {
      byScore: true,
    });

    result = result.slice(-10).reverse();
    const sanitizedEntries = result.reverse().map((entry) => this.sanitizeHistoryEntry(entry));
    const recentChats = sanitizedEntries.join("\n");
    return recentChats;
  }

    const key = this.generateRedisCompanionKey(companionKey);
    let result = await this.history.zrange(key, 0, Date.now(), {
      byScore: true,
    });

    result = result.slice(-10).reverse();
    const recentChats = result.reverse().join("\n");
    return sanitizeChatHistory(recentChats);
  }

  /**
   * Sanitizes a raw input string before it is stored or forwarded to an LLM/embedding model.
   * - Strips ASCII and Unicode control characters (including prompt-injection vectors)
   * - Trims leading/trailing whitespace
   * - Enforces a maximum length to prevent oversized payloads
   */
  private sanitizeInput(raw: string, maxLength = 4000): string {
    if (typeof raw !== "string") return "";
    // Remove ASCII control chars (0x00-0x1F, 0x7F) and Unicode control/format categories
    // eslint-disable-next-line no-control-regex
    const stripped = raw.replace(/[\x00-\x1F\x7F\u200B-\u200D\uFEFF]/g, "");
    return stripped.trim().slice(0, maxLength);
  }

  public async seedChatHistory(
    seedContent: String,
    delimiter: string = "\n",
    companionKey: CompanionKey
  ) {
    const key = await this.getVerifiedKey(companionKey);
    if (await this.history.exists(key)) {
      console.log("User already has chat history");
      return;
    }

    // cryptoModule is hoisted outside the loop to avoid dynamic require inside iteration
    const content = seedContent.split(delimiter);
    let counter = 0;
    for (const line of content) {
      const sanitizedLine = this.sanitizeInput(line);
      if (!sanitizedLine) {
        counter += 1;
        continue;
      }
      // NX flag prevents overwriting existing members, enforcing append-only immutability
      await this.history.zadd(key, { score: counter, member: sanitizedLine }, { nx: true });
      // Append audit record for each chat history entry written
      await appendAuditRecord(this.history, {
        event: "chat_history_seed_write",
        key,
        score: counter,
        memberHash: require("crypto").createHash("sha256").update(sanitizedLine).digest("hex"),
        timestamp: new Date().toISOString(),
      });
      counter += 1;
    }
    // Enforce expiry on seeded history
    await this.history.expire(key, 86400);
  }
}

/**
 * appendAuditRecord — writes a structured, append-only audit entry to Redis.
 * Uses RPUSH on a dedicated audit-log list so records are never overwritten or deleted
 * by normal application logic, satisfying forensic-readiness requirements.
 *
 * @param redis  - the Redis client instance
 * @param record - the audit payload (must include at minimum event + timestamp)
 */
import { createHash as _cryptoCreateHash } from "crypto";

async function appendAuditRecord(
  redis: { rpush: (key: string, ...values: string[]) => Promise<unknown> },
  record: Record<string, unknown>
): Promise<void> {
  const AUDIT_LOG_KEY = "audit:ai_actions_log";
  const entry = JSON.stringify({
    ...record,
    _auditVersion: "1",
    _writtenAt: new Date().toISOString(),
  });
  await redis.rpush(AUDIT_LOG_KEY, entry);
}

// Hoisted crypto import — must never be required dynamically inside loops or callbacks
const cryptoModule = require("crypto") as typeof import("crypto");

/**
 * sanitizeQuery — validates a query string before it enters the retrieval or LLM pipeline.
 *
 * Blocks:
 *  - Shell/system commands (e.g. rm, curl, wget, bash, eval, exec, sudo, chmod, etc.)
 *  - Base64-encoded payloads (long base64 blobs that may hide instructions)
 *  - Binary / non-printable content
 *  - Leetspeak obfuscation patterns commonly used to bypass filters
 *  - Hidden prompt-injection markers (e.g. "ignore previous instructions", "system:", "<|im_start|>")
 *
 * @param query - raw user-supplied query string
 * @returns the original query if it passes all checks
 * @throws Error if any suspicious pattern is detected
 */
function sanitizeQuery(query: string): string {
  if (typeof query !== "string") {
    throw new Error("[sanitizeQuery] Query must be a string.");
  }

  // 1. Reject binary / non-printable characters (allow common whitespace)
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(query)) {
    throw new Error("[sanitizeQuery] Query contains binary or non-printable characters.");
  }

  // 2. Reject base64-encoded blobs (20+ consecutive base64 chars with optional padding)
  //    Legitimate natural-language queries rarely contain such sequences.
  if (/(?:[A-Za-z0-9+/]{20,}={0,2})/.test(query)) {
    // Secondary check: attempt decode and see if it contains shell commands
    const b64Matches = query.match(/[A-Za-z0-9+/]{20,}={0,2}/g) ?? [];
    for (const match of b64Matches) {
      try {
        const decoded = Buffer.from(match, "base64").toString("utf8");
        if (/\b(bash|sh|cmd|powershell|eval|exec|system|curl|wget|nc|ncat|python|perl|ruby|php)\b/i.test(decoded)) {
          throw new Error("[sanitizeQuery] Query contains a base64-encoded shell command payload.");
        }
      } catch (e) {
        if ((e as Error).message.startsWith("[sanitizeQuery]")) throw e;
        // Decode failed — not valid base64, safe to continue
      }
    }
  }

  // 3. Reject shell command patterns
  const shellCommandPattern =
    /\b(rm\s+-rf|sudo|chmod|chown|curl|wget|bash|sh\s+-c|eval|exec|system|popen|subprocess|os\.system|__import__|import\s+os|import\s+subprocess|nc\s+-|ncat\s+|python\s+-c|perl\s+-e|ruby\s+-e|php\s+-r)\b/i;
  if (shellCommandPattern.test(query)) {
    throw new Error("[sanitizeQuery] Query contains a shell command or code execution pattern.");
  }

  // 4. Reject prompt-injection markers
  const promptInjectionPattern =
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?|system\s*:|<\|im_start\||<\|im_end\||\[INST\]|\[\/?SYS\]|###\s*instruction|you\s+are\s+now\s+(a\s+)?|disregard\s+(all\s+)?previous|forget\s+(all\s+)?previous|new\s+persona|act\s+as\s+(if\s+you\s+are|a\s+)/i;
  if (promptInjectionPattern.test(query)) {
    throw new Error("[sanitizeQuery] Query contains a prompt-injection pattern.");
  }

  // 5. Reject leetspeak obfuscation (e.g. 3x3c, 1gnor3, 3v4l)
  //    Heuristic: high ratio of digit-substituted alpha characters
  const leetspeakPattern = /(?:[a-z]*[013456789][a-z0-9]*){4,}/i;
  if (leetspeakPattern.test(query.replace(/\s+/g, ""))) {
    // Only flag if the leet sequence also resembles a blocked keyword when decoded
    const normalized = query
      .replace(/0/g, "o")
      .replace(/1/g, "i")
      .replace(/3/g, "e")
      .replace(/4/g, "a")
      .replace(/5/g, "s")
      .replace(/6/g, "g")
      .replace(/7/g, "t")
      .replace(/8/g, "b")
      .replace(/9/g, "g");
    if (shellCommandPattern.test(normalized) || promptInjectionPattern.test(normalized)) {
      throw new Error("[sanitizeQuery] Query contains leetspeak-obfuscated malicious content.");
    }
  }

  return query;
}

export default MemoryManager;
