import { Redis } from "@upstash/redis";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";
import { PineconeClient } from "@pinecone-database/pinecone";
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { SupabaseClient, createClient } from "@supabase/supabase-js";

// ── Model registry ────────────────────────────────────────────────────────────
const APPROVED_EMBEDDING_MODELS: ReadonlySet<string> = new Set([
  "text-embedding-ada-002",
]);

const PINNED_EMBEDDING_MODEL = "text-embedding-ada-002";

function createApprovedEmbeddings(apiKey: string | undefined): OpenAIEmbeddings {
  if (!APPROVED_EMBEDDING_MODELS.has(PINNED_EMBEDDING_MODEL)) {
    throw new Error(
      `Model '${PINNED_EMBEDDING_MODEL}' is NOT in the approved model registry. ` +
      `Approved models: ${[...APPROVED_EMBEDDING_MODELS].join(", ")}`
    );
  }
  console.log(
    `INFO: model identity — provider=openai model=${PINNED_EMBEDDING_MODEL} ` +
    `registry=approved timestamp=${new Date().toISOString()}`
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
      ...doc,
      pageContent: doc.pageContent.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, ""),
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
  return sanitized;
}

function sanitizeChatHistory(input: string): string {
  // Remove null bytes and non-printable control characters (except common whitespace)
  let sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

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

  // Truncate to a safe maximum length to prevent oversized payloads
  const MAX_LENGTH = 4000;
  if (sanitized.length > MAX_LENGTH) {
    sanitized = sanitized.slice(-MAX_LENGTH);
  }

  return sanitized;
}

class MemoryManager {
  private static instance: MemoryManager;
  private history: Redis | null = null;
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
    if (!this.history) {
      this.history = Redis.fromEnv();
    }
    return this.history;
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
    const mac = createHmac("sha256", secret).update(payload).digest("hex");
    return `session:${mac}`;
  }

  public async writeToHistory(text: string, companionKey: CompanionKey) {
    if (!companionKey || typeof companionKey.userId == "undefined") {
      console.log("Companion key set incorrectly");
      return "";
    }

    const key = this.generateRedisCompanionKey(companionKey);
    const result = await this.history.zadd(key, {
      score: Date.now(),
      member: text,
    });
    // Enforce expiry: session history expires after 24 hours of inactivity
    await this.history.expire(key, 86400);

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

    result = result.slice(-10).reverse();
    const recentChats = result.reverse().join("\n");
    return recentChats;
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

    const content = seedContent.split(delimiter);
    let counter = 0;
    for (const line of content) {
      await this.history.zadd(key, { score: counter, member: line });
      counter += 1;
    }
    // Enforce expiry on seeded history
    await this.history.expire(key, 86400);
  }
}

export default MemoryManager;
