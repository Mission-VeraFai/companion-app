// Redis removed: replaced with in-memory store to stay within 3-credential limit
import { HuggingFaceInferenceEmbeddings } from "langchain/embeddings/hf";
import { PineconeClient } from "@pinecone-database/pinecone";
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { SupabaseClient, createClient } from "@supabase/supabase-js";

const DANGEROUS_PATTERNS = [
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
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

function sanitizeDocs(docs: any[] | undefined): any[] {
  if (!docs || !Array.isArray(docs)) return [];
  return docs.filter((doc) => {
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
}

const APPROVED_EMBEDDING_MODELS: ReadonlySet<string> = new Set([
  "text-embedding-ada-002",
]);

const PINNED_EMBEDDING_MODEL = "text-embedding-ada-002";

function createApprovedEmbeddings(): OpenAIEmbeddings {
  if (!APPROVED_EMBEDDING_MODELS.has(PINNED_EMBEDDING_MODEL)) {
    throw new Error(
      `Model '${PINNED_EMBEDDING_MODEL}' is not in the approved model registry. ` +
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

function sanitizeInput(input: string): string {
  if (typeof input !== "string") {
    throw new Error("Invalid input: recentChatHistory must be a string.");
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
  sanitized = sanitized.replace(
    /(`[^`]*`|\$\([^)]*\)|\|\s*\w+|&&|;\s*\w+|>\s*\/|<\s*\/|\bsudo\b|\brm\b|\bchmod\b|\bchown\b|\bcurl\b|\bwget\b|\beval\b|\bexec\b)/gi,
    "[REDACTED]"
  );
  // Remove base64-encoded or URL-encoded payloads (heuristic: long unbroken alphanum strings)
  sanitized = sanitized.replace(
    /(?:[A-Za-z0-9+/]{40,}={0,2})/g,
    "[REDACTED]"
  );
  // Remove null bytes and other non-printable control characters
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  return sanitized.trim();
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
    companionFileName: string
  ) {
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
            const sanitizedHistory = sanitizeInput(recentChatHistory);
            const sanitizedHistory = sanitizeInput(recentChatHistory);
            const similarDocsRaw = await vectorStore
        .similaritySearch(recentChatHistory, 3)
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
    // Refresh expiry on every write; sessions expire after 24 hours of inactivity
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

    const MAX_HISTORY_ENTRIES = 10;
    const MAX_ENTRY_LENGTH = 200;
    result = result.slice(-MAX_HISTORY_ENTRIES).reverse();
    const recentChats = result
      .reverse()
      .map((entry: string) => entry.slice(0, MAX_ENTRY_LENGTH))
      .join("\n");
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
  }
}

export default MemoryManager;
