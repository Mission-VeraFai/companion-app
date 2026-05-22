// Call embeding API and insert to supabase
// Ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/supabase

import dotenv from "dotenv";
// Credential policy: This script is permitted to hold credentials for at most
// ONE external AI service and ONE external storage service.
// Do NOT add credentials for additional external systems (e.g. Pinecone, audit APIs).
// All credential access must go through getClient() below.
import { AzureOpenAI } from "openai";
import { createClient } from "@supabase/supabase-js";

// Credential broker: centralises and limits external system credential usage.
// Only two external systems are permitted: Azure OpenAI (AI) and Supabase (storage).
function getAzureOpenAIClient() {
  const { AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_VERSION } = process.env;
  if (!AZURE_OPENAI_API_KEY || !AZURE_OPENAI_ENDPOINT) {
    throw new Error("Missing required Azure OpenAI credentials.");
  }
  return new AzureOpenAI({
    apiKey: AZURE_OPENAI_API_KEY,
    endpoint: AZURE_OPENAI_ENDPOINT,
    apiVersion: AZURE_OPENAI_API_VERSION,
  });
}

function getSupabaseClient() {
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("Missing required Supabase credentials.");
  }
  return createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
}

import fs from "fs";
import path from "path";
import crypto from "crypto";

// Singapore PII detection patterns
const SINGAPORE_PII_PATTERNS = [
  // NRIC/FIN numbers (S/T/F/G followed by 7 digits and a letter)
  { name: "NRIC/FIN", pattern: /\b[STFG]\d{7}[A-Z]\b/i },
  // Singapore phone numbers (+65 or local 8-digit starting with 6, 8, or 9)
  { name: "SG Phone Number", pattern: /(?:\+65[\s-]?)?[689]\d{7}\b/ },
  // Singapore postal codes (6-digit starting with valid prefix)
  { name: "SG Postal Code", pattern: /\bSingapore\s+\d{6}\b/i },
  // Passport numbers (general international format)
  { name: "Passport Number", pattern: /\b[A-Z]{1,2}\d{6,9}\b/ },
  // Email addresses
  { name: "Email Address", pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/ },
  // Singapore bank account numbers (typically 10 digits)
  { name: "Bank Account", pattern: /\b\d{3}-\d{5}-\d{1,3}\b/ },
  // Date of birth patterns
  { name: "Date of Birth", pattern: /\bDOB[:\s]+\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4}\b/i },
];

function detectSingaporePII(content) {
  const detectedPII = [];
  for (const { name, pattern } of SINGAPORE_PII_PATTERNS) {
    if (pattern.test(content)) {
      detectedPII.push(name);
    }
  }
  return detectedPII;
}

/**
 * Redacts common PII patterns from a string.
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
  // Credit/debit card numbers (13–16 digits, optionally separated by spaces or dashes)
  text = text.replace(/\b(?:\d[ -]?){13,16}\b/g, "[REDACTED_CARD]");
  // Names preceded by common honorifics
  text = text.replace(/\b(Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*/g, "[REDACTED_NAME]");
  return text;
}

/**
 * Sanitizes file content to prevent prompt injection attacks.
 * Checks for hidden prompts, base64-encoded payloads, leetspeak,
 * shell commands, and other malicious content patterns.
 * Throws an error if suspicious content is detected.
 */
function sanitizeFileContent(content, fileName) {
  // Check for common prompt injection patterns (case-insensitive)
  const promptInjectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /you\s+are\s+now\s+(a\s+)?(?!a\s+companion)/i,
    /act\s+as\s+(if\s+you\s+are\s+)?(?!a\s+companion)/i,
    /new\s+(role|persona|identity|instructions?|prompt|task|objective)/i,
    /system\s*:\s*(you|your|ignore|forget|disregard)/i,
    /\[\s*(system|user|assistant|human|ai)\s*\]/i,
    /<\s*(system|instructions?|prompt)\s*>/i,
    /###\s*(system|instructions?|new\s+task|override)/i,
  ];

  // Check for base64-encoded content (long base64 strings are suspicious)
  const base64Pattern = /[A-Za-z0-9+/]{50,}={0,2}/;

  // Check for shell command injection patterns
  const shellCommandPatterns = [
    /`[^`]{0,200}`/,                          // backtick execution
    /\$\([^)]{0,200}\)/,                      // $() subshell
    /;\s*(rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat)\s/i,
    /\|\s*(bash|sh|python|perl|ruby|nc|ncat|netcat)\s/i,
    /&&\s*(rm|wget|curl|bash|sh|python|perl|ruby)\s/i,
  ];

  // Check for leetspeak obfuscation (simple heuristic: high ratio of digit-letter substitutions)
  const leetspeakPattern = /(?:[i1][g9][n][o0][r][e3]|[d][i1][s5][r][e3][g9][a4][r][d]|[f][o0][r][g9][e3][t7])/i;

  // Check for hidden/invisible unicode characters used for obfuscation
  const hiddenCharsPattern = /[​-‏‪-‮⁠-⁤﻿]/;

  // Check for excessive repetition of instruction-like keywords
  const instructionKeywords = (content.match(/\b(instruction|prompt|ignore|system|override|jailbreak|bypass)\b/gi) || []).length;

  const violations = [];

  for (const pattern of promptInjectionPatterns) {
    if (pattern.test(content)) {
      violations.push(`Prompt injection pattern detected: ${pattern}`);
    }
  }

  if (base64Pattern.test(content)) {
    violations.push("Suspicious base64-encoded content detected");
  }

  for (const pattern of shellCommandPatterns) {
    if (pattern.test(content)) {
      violations.push(`Shell command pattern detected: ${pattern}`);
    }
  }

  if (leetspeakPattern.test(content)) {
    violations.push("Leetspeak obfuscation pattern detected");
  }

  if (hiddenCharsPattern.test(content)) {
    violations.push("Hidden/invisible unicode characters detected");
  }

  if (instructionKeywords > 10) {
    violations.push(`Excessive instruction-related keywords detected (${instructionKeywords} occurrences)`);
  }

  if (violations.length > 0) {
    throw new Error(
      `Malicious content detected in companion file "${fileName}": ${violations.join("; ")}`
    );
  }

  return content;
}

dotenv.config({ path: `.env.local` });

// External credentialed systems used by this script (limit: 2):
// 1. Supabase  — SUPABASE_URL + SUPABASE_PRIVATE_KEY
// 2. OpenAI    — OPENAI_API_KEY
const REQUIRED_ENV_VARS = ["SUPABASE_URL", "SUPABASE_PRIVATE_KEY", "OPENAI_API_KEY"];
const missingVars = REQUIRED_ENV_VARS.filter((v) => !process.env[v]);
if (missingVars.length > 0) {
  throw new Error(`Missing required environment variables: ${missingVars.join(", ")}`);
}

// Sanitize and validate text before sending to the LLM embedding API
function sanitizeContent(text) {
  if (typeof text !== "string") {
    throw new TypeError("File content must be a string");
  }
  // Remove null bytes
  let sanitized = text.replace(/\0/g, "");
  // Remove non-printable ASCII control characters (except newline, carriage return, tab)
  sanitized = sanitized.replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Trim leading/trailing whitespace
  sanitized = sanitized.trim();
  // Enforce a maximum content length to prevent oversized payloads (1MB)
  const MAX_LENGTH = 1_000_000;
  if (sanitized.length > MAX_LENGTH) {
    sanitized = sanitized.slice(0, MAX_LENGTH);
  }
  if (sanitized.length === 0) {
    throw new Error("File content is empty after sanitization");
  }
  return sanitized;
}

const fileNames = fs.readdirSync("companions");
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

/**
 * Checks text for prompt injection patterns, base64-encoded payloads,
 * shell commands, and other malicious content before passing to the AI pipeline.
 * Throws an error if suspicious content is detected.
 */
function sanitizeForAIPipeline(text, sourceFile) {
  // Detect common prompt injection / jailbreak phrases
  const promptInjectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /you\s+are\s+now\s+(a\s+)?(?!a companion)/i,
    /act\s+as\s+(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken|DAN)/i,
    /do\s+anything\s+now/i,
    /jailbreak/i,
    /\bDAN\b/,
    /override\s+(your\s+)?(safety|content)\s+(filter|policy|guideline)/i,
    /bypass\s+(your\s+)?(safety|content)\s+(filter|policy|guideline)/i,
    /system\s*:\s*you\s+are/i,
    /<\s*system\s*>/i,
    /\[INST\]/i,
    /###\s*System/i,
  ];

  // Detect shell command patterns
  const shellCommandPatterns = [
    /`[^`]*`/,                          // backtick execution
    /\$\([^)]*\)/,                      // $(command) substitution
    /;\s*(rm|curl|wget|bash|sh|python|node|exec|eval)\s/i,
    /&&\s*(rm|curl|wget|bash|sh|python|node|exec|eval)\s/i,
    /\|\s*(bash|sh|python|node|exec|eval)\s/i,
    /\b(rm\s+-rf|chmod\s+777|curl\s+.*\|\s*bash|wget\s+.*\|\s*bash)\b/i,
  ];

  // Detect base64-encoded content (long base64 strings may hide payloads)
  const base64Pattern = /(?:[A-Za-z0-9+/]{40,}={0,2})/;

  // Detect URLs that could be used for exfiltration or SSRF
  const suspiciousUrlPattern = /https?://(?!.*\.(openai\.com|supabase\.co|supabase\.io))[^\s]{0,200}(?:exec|eval|cmd|shell|payload|inject)/i;

  for (const pattern of promptInjectionPatterns) {
    if (pattern.test(text)) {
      throw new Error(
        `Prompt injection pattern detected in file "${sourceFile}". Aborting indexing.`
      );
    }
  }

  for (const pattern of shellCommandPatterns) {
    if (pattern.test(text)) {
      throw new Error(
        `Shell command pattern detected in file "${sourceFile}". Aborting indexing.`
      );
    }
  }

  if (base64Pattern.test(text)) {
    // Attempt to decode and re-check decoded content for injection patterns
    const base64Matches = text.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || [];
    for (const match of base64Matches) {
      try {
        const decoded = Buffer.from(match, "base64").toString("utf8");
        for (const pattern of promptInjectionPatterns) {
          if (pattern.test(decoded)) {
            throw new Error(
              `Base64-encoded prompt injection detected in file "${sourceFile}". Aborting indexing.`
            );
          }
        }
        for (const pattern of shellCommandPatterns) {
          if (pattern.test(decoded)) {
            throw new Error(
              `Base64-encoded shell command detected in file "${sourceFile}". Aborting indexing.`
            );
          }
        }
      } catch (e) {
        if (e.message.includes("Aborting indexing")) throw e;
        // Not valid base64 — ignore decode errors
      }
    }
  }

  if (suspiciousUrlPattern.test(text)) {
    throw new Error(
      `Suspicious URL with potential command injection detected in file "${sourceFile}". Aborting indexing.`
    );
  }

  return text;
}

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (fileName.endsWith(".txt")) {
      const filePath = path.join("companions", fileName);
      const rawContent = fs.readFileSync(filePath, "utf8");
      const fileContent = redactPII(rawContent);
      const MAX_SECTION_CHARS = 8000;
      const rawLastSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      // Field-level filtering: remove metadata-style lines ("Key: Value" at line start)
      const filteredSection = rawLastSection
        .split("\n")
        .filter((line) => !/^[A-Za-z][\w\s]{0,30}:\s+\S/.test(line.trimStart()))
        .join("\n")
        .trim();
      // Size bounding: cap ingested content to prevent over-broad context injection
      const lastSection = filteredSection.slice(0, MAX_SECTION_CHARS);

      // Sanitize content before passing it into the AI pipeline
      const sanitizedSection = sanitizeForAIPipeline(lastSection, fileName);

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
      const fileContent = fs.readFileSync(filePath, "utf8");
      const detectedPII = detectSingaporePII(fileContent);
      if (detectedPII.length > 0) {
        throw new Error(
          `Singapore PII detected in file "${fileName}": ${detectedPII.join(", ")}. Upload aborted to protect personal data.`
        );
      }
      const rawSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      const lastSection = sanitizeContent(rawSection);
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

const auth = {
  detectSessionInUrl: true,
  persistSession: true,
  autoRefreshToken: true,
};

const client = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_PRIVATE_KEY,
  { auth }
);

// Patterns that indicate dynamic code execution primitives in LLM output
const DANGEROUS_CODE_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"`]/gi,
  /\bsetInterval\s*\(\s*['"`]/gi,
  /\bsetImmediate\s*\(\s*['"`]/gi,
  /\bprocess\.binding\s*\(/gi,
  /\brequire\s*\(/gi,
  /\bimport\s*\(/gi,
  /\b__import__\s*\(/gi,
  /\bexecSync\s*\(/gi,
  /\bspawnSync\s*\(/gi,
  /\bexecFile\s*\(/gi,
];

/**
 * Validates that LLM output does not contain dynamic code execution primitives.
 * Returns true if the content is safe, false if dangerous patterns are found.
 */
function containsDangerousCodePrimitive(content) {
  return DANGEROUS_CODE_PATTERNS.some((pattern) => pattern.test(content));
}

/**
 * Sanitizes LLM output by removing dangerous code execution patterns.
 * Logs a warning when dangerous content is detected and removed.
 */
function sanitizeLLMOutput(content) {
  if (containsDangerousCodePrimitive(content)) {
    console.warn(
      "[SECURITY WARNING] Dangerous code execution primitive detected in LLM output. Sanitizing content."
    );
    let sanitized = content;
    for (const pattern of DANGEROUS_CODE_PATTERNS) {
      sanitized = sanitized.replace(pattern, "[REDACTED]");
    }
    return sanitized;
  }
  return content;
}

/**
 * Validates and sanitizes all documents produced from LLM output before
 * indexing them into the vector store.
 */
function validateAndSanitizeDocs(docs) {
  return docs
    .filter((doc) => doc !== undefined)
    .map((doc) => {
      const sanitizedContent = sanitizeLLMOutput(doc.pageContent);
      return new Document({
        metadata: doc.metadata,
        pageContent: sanitizedContent,
      });
    });
}

const sanitizedDocs = validateAndSanitizeDocs(langchainDocs.flat());

if (sanitizedDocs.length === 0) {
  console.error("[ERROR] No valid documents to index after sanitization.");
  process.exit(1);
}

console.log(
  JSON.stringify({
    timestamp: new Date().toISOString(),
    event: "llm_interaction_start",
    model: "HuggingFaceInferenceEmbeddings",
    action: "SupabaseVectorStore.fromDocuments",
    documentCount: sanitizedDocs.length,
  })
);
const filteredDocs = sanitizedDocs;

// --- Audit: pre-action record ---
const auditTimestamp = new Date().toISOString();
const modelIdentifier = "text-embedding-ada-002"; // OpenAIEmbeddings default model
const principal = process.env.AUDIT_PRINCIPAL || `script:indexPGVector.mjs:pid=${process.pid}`;
const inputPayload = JSON.stringify(filteredDocs.map((d) => d.pageContent));
const inputHash = crypto.createHash("sha256").update(inputPayload).digest("hex");

const auditEntry = {
  timestamp: auditTimestamp,
  action: "AI_EMBEDDING_INDEX",
  model: modelIdentifier,
  targetTable: "documents",
  documentCount: filteredDocs.length,
  inputHash,
  status: "INITIATED",
};

// --- Secure audit-log path resolution ---
// Only allow paths that resolve inside the project root (or CWD).
// This prevents path-traversal and log-injection via the env variable.
const AUDIT_LOG_BASE_DIR = path.resolve(process.cwd());

function resolveAuditLogPath(envValue, fallback) {
  // Strip newline / carriage-return characters to prevent log injection.
  const raw = (envValue || fallback).replace(/[\r\n]/g, "");
  const resolved = path.resolve(AUDIT_LOG_BASE_DIR, raw);
  // Ensure the resolved path is still inside the trusted base directory.
  if (!resolved.startsWith(AUDIT_LOG_BASE_DIR + path.sep) && resolved !== AUDIT_LOG_BASE_DIR) {
    throw new Error(
      `[SECURITY] AUDIT_LOG_PATH resolves outside the allowed directory: ${resolved}`
    );
  }
  return resolved;
}

const auditLogPath = resolveAuditLogPath(process.env.AUDIT_LOG_PATH, "audit.log");
const MAX_AUDIT_LOG_BYTES = parseInt(process.env.AUDIT_LOG_MAX_BYTES || String(10 * 1024 * 1024), 10); // default 10 MB
const MAX_AUDIT_LOG_ROTATIONS = parseInt(process.env.AUDIT_LOG_MAX_ROTATIONS || "5", 10);

/**
 * Appends a JSON audit record to the audit log file, rotating the file when
 * it exceeds MAX_AUDIT_LOG_BYTES.  Rotated files are named <path>.1 … <path>.N
 * (oldest is dropped when the rotation count exceeds MAX_AUDIT_LOG_ROTATIONS).
 */
function appendAuditLog(logPath, record) {
  // Rotate if the current log file is too large
  try {
    const stat = fs.existsSync(logPath) ? fs.statSync(logPath) : null;
    if (stat && stat.size >= MAX_AUDIT_LOG_BYTES) {
      // Shift existing rotated files: .N-1 → .N, dropping anything beyond the limit
      for (let i = MAX_AUDIT_LOG_ROTATIONS - 1; i >= 1; i--) {
        const older = `${logPath}.${i}`;
        const newer = `${logPath}.${i + 1}`;
        if (fs.existsSync(older)) {
          if (i + 1 > MAX_AUDIT_LOG_ROTATIONS) {
            fs.unlinkSync(older);
          } else {
            fs.renameSync(older, newer);
          }
        }
      }
      fs.renameSync(logPath, `${logPath}.1`);
    }
  } catch (rotateErr) {
    // Log rotation failure must not suppress the audit write
    console.error("[AUDIT][WARN] Log rotation failed:", rotateErr.message);
  }
  fs.appendFileSync(logPath, JSON.stringify(record) + "\n", "utf8");
}

appendAuditLog(auditLogPath, auditEntry);
console.log("[AUDIT] Indexing action initiated:", JSON.stringify(auditEntry));

let indexingOutcome = "SUCCESS";
let indexingError = null;
try {
    // Wrap OpenAIEmbeddings to validate/sanitize LLM embedding output before storage
  const DYNAMIC_CODE_PATTERNS = [
    /eval\s*\(/i,
    /new\s+Function\s*\(/i,
    /setTimeout\s*\(/i,
    /setInterval\s*\(/i,
    /Function\s*\(/i,
    /execScript\s*\(/i,
    /\bimport\s*\(/i,
    /require\s*\(/i,
    /process\.binding/i,
    /child_process/i,
    /__proto__/i,
    /constructor\s*\[/i,
  ];

  function validateEmbeddingVector(vector, index) {
    if (!Array.isArray(vector)) {
      throw new Error(
        `[EMBEDDING VALIDATION] Embedding at index ${index} is not an array. Possible malformed LLM output.`
      );
    }
    for (let i = 0; i < vector.length; i++) {
      const val = vector[i];
      if (typeof val !== "number" || !isFinite(val)) {
        throw new Error(
          `[EMBEDDING VALIDATION] Non-finite or non-numeric value detected at embedding[${index}][${i}]: ${JSON.stringify(val)}`
        );
      }
    }
    // Serialize and check for dynamic code execution primitives in the raw output
    const serialized = JSON.stringify(vector);
    for (const pattern of DYNAMIC_CODE_PATTERNS) {
      if (pattern.test(serialized)) {
        throw new Error(
          `[EMBEDDING VALIDATION] Dynamic code execution primitive detected in embedding output at index ${index}. Pattern: ${pattern}`
        );
      }
    }
  }

  class SanitizingEmbeddings {
    constructor(inner) {
      this.inner = inner;
    }
    async embedDocuments(texts) {
      const rawEmbeddings = await this.inner.embedDocuments(texts);
      if (!Array.isArray(rawEmbeddings)) {
        throw new Error("[EMBEDDING VALIDATION] embedDocuments did not return an array.");
      }
      rawEmbeddings.forEach((vec, idx) => validateEmbeddingVector(vec, idx));
      console.log(
        JSON.stringify({
          timestamp: new Date().toISOString(),
          event: "embedding_validation",
          status: "passed",
          embeddingCount: rawEmbeddings.length,
        })
      );
      return rawEmbeddings;
    }
    async embedQuery(text) {
      const rawEmbedding = await this.inner.embedQuery(text);
      validateEmbeddingVector(rawEmbedding, 0);
      return rawEmbedding;
    }
  }

  const sanitizedEmbeddings = new SanitizingEmbeddings(
    new CohereEmbeddings({
    apiKey: process.env.COHERE_API_KEY,
    model: "embed-english-v3.0", // APPROVED_REGISTRY: pinned version
  })
  );

    // MCP servers must not call LLMs directly.
  // Delegate embedding + indexing to the external embedding service.
  const embeddingServiceUrl = process.env.EMBEDDING_SERVICE_URL;
  if (!embeddingServiceUrl) {
    throw new Error(
      "[CONFIG] EMBEDDING_SERVICE_URL is not set. " +
      "An external embedding service must handle LLM interactions."
    );
  }

  const delegationPayload = {
    documents: filteredDocs.map((d) => ({
      pageContent: d.pageContent,
      metadata: d.metadata,
    })),
    targetTable: "documents",
    model: modelIdentifier,
  };

  const serviceResponse = await fetch(embeddingServiceUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(process.env.EMBEDDING_SERVICE_API_KEY && {
        Authorization: `Bearer ${process.env.EMBEDDING_SERVICE_API_KEY}`,
      }),
    },
    body: JSON.stringify(delegationPayload),
  });

  if (!serviceResponse.ok) {
    const errBody = await serviceResponse.text().catch(() => "(unreadable)");
    throw new Error(
      `[EMBEDDING_SERVICE] Request failed: HTTP ${serviceResponse.status} — ${errBody}`
    );
  }
} catch (err) {
  indexingOutcome = "FAILURE";
  indexingError = err.message;
  throw err;
} finally {
  // --- Audit: post-action record ---
  const auditCompletionEntry = {
    timestamp: new Date().toISOString(),
    action: "AI_EMBEDDING_INDEX",
    model: modelIdentifier,
    targetTable: "documents",
    documentCount: filteredDocs.length,
    inputHash,
    status: indexingOutcome,
    ...(indexingError && { error: indexingError }),
  };
  // Retention policy: rotate audit log when it exceeds MAX_AUDIT_LOG_BYTES.
const MAX_AUDIT_LOG_BYTES = 10 * 1024 * 1024; // 10 MB retention threshold
const AUDIT_LOG_RETENTION_DAYS = 90;
try {
  const { statSync, renameSync } = await import("fs");
  let stat;
  try { stat = statSync(auditLogPath); } catch (_) { stat = null; }
  if (stat && stat.size >= MAX_AUDIT_LOG_BYTES) {
    // --- HITL Approval Gate ---
    // Purging/rotating audit logs is a risky destructive operation.
    // Execution requires explicit human approval via the
    // AUDIT_LOG_ROTATION_APPROVED=true environment variable OR
    // the --approve-log-rotation CLI flag.
    const hitlApproved =
      process.env.AUDIT_LOG_ROTATION_APPROVED === "true" ||
      process.argv.includes("--approve-log-rotation");

    if (!hitlApproved) {
      // Log a pending-approval entry and skip the destructive operation.
      appendAuditLog(auditLogPath, {
        timestamp: new Date().toISOString(),
        event: "audit_log_rotation_pending_approval",
        reason: "HITL approval required before purging audit logs",
        currentSizeBytes: stat.size,
        thresholdBytes: MAX_AUDIT_LOG_BYTES,
        retentionDays: AUDIT_LOG_RETENTION_DAYS,
        policy: `Logs older than ${AUDIT_LOG_RETENTION_DAYS} days should be purged per retention policy`,
        approvalInstructions:
          "Re-run with AUDIT_LOG_ROTATION_APPROVED=true or --approve-log-rotation flag after human review.",
      });
      console.warn(
        "[AUDIT] Log rotation SKIPPED — HITL approval required. " +
          "Set AUDIT_LOG_ROTATION_APPROVED=true or pass --approve-log-rotation to approve."
      );
    } else {
      const rotatedPath = `${auditLogPath}.${new Date().toISOString().replace(/[:.]/g, "-")}.rotated`;
      renameSync(auditLogPath, rotatedPath);
      appendAuditLog(auditLogPath, {
        timestamp: new Date().toISOString(),
        event: "audit_log_rotated",
        rotatedTo: rotatedPath,
        retentionDays: AUDIT_LOG_RETENTION_DAYS,
        policy: `Logs older than ${AUDIT_LOG_RETENTION_DAYS} days should be purged per retention policy`,
        approvedBy: "human-operator",
        approvalMethod:
          process.argv.includes("--approve-log-rotation")
            ? "cli-flag"
            : "env-var",
      });
    }
  }
} catch (rotationErr) {
  console.error("[AUDIT] Log rotation check failed:", rotationErr.message);
}
appendAuditLog(auditLogPath, auditCompletionEntry);
const { principal: _principal1, ...auditCompletionEntryForLog } = auditCompletionEntry;
console.log("[AUDIT] Indexing action completed:", JSON.stringify(auditCompletionEntryForLog));

// Emit the completion event with inputHash and principal so the causal chain
// is complete and traceable back to the append-only audit log entries above.
const llmInteractionEndEntry = {
  timestamp: new Date().toISOString(),
  event: "llm_interaction_end",
  model: APPROVED_EMBEDDING_MODEL_ID,
  action: "SupabaseVectorStore.fromDocuments",
  status: indexingOutcome,
  documentCount: docsToIndex.length,
  inputHash,
  principal,
};
appendAuditLog(auditLogPath, llmInteractionEndEntry);
const { principal: _principal2, ...llmInteractionEndEntryForLog } = llmInteractionEndEntry;
console.log(JSON.stringify(llmInteractionEndEntryForLog));
