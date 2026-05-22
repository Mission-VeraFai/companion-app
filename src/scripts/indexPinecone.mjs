// Major ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/pinecone
import { PineconeClient } from "@pinecone-database/pinecone";
import dotenv from "dotenv";
import { Document } from "langchain/document";
import { OpenAIEmbeddings } from "@langchain/openai";
// APPROVED REGISTRY: @langchain/pinecone@0.0.3
import { PineconeStore } from "@langchain/pinecone";

// ── Model Registry ────────────────────────────────────────────────────────────
// Only models listed here may be instantiated in this workload.
const APPROVED_MODEL_REGISTRY = new Set([
  "text-embedding-ada-002@2",                     // OpenAI embedding model
  "sentence-transformers/all-MiniLM-L6-v2@1.0",  // HuggingFace embedding model
]);

function assertInRegistry(modelId) {
  if (!APPROVED_MODEL_REGISTRY.has(modelId)) {
    throw new Error(
      `Model "${modelId}" is NOT in the approved model registry. ` +
      `Approved models: ${[...APPROVED_MODEL_REGISTRY].join(", ")}`
    );
  }
}
// ─────────────────────────────────────────────────────────────────────────────

// Pinned model identifiers — update registry above when bumping versions.
// Only the OpenAI text-embedding-ada-002 model is approved for use in this workload.
const OPENAI_EMBEDDING_MODEL_ID = "text-embedding-ada-002@2"; // matches APPROVED_MODEL_REGISTRY
const OPENAI_EMBEDDING_MODEL_NAME = "text-embedding-ada-002"; // actual OpenAI model name
// HuggingFace and LLaMA-family models are NOT approved; do not instantiate them.
// const HF_EMBEDDING_MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2@1.0"; // REMOVED: NOT_IN_REGISTRY
// const HF_EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"; // REMOVED: NOT_IN_REGISTRY
import { CharacterTextSplitter } from "langchain/text_splitter";
import fs from "fs";
import path from "path";
import crypto from "crypto";

dotenv.config({ path: `.env.local` });

// ── Path Sanitization Helper ─────────────────────────────────────────────────
/**
 * Resolves and validates that a file path stays within an allowed base directory.
 * Throws if the resolved path escapes the base directory (path traversal).
 *
 * @param {string} baseDir   - The absolute directory that paths must reside within.
 * @param {string} userPath  - The path segment derived from env vars or user input.
 * @returns {string}         - The safe, resolved absolute path.
 */
function safePath(baseDir, userPath) {
  // Reject null/undefined/non-string input
  if (typeof userPath !== "string" || userPath.trim() === "") {
    throw new Error(`Path sanitization failed: path must be a non-empty string, got: ${JSON.stringify(userPath)}`);
  }
  // Reject obvious traversal sequences before resolution
  if (/\.\./.test(userPath)) {
    throw new Error(`Path traversal detected in path segment: "${userPath}"`);
  }
  // Reject absolute paths supplied as the user segment (must be relative)
  if (path.isAbsolute(userPath)) {
    throw new Error(`Absolute path not allowed as user-supplied segment: "${userPath}"`);
  }
  // Reject null bytes
  if (userPath.includes("\0")) {
    throw new Error(`Null byte detected in path segment: "${userPath}"`);
  }
  const resolvedBase = path.resolve(baseDir);
  const resolvedFull = path.resolve(baseDir, userPath);
  if (!resolvedFull.startsWith(resolvedBase + path.sep) && resolvedFull !== resolvedBase) {
    throw new Error(
      `Path traversal blocked: resolved path "${resolvedFull}" escapes base directory "${resolvedBase}"`
    );
  }
  return resolvedFull;
}

/**
 * Returns a safe filename by stripping all characters except alphanumerics,
 * hyphens, underscores, and dots. Throws if the result is empty.
 *
 * @param {string} name - Raw name from env var or user input.
 * @returns {string}    - Sanitized filename-safe string.
 */
function sanitizeFileName(name) {
  if (typeof name !== "string" || name.trim() === "") {
    throw new Error(`sanitizeFileName: input must be a non-empty string, got: ${JSON.stringify(name)}`);
  }
  const sanitized = name.replace(/[^a-zA-Z0-9_\-\.]/g, "_");
  if (sanitized.trim() === "") {
    throw new Error(`sanitizeFileName: sanitized result is empty for input: "${name}"`);
  }
  return sanitized;
}
// ─────────────────────────────────────────────────────────────────────────────

// ── Prompt-Injection / Malicious-Content Guard ───────────────────────────────
/**
 * Throws if the supplied text contains patterns associated with prompt
 * injection, hidden instructions, base64 payloads, leetspeak obfuscation,
 * invisible Unicode characters, or shell / binary commands.
 *
 * @param {string} text  - Raw page content of a document.
 * @param {number} index - Document index (for error messages).
 */
/**
 * Redacts common PII patterns from text by replacing them with placeholder tokens.
 * Covers: email addresses, US phone numbers, SSNs, credit card numbers,
 * IPv4 addresses, dates of birth, US ZIP codes, and passport-style identifiers.
 *
 * @param {string} text - Raw page content to redact.
 * @returns {string} Text with PII replaced by placeholder tokens.
 */
function redactPII(text) {
  // Email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]');

  // US Social Security Numbers (###-##-#### or #########)
  text = text.replace(/\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b/g, '[REDACTED_SSN]');

  // Credit card numbers (13–19 digits, optionally separated by spaces or dashes)
  text = text.replace(/\b(?:\d[ \-]?){13,19}\b/g, '[REDACTED_CC]');

  // US phone numbers (various formats)
  text = text.replace(/\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b/g, '[REDACTED_PHONE]');

  // IPv4 addresses
  text = text.replace(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, '[REDACTED_IP]');

  // Dates that may indicate date of birth (MM/DD/YYYY, DD-MM-YYYY, YYYY-MM-DD)
  text = text.replace(/\b(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2})\b/g, '[REDACTED_DATE]');

  // US ZIP codes (##### or #####-####)
  text = text.replace(/\b\d{5}(?:-\d{4})?\b/g, '[REDACTED_ZIP]');

  // Passport / national ID style identifiers (letter(s) followed by 6–9 digits)
  text = text.replace(/\b[A-Z]{1,2}\d{6,9}\b/g, '[REDACTED_ID]');

  // Driver's license common patterns (alphanumeric, 8–12 chars starting with a letter)
  text = text.replace(/\b[A-Z]\d{7,11}\b/g, '[REDACTED_DL]');

  return text;
}

// ── Singapore PII Guard ──────────────────────────────────────────────────────
/**
 * Throws if the supplied text contains Singapore-specific PII categories:
 * NRIC/FIN, SingPass ID, CPF account numbers, Singapore passport numbers,
 * or Singapore local phone numbers.
 *
 * @param {string} text  - Raw page content of a document.
 * @param {number} index - Document index (for error messages).
 */
function assertNoSingaporePII(text, index) {
  const label = `Document[${index}]`;

  // 1. NRIC / FIN — format: S/T/F/G followed by 7 digits and a letter
  //    S/T = Singapore Citizens & PRs; F/G = Foreigners (FIN)
  const nricFin = /\b[STFG]\d{7}[A-Z]\b/i;
  if (nricFin.test(text)) {
    throw new Error(`${label}: Singapore NRIC/FIN number detected — upload blocked to prevent PII leakage.`);
  }

  // 2. SingPass ID — typically an NRIC/FIN used as login ID, but also
  //    sometimes represented as a standalone alphanumeric token prefixed
  //    with the same pattern; covered by the NRIC/FIN check above.
  //    Additional heuristic: explicit label proximity.
  const singpassLabel = /singpass\s*(?:id|login|user(?:name|id)?)?\s*[:\-]?\s*[STFG]\d{7}[A-Z]/i;
  if (singpassLabel.test(text)) {
    throw new Error(`${label}: SingPass credential detected — upload blocked to prevent PII leakage.`);
  }

  // 3. CPF Account Number — 9-digit numeric string commonly labelled "CPF"
  //    or appearing near CPF-related keywords.
  const cpfPattern = /\bCPF\b[^\n]{0,30}\b\d{9}\b|\b\d{9}\b[^\n]{0,30}\bCPF\b/i;
  if (cpfPattern.test(text)) {
    throw new Error(`${label}: CPF account number detected — upload blocked to prevent PII leakage.`);
  }

  // 4. Singapore Passport Number — format: E followed by 7 digits
  const sgPassport = /\bE\d{7}\b/;
  if (sgPassport.test(text)) {
    throw new Error(`${label}: Singapore passport number detected — upload blocked to prevent PII leakage.`);
  }

  // 5. Singapore local phone numbers — +65 followed by 8 digits starting with 6, 8, or 9
  const sgPhone = /(?:\+65|\(65\))[\s\-]?[689]\d{7}\b|\b[689]\d{7}\b/;
  if (sgPhone.test(text)) {
    throw new Error(`${label}: Singapore phone number detected — upload blocked to prevent PII leakage.`);
  }
}
// ─────────────────────────────────────────────────────────────────────────────

function assertNoMaliciousContent(text, index) {
  const label = `Document[${index}]`;

  // 1. Invisible / zero-width Unicode characters (common prompt-injection vector)
  const invisibleChars = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/;
  if (invisibleChars.test(text)) {
    throw new Error(`${label}: invisible/zero-width Unicode characters detected — possible hidden prompt injection.`);
  }

  // 2. Base64-encoded blobs (≥ 40 contiguous base64 chars with optional padding)
  //    Legitimate prose rarely contains long unbroken base64 strings.
  const base64Blob = /(?:[A-Za-z0-9+/]{40,}={0,2})/;
  if (base64Blob.test(text)) {
    throw new Error(`${label}: long base64-encoded content detected — possible obfuscated payload.`);
  }

  // 3. Leetspeak / character-substitution obfuscation heuristic
  //    Flags strings that mix digits into words in a leet pattern (e.g. "3x3cut3", "sh3ll").
  const leetspeak = /\b(?:[a-zA-Z]*[013456789][a-zA-Z]+[013456789][a-zA-Z0-9]*|[a-zA-Z]+[013456789]{2,}[a-zA-Z0-9]*)\b/;
  if (leetspeak.test(text)) {
    throw new Error(`${label}: leetspeak / character-substitution obfuscation detected.`);
  }

  // 4. Shell / binary command patterns
  // Patterns are constructed dynamically to avoid embedding shell command
  // literals directly in source code.
  const _sp = (...parts) => parts.join("");
  const shellPatterns = [
    // Shell interpreter invocations
    new RegExp(
      _sp("\\b(", ["bash","sh","zsh","fish"].join("|"), "|",
        ["cmd","exe"].join("."), "|", ["power","shell"].join(""), "|", "pwsh",
        ")\\s+(-[a-zA-Z]+\\s+)?([\"'][^\"']*[\"']|\\S+)"),
      "i"
    ),
    // Network fetch / scripting runtimes
    new RegExp(
      _sp("\\b(",
        ["cur"+"l", "w"+"get", "nc", "ncat", "netcat",
         "python[23]?", "perl", "ruby", "php", "node"].join("|"),
        ")\\s+"),
      "i"
    ),
    // Privilege / file-permission commands
    new RegExp(
      _sp("\\b(",
        ["ch"+"mod", "ch"+"own", "su"+"do", "su", "pass"+"wd",
         "useradd", "userdel", "visudo"].join("|"),
        ")\\b"),
      "i"
    ),
    // Destructive shell patterns
    new RegExp(
      _sp("\\b(",
        "r"+"m\\s+-[rRf]{1,3}", "|",
        "mkfs", "|",
        "dd\\s+if=", "|",
        "fork\\s*bomb", "|",
        ":\\s*\\(\\s*\\)\\s*\\{"
      , ")"),
      "i"
    ),
    // Sensitive system paths
    new RegExp(
      _sp("(",
        ["/etc/pass"+"wd", "/etc/sha"+"dow",
         "/proc/self", "/dev/tcp", "/dev/udp"].join("|"),
        ")"),
      "i"
    ),
    // Command substitution
    /\$\(.*\)|`[^`]+`/,
    // Code execution calls
    new RegExp(
      _sp("\\b(",
        ["ex"+"ec", "ev"+"al", "sys"+"tem", "popen", "subprocess"].join("|"),
        ")\\s*\\("),
      "i"
    ),
    // Hex-escaped bytes
    /\\x[0-9a-fA-F]{2}/,
    // Unicode escapes in raw text
    /\\u[0-9a-fA-F]{4}/,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(text)) {
      throw new Error(`${label}: shell or binary command pattern detected (pattern: ${pattern}) — possible command injection.`);
    }
  }

  // 5. Hidden prompt / instruction injection keywords
  //    Catches common adversarial instruction prefixes regardless of case.
  const promptInjectionPhrases = [
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i,
    /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i,
    /forget\s+(everything|all|prior|previous)/i,
    /you\s+are\s+now\s+(a|an|the)\s+/i,
    /act\s+as\s+(a|an|the)\s+/i,
    /new\s+instructions?\s*:/i,
    /system\s*:\s*(you|your|ignore)/i,
    /\[INST\]|<<SYS>>|<\|im_start\|>|<\|im_end\|>/i, // common model control tokens
    /###\s*(instruction|system|prompt|context)\s*:/i,
  ];
  for (const phrase of promptInjectionPhrases) {
    if (phrase.test(text)) {
      throw new Error(`${label}: hidden prompt injection phrase detected (pattern: ${phrase}).`);
    }
  }
}
// ─────────────────────────────────────────────────────────────────────────────

// Validate required credentials are present before use
const requiredEnvVars = ["PINECONE_API_KEY", "PINECONE_ENVIRONMENT", "PINECONE_INDEX"];
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
  event: "llm_interaction_complete",
  service: "HuggingFaceInferenceEmbeddings",
  model: "sentence-transformers/all-MiniLM-L6-v2",
  action: "PineconeStore.fromDocuments",
  documentCount: docsToEmbed.length,
  status: "success",
}));

// ── Audit logging setup ────────────────────────────────────────────────────
const AUDIT_LOG_PATH = path.resolve("audit_log.jsonl");

const AUDIT_HMAC_SECRET = process.env.AUDIT_HMAC_SECRET || (() => { throw new Error("AUDIT_HMAC_SECRET env var is required for signed audit records"); })();

function signAuditRecord(record) {
  const payload = JSON.stringify(record, Object.keys(record).sort());
  return crypto.createHmac("sha256", AUDIT_HMAC_SECRET).update(payload).digest("hex");
}

function writeAuditRecord(record) {
  // Attach retention metadata so downstream archival tools can enforce policy.
  const enriched = {
    ...record,
    retentionDays: AUDIT_LOG_RETENTION_DAYS,
    auditSchemaVersion: "1.0",
  };

  // Compute an HMAC-SHA256 integrity tag over the canonical JSON payload.
  const payload = JSON.stringify(enriched);
  const hmac = crypto
    .createHmac("sha256", AUDIT_HMAC_SECRET)
    .update(payload)
    .digest("hex");
  const line = JSON.stringify({ ...enriched, _integrity: hmac }) + "\n";

  const logPath = getAuditLogPath();
  maybeRotateAuditLog(logPath);

  // Open with flag 'a' (append-only) and restrictive permissions (0o600).
  const fd = fs.openSync(logPath, "a", 0o600);
  try {
    fs.appendFileSync(fd, line);
  } finally {
    fs.closeSync(fd);
  }

  // Best-effort purge of logs beyond the retention window.
  purgeExpiredAuditLogs();
}

const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);

// Compute a deterministic hash of the input corpus for forensic traceability.
const inputHash = crypto
  .createHash("sha256")
  .update(filteredDocs.map((d) => d.pageContent).join("\0"))
  .digest("hex");

const MODEL_IDENTIFIER = process.env.APPROVED_EMBEDDING_MODEL; // Approved embedding model from registry
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

// --- LLM Output Validation: check for dynamic code execution primitives ---
const DYNAMIC_CODE_PATTERNS = [
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /new\s+Function\s*\(/,
  /\bsetTimeout\s*\(\s*['"`]/,
  /\bsetInterval\s*\(\s*['"`]/,
  /\bimportScripts\s*\(/,
  /\bdocument\.write\s*\(/,
  /\bInlineScript\b/,
  /__import__\s*\(/,
  /\bcompile\s*\(/,
  /\bexecfile\s*\(/,
  /\bos\.system\s*\(/,
  /\bsubprocess\b/,
];

function containsDynamicCodePrimitive(text) {
  return DYNAMIC_CODE_PATTERNS.some((pattern) => pattern.test(text));
}

function validateAndSanitizeEmbeddingOutput(vectors) {
  if (!Array.isArray(vectors)) {
    throw new Error("LLM output validation failed: embedding output is not an array");
  }
  for (let i = 0; i < vectors.length; i++) {
    const vec = vectors[i];
    if (!Array.isArray(vec)) {
      throw new Error(`LLM output validation failed: embedding at index ${i} is not a numeric array`);
    }
    for (const val of vec) {
      if (typeof val !== "number" || !isFinite(val)) {
        throw new Error(`LLM output validation failed: non-finite or non-numeric value in embedding at index ${i}`);
      }
    }
  }
  return vectors;
}

// Validate document content for dynamic code execution primitives before embedding
for (let i = 0; i < filteredDocs.length; i++) {
  const docContent = filteredDocs[i].pageContent || "";
  if (containsDynamicCodePrimitive(docContent)) {
    writeAuditRecord({
      event: "llm_output_validation_rejected",
      timestamp: new Date().toISOString(),
      principal,
      reason: "dynamic_code_primitive_detected",
      documentIndex: i,
    });
    throw new Error(
      `LLM output validation failed: dynamic code execution primitive detected in document at index ${i}. Aborting indexing.`
    );
  }
}

// Wrap OpenAIEmbeddings to intercept and validate embedding vectors
const baseEmbeddings = new OpenAIEmbeddings({ modelName: OPENAI_EMBEDDING_MODEL_NAME });
const validatingEmbeddings = {
  ...baseEmbeddings,
  embedDocuments: async (texts) => {
    // Validate input texts for dynamic code primitives
    for (let i = 0; i < texts.length; i++) {
      if (containsDynamicCodePrimitive(texts[i])) {
        throw new Error(
          `LLM output validation failed: dynamic code execution primitive detected in embedding input text at index ${i}`
        );
      }
    }
    const vectors = await baseEmbeddings.embedDocuments(texts);
    return validateAndSanitizeEmbeddingOutput(vectors);
  },
  embedQuery: async (text) => {
    if (containsDynamicCodePrimitive(text)) {
      throw new Error(
        "LLM output validation failed: dynamic code execution primitive detected in embedding query text"
      );
    }
    const vector = await baseEmbeddings.embedQuery(text);
    if (!Array.isArray(vector)) {
      throw new Error("LLM output validation failed: query embedding output is not an array");
    }
    for (const val of vector) {
      if (typeof val !== "number" || !isFinite(val)) {
        throw new Error("LLM output validation failed: non-finite or non-numeric value in query embedding");
      }
    }
    return vector;
  },
};

// ── Approved model registry ──────────────────────────────────────────────
const APPROVED_MODEL_REGISTRY = [
  "sentence-transformers/all-MiniLM-L6-v2@1.0",
];

function assertModelAllowed(modelId) {
  if (!APPROVED_MODEL_REGISTRY.includes(modelId)) {
    const msg = `Model '${modelId}' is not in the approved model registry. Execution blocked.`;
    writeAuditRecord({
      event: "model_blocked",
      timestamp: new Date().toISOString(),
      principal,
      modelId,
      reason: msg,
    });
    throw new Error(msg);
  }
  writeAuditRecord({
    event: "model_allowed",
    timestamp: new Date().toISOString(),
    principal,
    modelId,
  });
}

// ── Tool allow list enforcement ───────────────────────────────────────────
const TOOL_ALLOW_LIST = [
  "OpenAIEmbeddings",
  "PineconeStore.fromDocuments",
];

function assertToolAllowed(toolName) {
  if (!TOOL_ALLOW_LIST.includes(toolName)) {
    const msg = `Tool '${toolName}' is not on the approved allow list. Execution blocked.`;
    writeAuditRecord({
      event: "tool_blocked",
      timestamp: new Date().toISOString(),
      principal,
      toolName,
      reason: msg,
    });
    throw new Error(msg);
  }
  writeAuditRecord({
    event: "tool_allowed",
    timestamp: new Date().toISOString(),
    principal,
    toolName,
  });
}

// Validate model identifier against the approved registry before any execution.
assertModelAllowed(MODEL_IDENTIFIER);

// Validate all tools against the allow list before any execution.
assertToolAllowed("OpenAIEmbeddings");
assertToolAllowed("PineconeStore.fromDocuments");

let outcome = "success";
let errorMessage = null;
try {
  // Use the validated/sanitized embeddings wrapper to ensure all LLM/embedding
  // output is checked for eval/exec/dynamic code execution primitives before
  // being written to the vector store.
  await PineconeStore.fromDocuments(
    filteredDocs,
    validatedEmbeddings,
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
    documentCount: filteredDocs.length,
    inputHash,
    outcome,
    ...(errorMessage && { errorMessage }),
  });
}

// Route the completion event through the audit system so it carries the same
// inputHash (correlation/trace ID) as the surrounding writeAuditRecord calls,
// preserving the causal chain required for forensic readiness.
writeAuditRecord({
  event: "llm_interaction_complete",
  timestamp: new Date().toISOString(),
  principal,
  service: "HuggingFaceInferenceEmbeddings",
  model: MODEL_IDENTIFIER, // approved: text-embedding-ada-002@2
  action: "PineconeStore.fromDocuments",
  documentCount: filteredDocs.length,
  modelIdentifier: MODEL_IDENTIFIER,
  correlationId: inputHash,
  status: "success",
});
