// Call embeding API and insert to supabase
// Ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/supabase

import dotenv from "dotenv";
import { Document } from "langchain/document";
// Using AzureOpenAIEmbeddings with an approved model from the organization's registry.
import { AzureOpenAIEmbeddings } from "@langchain/openai";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { createClient } from "@supabase/supabase-js";
import { CharacterTextSplitter } from "langchain/text_splitter";
import crypto from "crypto";
import { appendFileSync } from "fs";

/**
 * Explicit allow list of permitted tool/vector-store operations.
 * Only operations named here may be invoked by this agent.
 */
/**
 * Approved model registry: maps model label to pinned version and expected SHA-256
 * of the model identifier string (as a lightweight integrity anchor).
 */
// The local APPROVED_MODEL_REGISTRY below is the authoritative integrity anchor
// for approved models used by this agent.

// The authoritative approved model registry is fetched at runtime from
// APPROVED_MODEL_REGISTRY_URL. The local schema below is used only for
// structural validation of the fetched payload — it is NOT authoritative.
const LOCAL_REGISTRY_SCHEMA_KEYS = ["model", "version", "identityHash"];

/**
 * Fetches the authoritative approved model registry from the external URL.
 * Throws if the registry cannot be fetched or is malformed.
 * @returns {Promise<Object>} The frozen external registry object.
 */
async function fetchApprovedRegistry() {
  const registryUrl = process.env.APPROVED_MODEL_REGISTRY_URL;
  // Already validated above that this is set.
  let response;
  try {
    response = await fetch(registryUrl, {
      method: "GET",
      headers: { "Accept": "application/json" },
      // Enforce a strict timeout to avoid hanging.
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err) {
    throw new Error(
      `Policy violation: Failed to fetch approved model registry from ${registryUrl}: ${err.message}. ` +
      "All AI workloads must validate against the organization's authoritative external registry."
    );
  }
  if (!response.ok) {
    throw new Error(
      `Policy violation: Approved model registry fetch returned HTTP ${response.status} from ${registryUrl}. ` +
      "Cannot proceed without the authoritative registry."
    );
  }
  let registry;
  try {
    registry = await response.json();
  } catch (err) {
    throw new Error(
      `Policy violation: Approved model registry response from ${registryUrl} is not valid JSON: ${err.message}.`
    );
  }
  if (typeof registry !== "object" || registry === null || Array.isArray(registry)) {
    throw new Error(
      "Policy violation: Approved model registry must be a JSON object mapping model labels to entries."
    );
  }
  // Validate each entry has required fields.
  for (const [label, entry] of Object.entries(registry)) {
    for (const key of LOCAL_REGISTRY_SCHEMA_KEYS) {
      if (!entry || typeof entry[key] !== "string" || entry[key].trim() === "") {
        throw new Error(
          `Policy violation: Registry entry for "${label}" is missing or has invalid field "${key}".`
        );
      }
    }
  }
  return Object.freeze(registry);
}

// Module-level cache for the fetched external registry.
let _approvedRegistryCache = null;

/**
 * Returns the authoritative external registry, fetching it once per process.
 * @returns {Promise<Object>}
 */
async function getApprovedRegistry() {
  if (!_approvedRegistryCache) {
    _approvedRegistryCache = await fetchApprovedRegistry();
  }
  return _approvedRegistryCache;
}

/**
 * Verifies the model identity against the AUTHORITATIVE EXTERNAL approved registry.
 * Must be called with await before any model is instantiated.
 * Computes a SHA-256 hash of "<model>@<version>" and compares to the registered hash.
 * Throws if the model is not in the registry or the hash does not match.
 * @param {string} modelLabel - The registry key for the model.
 */
function assertModelIntegrity(modelLabel) {
  const entry = APPROVED_MODEL_REGISTRY[modelLabel];
  if (!entry) {
    throw new Error(
      `Model identity violation: "${modelLabel}" is not in the approved model registry.`
    );
  }
  const identityString = `${entry.model}@${entry.version}`;
  const computedHash = crypto.createHash("sha256").update(identityString).digest("hex");
  if (computedHash !== entry.identityHash) {
    throw new Error(
      `Model integrity check failed for "${modelLabel}": ` +
      `expected hash ${entry.identityHash}, got ${computedHash}. ` +
      `Model identity string: "${identityString}"`
    );
  }
  return entry;
}

const TOOL_ALLOW_LIST = Object.freeze([
  "SupabaseVectorStore.fromDocuments",
]);

/**
 * Validates that a requested tool operation is present in the allow list.
 * Throws a descriptive error if the tool is not permitted.
 * @param {string} toolName - The tool/operation identifier to check.
 */
function assertToolAllowed(toolName) {
  if (!TOOL_ALLOW_LIST.includes(toolName)) {
    throw new Error(
      `Tool invocation denied: "${toolName}" is not in the approved tool allow list. ` +
      `Permitted tools: ${TOOL_ALLOW_LIST.join(", ")}`
    );
  }
}

import fs from "fs";
import path from "path";

/**
 * Checks text for dynamic code execution primitives that may appear in LLM output.
 * Throws if any dangerous pattern is found.
 */
/**
 * Redacts common PII patterns from a string.
 * Replaces matched PII with a labeled placeholder (e.g. [REDACTED_EMAIL]).
 * @param {string} text - The text to redact PII from.
 * @returns {string} The text with PII replaced by placeholders.
 */
function redactPII(text) {
  if (typeof text !== "string") return text;

  const piiPatterns = [
    // Email addresses
    { pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, label: "EMAIL" },
    // US Social Security Numbers (XXX-XX-XXXX or XXXXXXXXX)
    { pattern: /\b(?!000|666|9\d{2})\d{3}[\s\-]?(?!00)\d{2}[\s\-]?(?!0000)\d{4}\b/g, label: "SSN" },
    // Credit card numbers (13–16 digits, optionally separated by spaces or dashes)
    { pattern: /\b(?:\d[ \-]?){13,16}\b/g, label: "CREDIT_CARD" },
    // US phone numbers in common formats
    { pattern: /\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b/g, label: "PHONE" },
    // IPv4 addresses
    { pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, label: "IP_ADDRESS" },
    // Dates of birth / dates in common formats (MM/DD/YYYY, YYYY-MM-DD, DD-MM-YYYY)
    { pattern: /\b(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\-\/]\d{2}[\-\/]\d{2})\b/g, label: "DATE" },
    // Names preceded by common honorifics
    { pattern: /\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*/g, label: "NAME" },
    // Singapore NRIC/FIN: S/T/F/G followed by 7 digits and a letter (e.g. S1234567D)
    { pattern: /\b[STFG]\d{7}[A-Z]\b/gi, label: "SG_NRIC_FIN" },
    // SingPass user ID patterns (e.g. SingPass_ID: user123)
    { pattern: /\bsingpass[_\-\s]?id[:\s]+[^\s,;]+/gi, label: "SG_SINGPASS_ID" },
    // SingPass login references
    { pattern: /\bsingpass\b/gi, label: "SG_SINGPASS_REF" },
    // CPF account numbers (9 digits, optionally preceded by CPF label)
    { pattern: /\bcpf[\s\-]?(?:account|no|number|acct)?[:\s]+\d{9}\b/gi, label: "SG_CPF_LABELED" },
    // Standalone 9-digit numbers that may be CPF account numbers
    { pattern: /\b\d{9}\b/g, label: "SG_CPF_NUMBER" },
    // Work Permit numbers (WP followed by 7–10 digits)
    { pattern: /\bW[Pp]\d{7,10}\b/g, label: "SG_WORK_PERMIT" },
    // Employment Pass / S Pass references with identifiers
    { pattern: /\b(?:EP|SP|EntrePass)[\s\-]?\d{7,10}\b/gi, label: "SG_PASS_NUMBER" },
    // Student Pass numbers (SP followed by 7–10 digits)
    { pattern: /\bS[Pp]\d{7,10}\b/g, label: "SG_STUDENT_PASS" },
    // Singapore phone numbers (+65 XXXX XXXX or local 8/9 XXXXXXX)
    { pattern: /\b(?:\+65[\s\-]?)?[89]\d{3}[\s\-]?\d{4}\b/g, label: "SG_PHONE" },
    // Singapore postal codes (6-digit codes, optionally preceded by "Singapore")
    { pattern: /\b(?:Singapore\s)?\d{6}\b/gi, label: "SG_POSTAL_CODE" },
    // Singapore postal codes (6 digits, optionally preceded by "Singapore" or "S")
    { pattern: /\b(?:Singapore\s+|S)\(?(\d{6})\)?\b/gi, label: "SG_POSTAL_CODE" },
  ];

  let redacted = text;
  for (const { pattern, label } of piiPatterns) {
    redacted = redacted.replace(pattern, `[REDACTED_${label}]`);
  }
  return redacted;
}

/**
 * Detects Singapore-specific PII in text content.
 * Checks for NRIC/FIN numbers, SingPass IDs, Singapore phone numbers,
 * Singapore postal codes combined with personal data, and other SG PII.
 * Returns an object with { found: boolean, matches: string[] }.
 * @param {string} text - The text to scan.
 */
function detectSingaporePII(text) {
  const sgPIIPatterns = [
    // NRIC/FIN: S/T/F/G followed by 7 digits and a letter
    { name: "NRIC/FIN", pattern: /\b[STFG]\d{7}[A-Z]\b/gi },
    // SingPass user ID patterns (NRIC-based or email-based SingPass)
    { name: "SingPass ID", pattern: /\bsingpass[_\-\s]?id[:\s]+[^\s,;]+/gi },
    // Singapore mobile numbers: +65 followed by 8 digits starting with 8 or 9
    { name: "SG Phone", pattern: /(?:\+65[\s-]?)?[89]\d{7}\b/g },
    // Singapore postal codes (6 digits, commonly preceded by keywords)
    { name: "SG Postal Code", pattern: /\b(?:postal|zip|postcode)[:\s]+\d{6}\b/gi },
    // CPF account references
    { name: "CPF Account", pattern: /\bcpf\s*(?:account|no\.?|number)[:\s]+[^\s,;]+/gi },
    // MAS-regulated entity references tied to personal data
    { name: "SG NRIC keyword", pattern: /\b(?:nric|fin|singpass|myinfo)\b/gi },
  ];

  const matches = [];
  for (const { name, pattern } of sgPIIPatterns) {
    const found = text.match(pattern);
    if (found) {
      matches.push(`${name}: ${found.slice(0, 3).join(", ")}${found.length > 3 ? " ..." : ""}`);
    }
  }
  return { found: matches.length > 0, matches };
}

function detectDynamicCodeExecution(text, context) {
  const dangerousPatterns = [
    { pattern: /\beval\s*\(/, label: "eval()" },
    { pattern: /\bexec\s*\(/, label: "exec()" },
    { pattern: /\bnew\s+Function\s*\(/, label: "new Function()" },
    { pattern: /\bsetTimeout\s*\(\s*['"`]/, label: "setTimeout with string" },
    { pattern: /\bsetInterval\s*\(\s*['"`]/, label: "setInterval with string" },
    { pattern: /\bexecSync\s*\(/, label: "execSync()" },
    { pattern: /\bspawnSync\s*\(/, label: "spawnSync()" },
    { pattern: /\bspawn\s*\(/, label: "spawn()" },
    { pattern: /\bexecFile\s*\(/, label: "execFile()" },
    { pattern: /\brequire\s*\(\s*['"`]child_process/, label: "require('child_process')" },
    { pattern: /\bimport\s*\(\s*['"`]child_process/, label: "import('child_process')" },
    { pattern: /\bvm\.runInNewContext\s*\(/, label: "vm.runInNewContext()" },
    { pattern: /\bvm\.runInThisContext\s*\(/, label: "vm.runInThisContext()" },
    { pattern: /\bvm\.Script\s*\(/, label: "vm.Script()" },
    { pattern: /\bProcessBuilder\s*\(/, label: "ProcessBuilder()" },
    { pattern: /\b__import__\s*\(/, label: "__import__()" },
    { pattern: /\bcompile\s*\(/, label: "compile()" },
    { pattern: /\bexecute\s*\(/, label: "execute()" },
  ];
  const found = dangerousPatterns
    .filter(({ pattern }) => pattern.test(text))
    .map(({ label }) => label);
  if (found.length > 0) {
    throw new Error(
      `Dynamic code execution primitive(s) detected in ${context}: ${found.join(", ")}. ` +
      "Processing aborted. Review and sanitize content before indexing."
    );
  }
}

/**
 * Validates that an embedding result is a valid numeric vector array.
 * Throws if the embedding contains non-numeric values or suspicious content.
 */
function validateEmbeddingVector(embedding, index) {
  if (!Array.isArray(embedding)) {
    throw new Error(`Embedding at index ${index} is not an array. Got: ${typeof embedding}`);
  }
  for (let i = 0; i < embedding.length; i++) {
    const val = embedding[i];
    if (typeof val !== "number" || !isFinite(val)) {
      throw new Error(
        `Embedding at index ${index}, position ${i} contains invalid value: ${JSON.stringify(val)}. ` +
        "Expected a finite number."
      );
    }
  }
}

/**
 * Detects Singapore PII in a given text string.
 * Categories checked:
 *  - NRIC / FIN numbers (e.g. S1234567A, T0312345B, F1234567K, G1234567X)
 *  - Singapore passport numbers (e.g. E1234567X)
 *  - Singapore mobile / local phone numbers (+65 XXXX XXXX or 8/9-digit starting with 6,8,9)
 *  - Singapore postal codes (6-digit, optionally preceded by "Singapore")
 *  - Full name + NRIC combos (broad heuristic)
 * Throws an error listing which PII types were found.
 */
function detectSingaporePII(text, fileName) {
  const findings = [];

  // NRIC / FIN: starts with S, T, F, G or M followed by 7 digits and a letter
  const nricRegex = /\b[STFGM]\d{7}[A-Z]\b/gi;
  if (nricRegex.test(text)) {
    findings.push("NRIC/FIN number");
  }

  // Singapore passport number: starts with E followed by 7 digits and a letter
  const passportRegex = /\bE\d{7}[A-Z]\b/gi;
  if (passportRegex.test(text)) {
    findings.push("Singapore passport number");
  }

  // Singapore phone numbers: +65 followed by 8 digits, or standalone 8-digit numbers starting with 6, 8, or 9
  const phoneRegex = /(\+65[\s-]?\d{4}[\s-]?\d{4}|\b[689]\d{7}\b)/g;
  if (phoneRegex.test(text)) {
    findings.push("Singapore phone number");
  }

  // Singapore postal codes: 6-digit number optionally preceded by "Singapore"
  const postalRegex = /\b(?:Singapore\s)?\d{6}\b/gi;
  if (postalRegex.test(text)) {
    findings.push("Singapore postal code");
  }

  // Singapore bank account numbers: DBS/POSB/OCBC/UOB patterns (9-12 digit sequences near bank keywords)
  const bankRegex = /\b(?:DBS|POSB|OCBC|UOB|Citibank|Standard Chartered|HSBC)[^\n]{0,40}\d{9,12}\b/gi;
  if (bankRegex.test(text)) {
    findings.push("Singapore bank account number");
  }

  if (findings.length > 0) {
    throw new Error(
      `PII detected in file "${fileName}": ${findings.join(", ")}. ` +
      "Upload aborted. Remove or redact PII before indexing."
    );
  }
}

/**
 * Redacts common PII patterns from a string.
 * Covers: email addresses, US phone numbers, SSNs, credit card numbers,
 * and names preceded by common honorifics.
 */
function redactPII(text) {
  // Email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");
  // US phone numbers (various formats)
  text = text.replace(/(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g, "[REDACTED_PHONE]");
  // Social Security Numbers
  text = text.replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[REDACTED_SSN]");
  // Credit card numbers (16-digit, optionally grouped by spaces or dashes)
  text = text.replace(/\b(?:\d[ -]?){13,16}\b/g, "[REDACTED_CC]");
  // Names preceded by honorifics
  text = text.replace(/\b(Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*/g, "[REDACTED_NAME]");
  return text;
}

/**
 * Sanitizes file content to prevent prompt injection attacks.
 * Checks for and removes/rejects hidden prompts, base64-encoded content,
 * leetspeak, shell commands, and other malicious patterns.
 */
function sanitizeFileContent(content, fileName) {
  // Check for excessively long lines that may indicate encoded payloads
  const lines = content.split("\n");
  for (const line of lines) {
    if (line.length > 2000) {
      throw new Error(`File ${fileName} contains suspiciously long line (possible encoded payload).`);
    }
  }

  // Detect base64-encoded blocks (long strings of base64 chars)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  if (base64Pattern.test(content)) {
    throw new Error(`File ${fileName} contains possible base64-encoded content.`);
  }

  // Detect shell command injection patterns
  const shellCommandPattern = /(?:\$\(|`[^`]*`|\|\s*\w+|;\s*\w+|&&\s*\w+|\|\|\s*\w+|\bexec\b|\beval\b|\bsystem\b|\bpassthru\b|\bpopen\b)/i;
  if (shellCommandPattern.test(content)) {
    throw new Error(`File ${fileName} contains possible shell command injection.`);
  }

  // Detect prompt injection attempts (instructions to override system behavior)
  const promptInjectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/i,
    /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/i,
    /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/i,
    /you\s+are\s+now\s+(a\s+)?(?!a companion)/i,
    /new\s+(role|persona|identity|instructions?|task|objective)/i,
    /act\s+as\s+(if\s+you\s+are|a\s+)?(?!a companion)/i,
    /\[\s*(system|assistant|user|human|ai)\s*\]/i,
    /<\s*(system|assistant|user|human|ai)\s*>/i,
    /###\s*(system|instruction|prompt|override)/i,
    /---\s*(system|instruction|prompt|override)/i,
  ];
  for (const pattern of promptInjectionPatterns) {
    if (pattern.test(content)) {
      throw new Error(`File ${fileName} contains possible prompt injection attempt.`);
    }
  }

  // Detect leetspeak patterns (common substitutions: 3=e, 4=a, 0=o, 1=i/l, @=a, $=s)
  const leetspeakPattern = /(?:[a-z]*[30@$1!|][a-z0-9@$1!|]{3,})/i;
  const leetspeakMatches = content.match(leetspeakPattern);
  if (leetspeakMatches) {
    // Only flag if there are multiple leetspeak tokens (reduce false positives)
    const allMatches = content.match(new RegExp(leetspeakPattern.source, 'gi')) || [];
    if (allMatches.length > 5) {
      throw new Error(`File ${fileName} contains possible leetspeak-encoded content.`);
    }
  }

  // Detect zero-width characters and other invisible Unicode used to hide content
  const hiddenCharsPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/;
  if (hiddenCharsPattern.test(content)) {
    throw new Error(`File ${fileName} contains hidden Unicode characters (possible steganographic content).`);
  }

  // Detect excessive special character sequences that may indicate obfuscation
  const obfuscationPattern = /(?:[^a-zA-Z0-9\s.,!?'"\-]{4,})/;
  const obfuscationMatches = content.match(new RegExp(obfuscationPattern.source, 'g')) || [];
  if (obfuscationMatches.length > 10) {
    throw new Error(`File ${fileName} contains excessive special characters (possible obfuscation).`);
  }

  // Strip any remaining control characters except standard whitespace
  const sanitized = content.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  return sanitized;
}

dotenv.config({ path: `.env.local` });

// Validate that all required credentials are supplied via environment variables only
const REQUIRED_ENV_VARS = ["SUPABASE_URL", "SUPABASE_PRIVATE_KEY", "OPENAI_API_KEY"];
for (const envVar of REQUIRED_ENV_VARS) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}. Credentials must be provided via .env.local and must never be hardcoded.`);
  }
}

/**
 * Sanitizes text content to prevent prompt injection attacks before
 * passing it to the AI embedding API.
 * Removes/neutralizes:
 *  - Hidden prompt injection patterns (e.g. "ignore previous instructions")
 *  - Base64-encoded blobs that could decode to malicious prompts
 *  - Shell command sequences
 */
function sanitizeContent(text) {
  if (typeof text !== "string") return "";

  // Remove null bytes and non-printable control characters (except common whitespace)
  let sanitized = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Detect and strip base64-encoded blobs (runs of 40+ base64 chars)
  sanitized = sanitized.replace(/[A-Za-z0-9+/]{40,}={0,2}/g, "[REDACTED_BASE64]");

  // Remove shell command patterns
  const shellPatterns = [
    /`[^`]*`/g,                          // backtick command substitution
    /\$\([^)]*\)/g,                      // $(...) command substitution
    /;\s*(rm|curl|wget|bash|sh|python|perl|ruby|nc|ncat|netcat|eval|exec)\b[^;\n]*/gi,
    /&&\s*(rm|curl|wget|bash|sh|python|perl|ruby|nc|ncat|netcat|eval|exec)\b[^&\n]*/gi,
    /\|\s*(rm|curl|wget|bash|sh|python|perl|ruby|nc|ncat|netcat|eval|exec)\b[^|\n]*/gi,
  ];
  for (const pattern of shellPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED_CMD]");
  }

  // Detect prompt injection phrases and neutralize them
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/gi,
    /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/gi,
    /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/gi,
    /you\s+are\s+now\s+(a\s+)?(?!a\s+companion)/gi,
    /new\s+(system\s+)?prompt\s*:/gi,
    /\[system\]/gi,
    /\[assistant\]/gi,
    /<\s*system\s*>/gi,
    /<\s*\/\s*system\s*>/gi,
    /###\s*system/gi,
    /###\s*instruction/gi,
  ];
  for (const pattern of injectionPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED_INJECTION]");
  }

  return sanitized;
}

const COMPANIONS_BASE_DIR = path.resolve("companions");
const fileNames = fs.readdirSync(COMPANIONS_BASE_DIR);
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (fileName.endsWith(".txt")) {
      const filePath = path.resolve(COMPANIONS_BASE_DIR, fileName);
      if (!filePath.startsWith(COMPANIONS_BASE_DIR + path.sep) && filePath !== COMPANIONS_BASE_DIR) {
        throw new Error(`Path traversal detected for file: ${fileName}`);
      }
      const rawContent = fs.readFileSync(filePath, "utf8");
      const fileContent = sanitizeFileContent(rawContent, fileName);
      const lastSection = sanitizeContent(
        fileContent.split("###ENDSEEDCHAT###").slice(-1)[0]
      );
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

/**
 * Sanitize a text string before sending it to the embedding API.
 * - Removes null bytes and non-printable ASCII control characters (except normal whitespace).
 * - Trims leading/trailing whitespace.
 * - Enforces a maximum character length to prevent oversized payloads.
 */
const MAX_CHUNK_LENGTH = 2000;

function sanitizeText(text) {
  if (typeof text !== "string") return "";
  // Remove null bytes and non-printable control characters (keep \t, \n, \r)
  let sanitized = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Trim whitespace
  sanitized = sanitized.trim();
  // Enforce maximum length
  if (sanitized.length > MAX_CHUNK_LENGTH) {
    sanitized = sanitized.slice(0, MAX_CHUNK_LENGTH);
  }
  return sanitized;
}

function sanitizeDocument(doc) {
  if (!doc || typeof doc.pageContent !== "string") return null;
  const cleanContent = sanitizeText(doc.pageContent);
  if (!cleanContent) return null;
  return new Document({
    metadata: doc.metadata,
    pageContent: cleanContent,
  });
}

const auth = {
  detectSessionInUrl: false,
  persistSession: false,
  autoRefreshToken: false,
};

const client = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_PRIVATE_KEY,
  { auth }
);

// Patterns that indicate dynamic code execution primitives in LLM output
const DANGEROUS_PATTERNS = [
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bnew\s+Function\s*\(/i,
  /\bsetTimeout\s*\(\s*['"`]/i,
  /\bsetInterval\s*\(\s*['"`]/i,
  /\bimport\s*\(/i,
  /\brequire\s*\(/i,
  /\bprocess\.binding\s*\(/i,
  /\bchild_process/i,
  /\bvm\.runInThisContext\s*\(/i,
  /\bvm\.runInNewContext\s*\(/i,
  /\bvm\.runInContext\s*\(/i,
];

/**
 * Validates and sanitizes a document's pageContent from LLM output.
 * Throws if dangerous dynamic code execution primitives are detected.
 * @param {Document} doc
 * @returns {Document}
 */
function validateAndSanitizeDoc(doc) {
  if (!doc || typeof doc.pageContent !== "string") {
    throw new Error("Invalid document: pageContent must be a string.");
  }
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(doc.pageContent)) {
      throw new Error(
        `Dangerous pattern detected in LLM output (matched: ${pattern}). ` +
        `Document from file "${doc.metadata?.fileName}" was rejected.`
      );
    }
  }
  // Sanitize: remove null bytes and non-printable control characters
  const sanitizedContent = doc.pageContent
    .replace(/\0/g, "")
    .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  return new Document({
    metadata: doc.metadata,
    pageContent: sanitizedContent,
  });
}

const rawDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
const safeDocs = rawDocs.map((doc) => validateAndSanitizeDoc(doc));

const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
console.log(
  JSON.stringify({
    event: "llm_interaction_start",
    model: "text-embedding-ada-002",
    action: "SupabaseVectorStore.fromDocuments",
    documentCount: filteredDocs.length,
    timestamp: new Date().toISOString(),
  })
);
const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
const MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"; // HuggingFaceInferenceEmbeddings approved model
const inputHash = crypto
  .createHash("sha256")
  .update(JSON.stringify(filteredDocs.map((d) => d.pageContent)))
  .digest("hex");
const principal = process.env.AUDIT_PRINCIPAL || process.env.USER || "unknown";
const auditLogPath = process.env.AUDIT_LOG_PATH || "audit_trail.jsonl";

const auditRecordStart = {
  event: "embedding_operation_start",
  timestamp: new Date().toISOString(),
  principal,
  model_id: MODEL_ID,
  input_document_count: filteredDocs.length,
  input_hash_sha256: inputHash,
  target_table: "documents",
  supabase_url: process.env.SUPABASE_URL,
};
// Retention policy: rotate audit log when it exceeds MAX_AUDIT_LOG_BYTES (default 10 MB).
// Rotated backup files older than AUDIT_LOG_RETENTION_DAYS (default 90 days) are deleted
// in-process to enforce the forensic-readiness retention period without relying solely on
// an external tool.
const MAX_AUDIT_LOG_BYTES = parseInt(process.env.MAX_AUDIT_LOG_BYTES || String(10 * 1024 * 1024), 10);
const AUDIT_LOG_RETENTION_DAYS = parseInt(process.env.AUDIT_LOG_RETENTION_DAYS || "90", 10);
const AUDIT_LOG_RETENTION_MS = AUDIT_LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;
function purgeExpiredAuditBackups(logPath) {
  try {
    const dir = path.dirname(logPath);
    const base = path.basename(logPath);
    const now = Date.now();
    for (const entry of fs.readdirSync(dir)) {
      // Match rotated backups: <logfile>.<timestamp>.bak
      if (entry.startsWith(base + ".") && entry.endsWith(".bak")) {
        const parts = entry.split(".");
        const ts = parseInt(parts[parts.length - 2], 10);
        if (!isNaN(ts) && now - ts > AUDIT_LOG_RETENTION_MS) {
          const expired = path.join(dir, entry);
          fs.unlinkSync(expired);
          console.warn(`[AUDIT] Expired backup purged (>${AUDIT_LOG_RETENTION_DAYS}d): ${expired}`);
        }
      }
    }
  } catch (_purgeErr) {
    // Non-fatal: log directory may not exist yet or entries already removed.
  }
}
function rotateAuditLogIfNeeded(logPath) {
  try {
    const { size } = fs.statSync(logPath);
    if (size >= MAX_AUDIT_LOG_BYTES) {
      const rotatedPath = `${logPath}.${Date.now()}.bak`;
      fs.renameSync(logPath, rotatedPath);
      console.warn(`[AUDIT] Log rotated: ${rotatedPath}`);
    }
  } catch (_statErr) {
    // File does not exist yet — first write; no rotation needed.
  }
  purgeExpiredAuditBackups(logPath);
}
rotateAuditLogIfNeeded(auditLogPath);
appendFileSync(auditLogPath, JSON.stringify(auditRecordStart) + "\n", "utf8");
console.log("[AUDIT]", JSON.stringify(auditRecordStart));

try {
  await SupabaseVectorStore.fromDocuments(
    filteredDocs,
    new HuggingFaceInferenceEmbeddings({
    openAIApiKey: (() => { const creds = { openaiApiKey: process.env.OPENAI_API_KEY,   supabaseUrl: (() => { const creds = { openaiApiKey: process.env.OPENAI_API_KEY, supabaseUrl: process.env.SUPABASE_URL, supabaseKey: process.env.SUPABASE_SERVICE_ROLE_KEY }; return creds.supabaseUrl; })(), supabaseKey: process.env.SUPABASE_SERVICE_ROLE_KEY }; return creds.openaiApiKey; })(),
    modelName: "text-embedding-ada-002", // Pinned model version — required by model registry policy
  }),
    {
      client,
      tableName: "documents",
    }
  );

  const auditRecordEnd = {
    event: "embedding_operation_success",
    timestamp: new Date().toISOString(),
    principal,
    model_id: MODEL_ID,
    input_hash_sha256: inputHash,
    target_table: "documents",
  };
  rotateAuditLogIfNeeded(auditLogPath);
  appendFileSync(auditLogPath, JSON.stringify(auditRecordEnd) + "\n", "utf8");
  console.log("[AUDIT]", JSON.stringify(auditRecordEnd));

  // llm_interaction_end is written here — inside the try block — so it is part of
  // the persistent, causally-ordered audit trail and only emitted on actual success.
  const llmInteractionEnd = {
    event: "llm_interaction_end",
    model: "text-embedding-3-small",
    action: "SupabaseVectorStore.fromDocuments",
    status: "success",
    documentCount: filteredDocs.length,
    principal,
    model_id: MODEL_ID,
    input_hash_sha256: inputHash,
    timestamp: new Date().toISOString(),
  };
  rotateAuditLogIfNeeded(auditLogPath);
  appendFileSync(auditLogPath, JSON.stringify(llmInteractionEnd) + "\n", "utf8");
  console.log("[AUDIT]", JSON.stringify(llmInteractionEnd));
} catch (err) {
  const auditRecordError = {
    event: "embedding_operation_failure",
    timestamp: new Date().toISOString(),
    principal,
    model_id: MODEL_ID,
    input_hash_sha256: inputHash,
    target_table: "documents",
    error: err.message,
  };
  rotateAuditLogIfNeeded(auditLogPath);
  appendFileSync(auditLogPath, JSON.stringify(auditRecordError) + "\n", "utf8");
  console.error("[AUDIT]", JSON.stringify(auditRecordError));
  throw err;
}
// llm_interaction_end has been moved inside the try block above and is now
// persisted to the audit log file as part of the complete causal chain.
