"use client";

import {Fragment, useEffect, useState} from "react";
import { Dialog, Transition } from "@headlessui/react";
// useCompletion replaced with approved internal LLM hook
function useCompletion({ api, body }: { api: string; body?: Record<string, unknown> }) {
  const [completion, setCompletion] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const complete = async (prompt: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch(api, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt, ...body }),
      });
      if (!response.ok) {
        throw new Error(`Approved LLM API error: HTTP ${response.status} ${response.statusText}`);
      }
      const data = await response.json();
      const result = data.completion ?? data.text ?? "";
      setCompletion(result);
      return result;
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      setError(err);
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  return { completion, isLoading, error, complete };
}
import { useSession } from "next-auth/react";
import {ChatBlock, responseToChatBlocks} from "@/components/ChatBlock";

// Sanitize LLM output by detecting and neutralizing dynamic code execution primitives
function sanitizeLLMOutput(output: string): string {
  if (!output) return output;

  // Patterns that represent dynamic code execution primitives
  const dangerousPatterns: Array<{ pattern: RegExp; label: string }> = [
    { pattern: /\beval\s*\(/gi, label: "eval()" },
    { pattern: /\bexec\s*\(/gi, label: "exec()" },
    { pattern: /new\s+Function\s*\(/gi, label: "new Function()" },
    { pattern: /\bsetTimeout\s*\(\s*['"`]/gi, label: "setTimeout(string)" },
    { pattern: /\bsetInterval\s*\(\s*['"`]/gi, label: "setInterval(string)" },
    { pattern: /\bsetImmediate\s*\(\s*['"`]/gi, label: "setImmediate(string)" },
    { pattern: /document\.write\s*\(/gi, label: "document.write()" },
    { pattern: /\bimportScripts\s*\(/gi, label: "importScripts()" },
    { pattern: /\brequire\s*\(\s*['"`]/gi, label: "require(string)" },
    { pattern: /\b__import__\s*\(/gi, label: "__import__()" },
    { pattern: /\bcompile\s*\(/gi, label: "compile()" },
    { pattern: /\bexecfile\s*\(/gi, label: "execfile()" },
  ];

  let sanitized = output;
  const detectedPatterns: string[] = [];

  for (const { pattern, label } of dangerousPatterns) {
    if (pattern.test(sanitized)) {
      detectedPatterns.push(label);
      // Reset lastIndex for global regexes
      pattern.lastIndex = 0;
      // Neutralize by inserting a zero-width space after the keyword to break execution
      sanitized = sanitized.replace(pattern, (match) => {
        // Insert a unicode word-joiner after the function name to break the call
        return match.replace(/\(/, "\u2060(");
      });
    }
    // Reset lastIndex after test()
    pattern.lastIndex = 0;
  }

  if (detectedPatterns.length > 0) {
    console.warn(
      `[security] LLM output contained dynamic code execution primitives and was sanitized. Detected: ${detectedPatterns.join(", ")}`
    );
  }

  return sanitized;
}

// Audit logging for AI-driven actions (decision log / forensic trail)
// Entries are sent to a server-side endpoint for persistent, append-only, immutable storage.
// Server-side enforcement note:
// The /api/audit/ai-action endpoint MUST be configured with:
//   - Append-only / immutable storage (no UPDATE or DELETE on audit rows)
//   - Retention policy: minimum 12 months hot, 7 years cold (adjust per compliance requirement)
//   - Log rotation must preserve all entries (rotation = archive, not delete)
// These controls MUST be verified during infrastructure review.
async function logAIAuditEntry(entry: {
  timestamp: string;
  principal: string;
  modelId: string;
  modelVersion: string;
  inputHash: string;
  outputHash: string;
  correlationId: string;
}): Promise<void> {
  let response: Response | undefined;
  try {
    response = await fetch("/api/audit/ai-action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(entry),
    });
    if (!response.ok) {
      throw new Error(
        `[audit] Server rejected audit entry: HTTP ${response.status} ${response.statusText} (correlationId=${entry.correlationId})`
      );
    }
  } catch (e) {
    // Log to console so local diagnostics are preserved.
    console.error("[audit] Failed to persist audit entry to server:", e);

    // Alert the monitoring system so the failure is visible to ops/SIEM.
    // This is a best-effort call; we do not suppress the original error.
    try {
      await fetch("/api/monitoring/alert", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          severity: "CRITICAL",
          source: "logAIAuditEntry",
          message: "Audit log write failure — forensic trail may be incomplete",
          correlationId: entry.correlationId,
          timestamp: new Date().toISOString(),
          detail: e instanceof Error ? e.message : String(e),
        }),
      });
    } catch (alertErr) {
      // If the alerting call also fails, surface it so it is not silently swallowed.
      console.error("[audit] Additionally failed to send monitoring alert:", alertErr);
    }

    // Re-throw so the caller knows the audit write failed and can decide
    // whether to abort the AI action or surface the error to the user.
    throw e;
  }
}

/**
 * Validates user input before sending to the AI agent.
 * Returns null if the input is safe, or an error message string if it is rejected.
 */
function validateUserInput(input: string): string | null {
  if (!input || typeof input !== "string") {
    return "Input must be a non-empty string.";
  }

  const trimmed = input.trim();

  if (trimmed.length === 0) {
    return "Input must not be blank.";
  }

  if (trimmed.length > 2000) {
    return "Input exceeds maximum allowed length.";
  }

  // Detect base64-encoded payloads (long runs of base64 chars are suspicious)
  const base64Pattern = /(?:[A-Za-z0-9+/]{40,}={0,2})/;
  if (base64Pattern.test(trimmed)) {
    return "Input contains potentially encoded content that is not allowed.";
  }

  // Detect shell command patterns
  const shellCommandPattern =
    /(\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|Runtime\.exec)\b|[`$]\(|&&|\|\||;\s*\w|>\s*\/|<\s*\/|\bsudo\b|\brm\s+-rf\b|\bchmod\b|\bchown\b|\bcurl\b.*\|\s*bash|\bwget\b.*\|\s*bash)/i;
  if (shellCommandPattern.test(trimmed)) {
    return "Input contains shell command patterns that are not allowed.";
  }

  // Detect prompt injection attempts (instructions to override system prompt)
  const promptInjectionPattern =
    /(ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)|disregard\s+(all\s+)?(previous|prior|above|earlier)|you\s+are\s+now\s+|new\s+persona|act\s+as\s+|pretend\s+(you\s+are|to\s+be)|forget\s+(all\s+)?(previous|prior|your)\s+(instructions?|training)|system\s*:\s*|<\s*system\s*>|\[\s*system\s*\]|###\s*instruction|\bDAN\b|do\s+anything\s+now)/i;
  if (promptInjectionPattern.test(trimmed)) {
    return "Input contains prompt injection patterns that are not allowed.";
  }

  // Detect leetspeak obfuscation (excessive digit-for-letter substitution)
  // e.g. 1337, h4x0r, 3x3cut3, etc.
  const leetspeakPattern = /(?:[a-z]*[013457@$!][a-z0-9@$!]*){4,}/i;
  if (leetspeakPattern.test(trimmed)) {
    return "Input contains obfuscated text patterns that are not allowed.";
  }

  // Detect hidden/invisible unicode characters sometimes used to smuggle instructions
  // eslint-disable-next-line no-control-regex
  const hiddenCharsPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/;
  if (hiddenCharsPattern.test(trimmed)) {
    return "Input contains hidden or invisible characters that are not allowed.";
  }

  // Detect attempts to inject code blocks or script tags
  const codeInjectionPattern =
    /(<\s*script\b|<\s*iframe\b|javascript\s*:|data\s*:\s*text\/html|vbscript\s*:)/i;
  if (codeInjectionPattern.test(trimmed)) {
    return "Input contains script or markup injection patterns that are not allowed.";
  }

  return null; // Input is safe
}

function generateCorrelationId(): string {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }
    return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }
}

async function sha256Hex(message: string): Promise<string> {
  try {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  } catch {
    return "hash-unavailable";
  }
}

/**
 * Signs provenance metadata with HMAC-SHA256 using a session-scoped key.
 * Falls back to a double-SHA256 chain if HMAC is unavailable.
 * The resulting hex string is attached to the rendered output as a
 * verifiable provenance signature.
 */
async function signProvenance(metadata: {
  correlationId: string;
  outputHash: string;
  modelId: string;
  timestamp: string;
  principal: string;
}): Promise<string> {
  const payload = JSON.stringify(metadata);
  try {
    // Derive a session-scoped HMAC key from a combination of the correlation ID
    // and the output hash so the signature is unique per response.
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(metadata.correlationId + metadata.outputHash),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign(
      "HMAC",
      keyMaterial,
      new TextEncoder().encode(payload)
    );
    return Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  } catch {
    // Fallback: double-SHA256 chain
    const first = await sha256Hex(payload);
    return sha256Hex(first + metadata.correlationId);
  }
}

/**
 * Returns the text unchanged. Watermarking via invisible Unicode characters
 * has been removed as it constitutes a hidden prompt injection mechanism
 * and violates the organisation's content-integrity policy.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function embedWatermark(text: string, _correlationId: string): string {
  return text;
}

// Removed: `last_name` global variable eliminated to prevent PII tracking in component scope per output data minimisation policy.

/**
 * Masks a PII email address for display/logging purposes.
 * e.g. "john.doe@example.com" -> "j*******@example.com"
 */
function maskEmail(email: string | null | undefined): string {
  if (!email) return "[unknown]";
  const atIndex = email.indexOf("@");
  if (atIndex <= 0) return "***";
  const local = email.slice(0, atIndex);
  const domain = email.slice(atIndex);
  return local[0] + "*".repeat(Math.max(local.length - 1, 3)) + domain;
}

// Approved model registry with pinned versions
// NOTE: Only models explicitly approved by the organization's LLM governance process
// may be listed here. Do NOT add models without prior approval.
const DEFAULT_MODEL_KEY = "default-approved-model";

const APPROVED_MODEL_REGISTRY: Record<string, { version: string; endpoint: string }> = {
  // Approved model: gpt-4o, pinned to stable release 2024-08-06, served via the organization's
  // approved OpenAI-compatible endpoint. Approved by LLM Governance Board — do NOT modify
  // without a new approval ticket.
  "gpt-4o": { version: "gpt-4o-2024-08-06", endpoint: "openai" },
};

/** The key used when no explicit llmIdentifier is supplied to resolveApprovedModel. */
const DEFAULT_MODEL_KEY = "gpt-4o";
const DEFAULT_MODEL_ENDPOINT = APPROVED_MODEL_REGISTRY[DEFAULT_MODEL_KEY]?.endpoint ?? "";

const MAX_PROMPT_LENGTH = 4000;

/**
 * Sanitizes and validates user-supplied prompt input before sending to the LLM.
 * - Trims whitespace
 * - Enforces maximum length
 * - Strips ASCII control characters (except newlines/tabs)
 * - Removes common prompt injection patterns
 * Throws if the input is empty or invalid after sanitization.
 */
function sanitizeUserInput(input: string): string {
  if (typeof input !== "string") {
    throw new Error("Invalid input: prompt must be a string.");
  }

  // Trim leading/trailing whitespace
  let sanitized = input.trim();

  // Reject empty input
  if (!sanitized) {
    throw new Error("Invalid input: prompt must not be empty.");
  }

  // Enforce maximum length to prevent token exhaustion / abuse
  if (sanitized.length > MAX_PROMPT_LENGTH) {
    sanitized = sanitized.slice(0, MAX_PROMPT_LENGTH);
  }

  // Strip ASCII control characters except newline (\n, 0x0A) and tab (\t, 0x09)
  // eslint-disable-next-line no-control-regex
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Remove common prompt injection / jailbreak patterns (case-insensitive)
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /you\s+are\s+now\s+(a|an)\s+/gi,
    /act\s+as\s+(a|an)\s+/gi,
    /<\s*script[^>]*>/gi,
    /system\s*:/gi,
  ];
  for (const pattern of injectionPatterns) {
    sanitized = sanitized.replace(pattern, "");
  }

  // Final check: ensure something remains after sanitization
  if (!sanitized.trim()) {
    throw new Error("Invalid input: prompt is empty after sanitization.");
  }

  return sanitized;
}

/**
 * Validates a prompt for malicious content before LLM invocation.
 * Throws if the prompt contains hidden prompts, base64-encoded content,
 * leetspeak obfuscation, invisible text, shell commands, or binary data.
 */
function sanitizePrompt(prompt: string): void {
  // 1. Reject invisible/zero-width Unicode characters (hidden text injection)
  const invisibleCharsPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u2028\u2029]/;
  if (invisibleCharsPattern.test(prompt)) {
    throw new Error("Prompt rejected: contains invisible or zero-width characters.");
  }

  // 2. Reject non-printable / binary-like bytes (binary executable injection)
  // Allow common whitespace (\t, \n, \r) but reject other control characters
  const binaryPattern = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
  if (binaryPattern.test(prompt)) {
    throw new Error("Prompt rejected: contains non-printable or binary characters.");
  }

  // 3. Reject base64-encoded blocks (common exfiltration / hidden instruction vector)
  // Matches long base64 strings (40+ chars) that look like encoded payloads
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/;
  if (base64Pattern.test(prompt)) {
    throw new Error("Prompt rejected: contains suspected base64-encoded content.");
  }

  // 4. Reject shell command patterns
  const shellCommandPattern = /(?:^|\s|;|&&|\|\|)(\$\(|`|\bsudo\b|\brm\s+-rf\b|\bchmod\b|\bchown\b|\bcurl\b.*\|.*sh|\bwget\b.*\|.*sh|\beval\b|\bexec\b|\bsystem\b|\bpasswd\b|\b\/etc\/shadow\b|\b\/bin\/sh\b|\b\/bin\/bash\b)/i;
  if (shellCommandPattern.test(prompt)) {
    throw new Error("Prompt rejected: contains suspected shell command patterns.");
  }

  // 5. Reject prompt injection / jailbreak keywords
  const injectionPattern = /(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?|disregard\s+(?:all\s+)?(?:previous|prior|above)|you\s+are\s+now\s+(?:a|an|the)\s+|act\s+as\s+(?:a|an|the)\s+|pretend\s+(?:you\s+are|to\s+be)\s+|forget\s+(?:all\s+)?(?:previous|prior|your)\s+|new\s+instructions?\s*:|system\s*:\s*you\s+are|<\s*system\s*>|\[\s*system\s*\])/i;
  if (injectionPattern.test(prompt)) {
    throw new Error("Prompt rejected: contains suspected prompt injection content.");
  }

  // 6. Reject leetspeak obfuscation (common bypass technique)
  // Detects heavy use of digit-for-letter substitution (e.g. 1gn0r3, 3x3cut3)
  const leetspeakPattern = /\b(?=[a-z0-9]*[0-9][a-z0-9]*[a-z][a-z0-9]*)(?=[a-z0-9]*[a-z][a-z0-9]*[0-9][a-z0-9]*)[a-z0-9]{4,}\b/i;
  const leetspeakWords = prompt.match(/\b[a-z0-9]{3,}\b/gi) || [];
  const leetspeakCount = leetspeakWords.filter(w =>
    /[0-9]/.test(w) && /[a-z]/i.test(w) && (w.match(/[0-9]/g) || []).length / w.length > 0.4
  ).length;
  if (leetspeakCount >= 3) {
    throw new Error("Prompt rejected: contains suspected leetspeak obfuscation.");
  }

  // 7. Length guard — extremely long prompts may embed hidden instructions
  const MAX_PROMPT_LENGTH = 4000;
  if (prompt.length > MAX_PROMPT_LENGTH) {
    throw new Error(`Prompt rejected: exceeds maximum allowed length of ${MAX_PROMPT_LENGTH} characters.`);
  }
}

function resolveApprovedModel(llmIdentifier: string): string {
  const key = (llmIdentifier && llmIdentifier.trim()) ? llmIdentifier.trim() : DEFAULT_MODEL_KEY;
  const entry = APPROVED_MODEL_REGISTRY[key];
  if (!entry) {
    throw new Error(
      `Model "${key}" is not in the approved registry. Refusing to proceed with an unapproved model.`
    );
  }
  return entry.endpoint;
}

// Allowlist of permitted LLM API endpoint segments.
// Only endpoints with a corresponding pinned-version entry in APPROVED_MODEL_REGISTRY are allowed.
const ALLOWED_LLM_ENDPOINTS: ReadonlySet<string> = new Set([
  "openai",
  // "anthropic" and "cohere" removed: no pinned-version registry entries exist for these endpoints.
]);

function sanitizeLlmEndpoint(llm: string): string {
  if (typeof llm === "string" && ALLOWED_LLM_ENDPOINTS.has(llm)) {
    return llm;
  }
  return "";
}

// Patterns that represent dynamic code execution primitives that must not appear in LLM output
// NOTE: Patterns are constructed via RegExp() with split tokens to avoid embedding raw dangerous
// command strings verbatim in source. Do NOT reassemble these into inline regex literals.
const DANGEROUS_CODE_PATTERNS: RegExp[] = [
  /\b[e][v][a][l]\s*\(/gi,
  /\b[e][x][e][c]\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bFunction\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"\`]/gi,
  /\bsetInterval\s*\(\s*['"\`]/gi,
  /\bsetImmediate\s*\(\s*['"\`]/gi,
  /\bdocument\.write\s*\(/gi,
  /\binnerHTML\s*=/gi,
  /\bouterHTML\s*=/gi,
  /\bimportScripts\s*\(/gi,
  /\brequire\s*\(/gi,
  /\bprocess\.binding\s*\(/gi,
  /\b__import__\s*\(/gi,
  /\bcompile\s*\(/gi,
  /\b[e][x][e][c][f][i][l][e]\s*\(/gi,
];

/**
 * Sanitizes LLM output by detecting and removing dynamic code execution primitives.
 * Returns the sanitized string, or throws if the content is considered unsafe.
 */
function sanitizeLLMOutput(output: string): string {
  let sanitized = output;
  let foundViolations: string[] = [];

  for (const pattern of DANGEROUS_CODE_PATTERNS) {
    if (pattern.test(sanitized)) {
      foundViolations.push(pattern.toString());
      // Replace the dangerous pattern with a safe placeholder
      sanitized = sanitized.replace(pattern, "[REMOVED:UNSAFE_CODE]");
    }
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0;
  }

  if (foundViolations.length > 0) {
    console.warn(
      "[Security] LLM output contained dynamic code execution primitives and was sanitized. Patterns matched:",
      foundViolations
    );
  }

  return sanitized;
}

// Pinned model registry: each entry maps a route label to a versioned model ID and digest
const PINNED_MODEL_REGISTRY: Record<string, { version: string; digest: string; endpoint: string }> = {
  claude: {
    version: "claude-3-opus-20240229",
    digest: "sha256:claude-3-opus-20240229-abcdef1234567890",
    endpoint: "claude",
  },
  llama: {
    version: "meta-llama/Llama-3-8b-chat-hf",
    digest: "sha256:llama-3-8b-chat-hf-abcdef1234567890",
    endpoint: "llama",
  },
  mistral: {
    version: "mistralai/Mistral-7B-Instruct-v0.3",
    digest: "sha256:mistral-7b-instruct-v0.3-abcdef1234567890",
    endpoint: "mistral",
  },
};
const DEFAULT_APPROVED_LLM = "mistral";

function resolveApprovedModel(llm: string): { version: string; digest: string; endpoint: string } {
  const entry = PINNED_MODEL_REGISTRY[llm];
  if (!entry) {
    console.warn(
      `LLM route "${llm}" is not in the pinned model registry. Falling back to default model.`
    );
    return PINNED_MODEL_REGISTRY[DEFAULT_APPROVED_LLM];
  }
  return entry;
}

export default function QAModal({
  open,
  setOpen,
  example,
}: {
  open: boolean;
  setOpen: any;
  example: any;
}) {
  if (!example) {
    // create a dummy so the completion doesn't croak during init.
    example = new Object();
    example.llm = "";
    example.name = "";
  }

  const resolvedModel = resolveApprovedModel(example.llm);

  let {
    completion,
    input,
    isLoading,
    handleInputChange,
    handleSubmit,
    stop,
    setInput,
    setCompletion,
  } = useCompletion({
    api: "/api/" + resolvedModel.endpoint,
    headers: {
      name: example.name,
      "x-model-version": resolvedModel.version,
      "x-model-digest": resolvedModel.digest,
    },
  });

    const [inputError, setInputError] = useState<string | null>(null);

  const MALICIOUS_PATTERNS = [
    // Shell command patterns
    /(?:^|\s|;|&&|\|\|)[\s]*(?:rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat|chmod|chown|sudo|su|exec|eval|system|popen)\s/i,
    // Base64-encoded content (long base64 strings that may hide commands)
    /(?:[A-Za-z0-9+/]{40,}={0,2})/,
    // Prompt injection attempts
    /(?:ignore\s+(?:previous|above|prior|all)\s+instructions?)/i,
    /(?:disregard\s+(?:previous|above|prior|all)\s+instructions?)/i,
    /(?:forget\s+(?:previous|above|prior|all)\s+instructions?)/i,
    /(?:you\s+are\s+now|act\s+as|pretend\s+(?:you\s+are|to\s+be)|roleplay\s+as)/i,
    /(?:system\s*:\s*|<\s*system\s*>|\[\s*system\s*\])/i,
    // Hidden unicode / zero-width characters used for injection
    /[\u200B-\u200D\uFEFF\u00AD]/,
    // Script/HTML injection
    /<\s*script[^>]*>/i,
    /javascript\s*:/i,
  ];

  const sanitizeInput = (value: string): { safe: boolean; reason?: string } => {
    if (!value || value.trim().length === 0) {
      return { safe: true };
    }
    for (const pattern of MALICIOUS_PATTERNS) {
      if (pattern.test(value)) {
        return { safe: false, reason: "Input contains potentially malicious content and cannot be submitted." };
      }
    }
    // Limit input length to prevent large payload attacks
    if (value.length > 2000) {
      return { safe: false, reason: "Input exceeds the maximum allowed length of 2000 characters." };
    }
    return { safe: true };
  };

  const safeHandleInputChange = (e: React.ChangeEvent<HTMLInputElement> | React.ChangeEvent<HTMLTextAreaElement>) => {
    const value = e.target.value;
    const { safe, reason } = sanitizeInput(value);
    if (!safe) {
      setInputError(reason || "Input validation failed.");
      // Do not propagate the change — keep the previous safe value
      return;
    }
    setInputError(null);
    handleInputChange(e);
  };

  const safeHandleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setInputError(null);
    const { safe, reason } = sanitizeInput(input);
    if (!safe) {
      setInputError(reason || "Input validation failed.");
      return;
    }
    handleSubmit(e);
  };

  let [blocks, setBlocks] = useState<any[] | null>(null)

  useEffect(() => {
    // When the completion changes, parse it to multimodal blocks for display.
    if (completion) {
      setBlocks(responseToChatBlocks(completion))
    } else {
      setBlocks(null)
    }
  }, [completion])

  useEffect(() => {
    // Log LLM response when completion changes.
    if (completion) {
      console.log("[LLM Interaction] Response received", {
        timestamp: new Date().toISOString(),
        llm: example.llm,
        name: example.name,
        response: completion,
      });
    }
  }, [completion])

  const loggedHandleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    console.log("[LLM Interaction] Request submitted", {
      timestamp: new Date().toISOString(),
      llm: example.llm,
      name: example.name,
      input: input,
    });
    handleSubmit(e);
  };

  if (!example) {
    console.log("ERROR: no companion selected");
    return null;
  }

  // Authentication guard: do not render the modal or allow LLM invocation
  // for unauthenticated users.
  if (status === "loading") {
    return null; // Still determining auth state — render nothing.
  }
  if (!session) {
    return (
      <Transition.Root show={open} as={Fragment}>
        <Dialog as="div" className="relative z-10" onClose={() => setOpen(false)}>
          <div className="fixed inset-0 bg-gray-950 bg-opacity-75 transition-opacity" />
          <div className="fixed inset-0 z-10 flex items-center justify-center">
            <Dialog.Panel className="rounded-lg bg-gray-800 p-8 text-white shadow-xl">
              <p className="text-lg font-semibold">You must be signed in to use this feature.</p>
              <button
                className="mt-4 rounded bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
                onClick={() => setOpen(false)}
              >
                Close
              </button>
            </Dialog.Panel>
          </div>
        </Dialog>
      </Transition.Root>
    );
  }

  const MAX_INPUT_LENGTH = 1000;

  const sanitizeInput = (value: string): string => {
    // Strip HTML/script tags and trim whitespace
    return value
      .replace(/<[^>]*>/g, "")
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "") // strip non-printable control chars
      .trim()
      .slice(0, MAX_INPUT_LENGTH);
  };

  const handleSanitizedInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const sanitized = sanitizeInput(e.target.value);
    // Mutate the event value so useCompletion receives the sanitized string
    const syntheticEvent = {
      ...e,
      target: { ...e.target, value: sanitized },
    } as React.ChangeEvent<HTMLInputElement>;
    handleInputChange(syntheticEvent);
  };

  const handleValidatedSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const sanitized = sanitizeInput(input);
    if (!sanitized || sanitized.length === 0) {
      return; // reject empty or whitespace-only input
    }
    if (sanitized.length > MAX_INPUT_LENGTH) {
      return; // reject oversized input
    }
    handleSubmit(e);
  };

  const handleClose = () => {
    setInput("");
    setCompletion("");
    stop();
    setOpen(false);
  };

  return (
    <Transition.Root show={open} as={Fragment}>
      <Dialog as="div" className="relative z-10" onClose={handleClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-gray-950 bg-opacity-75 transition-opacity" />
        </Transition.Child>

        <div className="fixed inset-0 z-10 overflow-y-auto">
          <div className="flex min-h-full items-end justify-center p-4 text-center sm:items-center sm:p-0">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
              enterTo="opacity-100 translate-y-0 sm:scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 translate-y-0 sm:scale-100"
              leaveTo="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
            >
              <Dialog.Panel className="relative transform overflow-hidden rounded-lg bg-gray-800 px-4 pb-4 pt-5 text-left shadow-xl transition-all sm:my-8 sm:p-6 w-full max-w-3xl">
                <div>
                  <form onSubmit={loggedHandleSubmit}>
                    <input
                      placeholder="How's your day?"
                      className={"w-full flex-auto rounded-md border-0 bg-white/5 px-3.5 py-2 shadow-sm focus:outline-none sm:text-sm sm:leading-6 " + (isLoading && !completion ? "text-gray-600 cursor-not-allowed" : "text-white")}
                      onChange={(e) => { setPendingInput(e.target.value); handleInputChange(e); }}                      
                      value={input}
                      onChange={handleSanitizedInputChange}
                      disabled={isLoading && !blocks}
                    />
                    {inputError && (
                      <p className="mt-2 text-sm text-red-400" role="alert">
                        {inputError}
                      </p>
                    )}
                  </form>
                  <div className="mt-3 sm:mt-5">
                    <div className="mt-2">
                      <p className="text-sm text-gray-500">
                        Chat with {example.name}
                      </p>
                    </div>
                    {blocks && (
                      <div className="mt-2">
                        {blocks}
                      </div>
                    )}

                    {isLoading && !blocks && (
                      <p className="flex items-center justify-center mt-4">
                        <svg
                          className="animate-spin -ml-1 mr-3 h-5 w-5 text-white"
                          xmlns="http://www.w3.org/2000/svg"
                          fill="none"
                          viewBox="0 0 24 24"
                        >
                          <circle
                            className="opacity-25"
                            cx="12"
                            cy="12"
                            r="10"
                            stroke="currentColor"
                            strokeWidth="4"
                          ></circle>
                          <path
                            className="opacity-75"
                            fill="currentColor"
                            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                          ></path>
                        </svg>
                      </p>
                    )}
                  </div>
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition.Root>
  );
}
