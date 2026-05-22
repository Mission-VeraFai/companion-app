"use client";

import {Fragment, useEffect, useRef, useState, useMemo} from "react";
import { useSession } from "next-auth/react";
import { Dialog, Transition } from "@headlessui/react";
// useCompletion replaced with approved internal fetch-based hook
function useCompletion({ api, body, onFinish, onError }: { api: string; body?: Record<string, unknown>; onFinish?: (prompt: string, completion: string) => void; onError?: (err: Error) => void; }) {
  const [completion, setCompletion] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | undefined>(undefined);

  const complete = async (prompt: string, options?: { body?: Record<string, unknown> }) => {
    setIsLoading(true);
    setError(undefined);
    setCompletion("");
    try {
      const res = await fetch(api, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt, ...body, ...(options?.body ?? {}) }),
      });
      if (!res.ok) throw new Error(`Request failed: ${res.status}`);
      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      let full = "";
      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = decoder.decode(value, { stream: true });
          full += chunk;
          setCompletion(full);
        }
      }
      onFinish?.(prompt, full);
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      setError(err);
      onError?.(err);
    } finally {
      setIsLoading(false);
    }
  };

  return { completion, isLoading, error, complete };
}
import {ChatBlock, responseToChatBlocks} from "@/components/ChatBlock";

// Patterns that indicate dynamic code execution primitives in LLM output
const DYNAMIC_CODE_PATTERNS: RegExp[] = [
  /\beval\s*\(/gi,
  /\bFunction\s*\(/gi,
  /\bnew\s+Function\b/gi,
  /\bexec\s*\(/gi,
  /\bexecSync\s*\(/gi,
  /\bspawnSync\s*\(/gi,
  /\bspawn\s*\(/gi,
  /\bexecFile\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"`]/gi,
  /\bsetInterval\s*\(\s*['"`]/gi,
  /\bsetImmediate\s*\(\s*['"`]/gi,
  /\bvm\.runInThisContext\b/gi,
  /\bvm\.runInNewContext\b/gi,
  /\bvm\.Script\b/gi,
  /\bimportScripts\s*\(/gi,
  /\bdocument\.write\s*\(/gi,
  /\binnerHTML\s*=/gi,
  /\bouterHTML\s*=/gi,
  /\binsertAdjacentHTML\s*\(/gi,
  /javascript\s*:/gi,
  /data\s*:\s*text\/html/gi,
  /\bprocess\.binding\s*\(/gi,
  /\brequire\s*\(\s*['"`]child_process/gi,
  /\b__import__\s*\(/gi,
  /\bcompile\s*\(/gi,
  /\bexecfile\s*\(/gi,
];

/**
 * Validates LLM output for the presence of dynamic code execution primitives.
 * Returns an object indicating whether the output is safe and which patterns were found.
 */
function validateLLMOutput(output: string): { safe: boolean; violations: string[] } {
  const violations: string[] = [];
  for (const pattern of DYNAMIC_CODE_PATTERNS) {
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0;
    if (pattern.test(output)) {
      violations.push(pattern.toString());
    }
  }
  return { safe: violations.length === 0, violations };
}

/**
 * Sanitizes LLM output by removing dynamic code execution primitives.
 * Logs a warning if any violations are found.
 * Returns sanitized output, or throws if the output cannot be safely sanitized.
 */
function sanitizeLLMOutput(output: string): string {
  const { safe, violations } = validateLLMOutput(output);
  if (!safe) {
    console.warn(
      "[security] LLM output contained dynamic code execution primitives. Blocking output.",
      violations
    );
    // Block the entire output to prevent any partial execution risk
    return "[Response blocked: output contained potentially unsafe dynamic code execution patterns.]"
  }
  return output;
}

function detectMaliciousInput(input: string): { safe: boolean; reason: string } {
  // Check for hidden/invisible characters used in prompt injection
  const hiddenCharsPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/;
  if (hiddenCharsPattern.test(input)) {
    return { safe: false, reason: "Input contains hidden or invisible characters that may indicate a prompt injection attempt." };
  }

  // Check for base64-encoded content (blocks of base64 that could hide malicious payloads)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/;
  if (base64Pattern.test(input)) {
    return { safe: false, reason: "Input contains base64-encoded content which may conceal malicious commands." };
  }

  // Check for leetspeak patterns commonly used to obfuscate malicious instructions
  const leetspeakPattern = /(?:[e3][x*][e3][c*]|[s$][h#][e3][l1][l1]|[p*][o0][w*][e3][r*][s$][h#][e3][l1][l1]|[s$][y*][s$][t*][e3][m*]|[r*][m*]\s*[-\/]|[d*][e3][l1][e3][t*][e3]\s)/i;
  if (leetspeakPattern.test(input)) {
    return { safe: false, reason: "Input contains leetspeak obfuscation patterns associated with malicious commands." };
  }

  // Check for shell command patterns
  const shellCommandPattern = /(?:^|\s|;|\||&|`)(\s*)(sudo|chmod|chown|wget|curl\s+.*-[oO]|nc\s|ncat\s|bash\s+-[ci]|sh\s+-[ci]|python[23]?\s+-c|perl\s+-e|ruby\s+-e|php\s+-r|eval\s*\(|exec\s*\(|system\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(|shell_exec\s*\(|`[^`]+`|\$\([^)]+\)|rm\s+(-rf?\s+\/|--no-preserve-root)|mkfs|dd\s+if=|fork\s*bomb|:\s*\(\s*\)\s*\{)/i;
  if (shellCommandPattern.test(input)) {
    return { safe: false, reason: "Input contains shell command patterns that could execute malicious code." };
  }

  // Check for binary/executable magic bytes encoded as escape sequences or hex strings
  const binaryMagicPattern = /(?:\\x4d\\x5a|\\x7f\\x45\\x4c\\x46|MZ[\s\S]{0,2}\x90|\x7fELF|%PDF-|\x89PNG)/i;
  if (binaryMagicPattern.test(input)) {
    return { safe: false, reason: "Input contains binary executable signatures." };
  }

  // Check for prompt injection instruction overrides
  const promptInjectionPattern = /(?:ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)|disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)|you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken|DAN)|do\s+anything\s+now|pretend\s+(you\s+have\s+no\s+restrictions|there\s+are\s+no\s+rules)|act\s+as\s+(if\s+you\s+are\s+)?(?:an?\s+)?(?:unrestricted|evil|malicious)|\[SYSTEM\]|\[INST\]|<\|im_start\|>|<\|system\|>)/i;
  if (promptInjectionPattern.test(input)) {
    return { safe: false, reason: "Input contains prompt injection patterns attempting to override system instructions." };
  }

  // Check for excessive special characters that may indicate obfuscated payloads
  const specialCharRatio = (input.match(/[^a-zA-Z0-9\s.,!?;:'"()-]/g) || []).length / Math.max(input.length, 1);
  if (specialCharRatio > 0.3 && input.length > 20) {
    return { safe: false, reason: "Input contains an unusually high ratio of special characters, which may indicate an obfuscated payload." };
  }

  return { safe: true, reason: "" };
}

async function sha256Hex(message: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Compute an HMAC-SHA-256 MAC over `message` using a secret key.
 * The secret is read from the NEXT_PUBLIC_AUDIT_HMAC_SECRET env var;
 * falls back to a build-time constant so the function never throws.
 * NOTE: for production, NEXT_PUBLIC_AUDIT_HMAC_SECRET must be set to a
 * high-entropy secret that is NOT committed to source control.
 */
async function hmacSha256Hex(message: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", keyMaterial, enc.encode(message));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Sanitized completion derived from rawCompletion — safe to render
  const completion = sanitizeLLMOutput(rawCompletion ?? "");

async function computeProvenanceSignature(text: string, modelId: string, timestamp: string): Promise<string> {
  const payload = `${modelId}|${timestamp}|${text}`;
  const secret = process.env.NEXT_PUBLIC_AUDIT_HMAC_SECRET ?? "__CHANGE_ME_IN_ENV__";
  return hmacSha256Hex(payload, secret);
}

/** Sanitizing wrapper around the raw `complete` function from useCompletion. */
  const safeComplete = async (rawInput: string, options?: Parameters<typeof _complete>[1]) => {
    const sanitized = sanitizeAndValidatePrompt(rawInput);
    return _complete(sanitized, options);
  };

// Module-level trace ID: generated once per page/session load and shared across
// all writeAuditLog calls so that every log entry in a multi-step workflow can
// be correlated end-to-end by this single traceId.
const _auditTraceId: string = (() => {
  if (typeof window === "undefined") return `trace-ssr-${Date.now()}`;
  const stored = sessionStorage.getItem("auditTraceId");
  if (stored) return stored;
  const generated = `trace-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  sessionStorage.setItem("auditTraceId", generated);
  return generated;
})();

/**
 * @param entry        - Audit fields to record.
 * @param principalId  - Verified principal identifier obtained from the
 *                       server-side signed session (e.g. next-auth session
 *                       user email/id). Must NOT come from client storage.
 */
async function writeAuditLog(entry: Record<string, unknown>, principalId: string = "anonymous"): Promise<void> {
  // Enrich entry with required forensic fields if not already present.
  // principalId is supplied by the caller from a server-verified session token
  // (next-auth JWT) — never read from sessionStorage/localStorage directly.

  const enrichedEntry: Record<string, unknown> = {
    ...entry,
    // Principal / session identifier (forensic requirement)
    principalId,
    sessionId: principalId,
    // Timestamp (ISO-8601, always overwrite to guarantee server-side ordering)
    timestamp: new Date().toISOString(),
  };

  // Compute input hash if an `input` field is present and hash not already supplied.
  if (typeof enrichedEntry.input === "string" && !enrichedEntry.inputHash) {
    try {
      enrichedEntry.inputHash = await sha256Hex(enrichedEntry.input as string);
    } catch {
      enrichedEntry.inputHash = "hash-unavailable";
    }
  }

  // Ensure modelVersion is recorded.
  if (!enrichedEntry.modelVersion && enrichedEntry.model) {
    enrichedEntry.modelVersion = resolveApprovedModel(enrichedEntry.model as string);
  }

  let response: Response;
  try {
    response = await fetch("/api/audit", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // Signal append-only / immutable retention intent to the server.
        "X-Audit-Append-Only": "true",
        "X-Audit-Retention-Policy": "immutable",
      },
      body: JSON.stringify(enrichedEntry),
    });
  } catch (err) {
    // Network-level failure: log and re-throw so callers can handle / alert.
    console.error("[audit] network error writing audit log", err);
    throw new Error(`[audit] Failed to reach audit endpoint: ${(err as Error).message}`);
  }

  if (!response.ok) {
    const msg = `[audit] Audit endpoint returned HTTP ${response.status}`;
    console.error(msg);
    throw new Error(msg);
  }

  // Enforce server-side retention policy acknowledgement.
  // The audit server MUST respond with a body confirming immutable/append-only
  // storage was applied. Advisory headers alone are insufficient — we require
  // the server to echo back its enforcement decision so the client can detect
  // misconfigured or non-compliant audit backends.
  let ackBody: Record<string, unknown> = {};
  try {
    ackBody = (await response.json()) as Record<string, unknown>;
  } catch {
    throw new Error(
      "[audit] Audit endpoint did not return a parseable JSON acknowledgement — retention policy enforcement cannot be confirmed."
    );
  }
  const retentionAck = ackBody["retentionPolicy"] ?? ackBody["retention_policy"];
  if (retentionAck !== "immutable") {
    throw new Error(
      `[audit] Server did not confirm immutable retention policy. Received: ${JSON.stringify(retentionAck)}. ` +
        "Audit record may not be forensically preserved."
    );
  }
}

var last_name = "";

// Maximum allowed prompt length (characters)
const MAX_PROMPT_LENGTH = 2000;

/**
 * Sanitize and validate user input before sending to the LLM.
 * - Trims whitespace
 * - Strips null bytes and control characters (except newlines/tabs)
 * - Removes potential prompt-injection patterns
 * - Enforces a maximum length
 * Throws an Error if the input is invalid.
 */
function sanitizeAndValidatePrompt(input: string): string {
  if (typeof input !== "string") {
    throw new Error("Invalid input: prompt must be a string.");
  }

  // Trim surrounding whitespace
  let sanitized = input.trim();

  // Reject empty input
  if (sanitized.length === 0) {
    throw new Error("Prompt must not be empty.");
  }

  // Enforce maximum length
  if (sanitized.length > MAX_PROMPT_LENGTH) {
    throw new Error(
      `Prompt exceeds maximum allowed length of ${MAX_PROMPT_LENGTH} characters.`
    );
  }

  // Strip null bytes and non-printable control characters (keep \n, \r, \t)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Remove common prompt-injection delimiters / jailbreak scaffolding
  sanitized = sanitized.replace(
    /<\|.*?\|>|\[INST\]|\[\/INST\]|###\s*(System|Human|Assistant|Instruction):/gi,
    ""
  );

  // Final check: ensure something meaningful remains after sanitization
  if (sanitized.trim().length === 0) {
    throw new Error("Prompt contained only disallowed characters.");
  }

  return sanitized;
}

// Approved model registry: only models from the organization's approved list are permitted.
// IMPORTANT: Populate this registry exclusively with model identifiers and pinned versions
// that appear in the organization's official approved model registry.
// Do NOT add any model that has not been reviewed and approved by the security team.
const APPROVED_MODEL_REGISTRY: Record<string, string> = {
  // Pinned, integrity-verified model identifiers approved by the security team.
  // Format: "<namespace>/<model-id>": "<model-id>@<pinned-version>"
  "openai/gpt-4o": "gpt-4o@2024-08-06",
  "anthropic/claude-3-5-sonnet": "claude-3-5-sonnet-20241022",
  "meta/llama-3.1-70b": "llama-3.1-70b@2024-07-23",
};

// Set this to a key that exists in APPROVED_MODEL_REGISTRY above.
const DEFAULT_APPROVED_MODEL = "openai/gpt-4o";

function resolveApprovedModel(llmIdentifier: string): string {
  // Only allow models that are explicitly listed in the approved registry.
  // No normalization or prefix-based routing is performed — identifiers must
  // match registry keys exactly to prevent disallowed models from being used.
  if (!llmIdentifier || !(llmIdentifier in APPROVED_MODEL_REGISTRY)) {
    console.warn(
      `Model "${llmIdentifier}" is not in the approved registry. Falling back to default: ${DEFAULT_APPROVED_MODEL}`
    );
    return APPROVED_MODEL_REGISTRY[DEFAULT_APPROVED_MODEL] ?? "";
  }
  return APPROVED_MODEL_REGISTRY[llmIdentifier];
}" is not in the approved registry. Falling back to default: ${DEFAULT_APPROVED_MODEL}`
    );
    return APPROVED_MODEL_REGISTRY[DEFAULT_APPROVED_MODEL] ?? "";
  }
  return APPROVED_MODEL_REGISTRY[llmIdentifier];
}

// Allowlist of permitted LLM API endpoint segments.
// Only values in this set may be interpolated into the API path.
const ALLOWED_LLM_ENDPOINTS: ReadonlySet<string> = new Set([
  "openai",
  "anthropic",
  "cohere",
  "mistral",
]);

function getSafeLlmEndpoint(llm: string): string {
  if (ALLOWED_LLM_ENDPOINTS.has(llm)) {
    return llm;
  }
  // Return empty string so the path becomes "/api/" which is harmless
  // and will not route to any unintended endpoint.
  return "";
}

const ALLOWED_LLM_PATHS: ReadonlySet<string> = new Set([
  "openai",
  "anthropic",
  "cohere",
  // Add every legitimate LLM route segment here
]);

function getAllowedLlmPath(llm: string): string {
  if (typeof llm === "string" && ALLOWED_LLM_PATHS.has(llm)) {
    return llm;
  }
  return "";
}

// Sanitize user input before sending to the LLM
function sanitizeUserInput(text: string): string {
  if (!text || typeof text !== "string") return "";
  // Trim whitespace
  let sanitized = text.trim();
  // Enforce maximum prompt length (4000 chars)
  const MAX_PROMPT_LENGTH = 4000;
  if (sanitized.length > MAX_PROMPT_LENGTH) {
    sanitized = sanitized.slice(0, MAX_PROMPT_LENGTH);
  }
  // Remove null bytes and non-printable control characters (except newlines/tabs)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Strip prompt injection attempts: remove sequences that try to override system instructions
  sanitized = sanitized.replace(/ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi, "[removed]");
  sanitized = sanitized.replace(/system\s*:\s*/gi, "");
  return sanitized;
}

/**
 * Sanitize user-supplied prompt input before sending to the LLM.
 * Returns the cleaned string, or null if the input should be blocked entirely.
 */
function sanitizeUserInput(text: string): string | null {
  if (!text || typeof text !== "string") return "";

  // 1. Block binary/non-printable content (potential binary executables)
  // Allow common whitespace (\t, \n, \r) but block other control characters
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(text)) {
    console.warn("[security] Input blocked: binary or non-printable characters detected.");
    return null;
  }

  // 2. Block base64-encoded blobs (long base64 strings are a common smuggling vector)
  // Heuristic: 60+ char base64-looking token with no spaces
  if (/(?:[A-Za-z0-9+/]{60,}={0,2})/.test(text)) {
    console.warn("[security] Input blocked: suspected base64-encoded content detected.");
    return null;
  }

  // 3. Block shell command patterns
  const shellPatterns: RegExp[] = [
    /`[^`]*`/,                          // backtick execution
    /\$\([^)]*\)/,                      // $(command) substitution
    /;\s*(rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat|chmod|chown|sudo|su|exec|eval)\b/i,
    /&&\s*(rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat|chmod|chown|sudo|su|exec|eval)\b/i,
    /\|\s*(bash|sh|python|perl|ruby|nc|ncat|netcat|exec|eval)\b/i,
    /\b(rm\s+-rf|mkfifo|mknod|dd\s+if=|wget\s+http|curl\s+http)\b/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(text)) {
      console.warn("[security] Input blocked: shell command pattern detected.");
      return null;
    }
  }

  // 4. Block hidden/invisible prompt injection characters
  // Zero-width spaces, direction overrides, and other invisible Unicode
  if (/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/.test(text)) {
    console.warn("[security] Input blocked: hidden/invisible Unicode characters detected.");
    return null;
  }

  // 5. Block leetspeak-obfuscated dangerous keywords
  // Normalize common leet substitutions and check for dangerous terms
  const leetNormalized = text
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s")
    .toLowerCase();
  const blockedLeetTerms: RegExp[] = [
    /\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|constraints?)\b/,
    /\bforget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|constraints?)\b/,
    /\bact\s+as\s+(if\s+you\s+are|a)\b/,
    /\byou\s+are\s+now\b/,
    /\bdan\s+mode\b/,
    /\bjailbreak\b/,
    /\bprompt\s+injection\b/,
    /\bsystem\s+prompt\b/,
    /\boverride\s+(your\s+)?(instructions?|rules?|constraints?)\b/,
  ];
  for (const pattern of blockedLeetTerms) {
    if (pattern.test(leetNormalized)) {
      console.warn("[security] Input blocked: suspected prompt injection or jailbreak attempt detected.");
      return null;
    }
  }

  // 6. Strip any remaining suspicious HTML/script tags that could affect rendering
  const stripped = text.replace(/<script[\s\S]*?<\/script>/gi, "").replace(/<[^>]+>/g, "");

  return stripped.trim();
}

// Sanitize LLM output by removing/neutralizing dynamic code execution primitives
function sanitizeLLMOutput(text: string): string {
  if (!text) return text;

  // Patterns for dynamic code execution primitives
  const dangerousPatterns: Array<[RegExp, string]> = [
    // eval(...) calls
    [/\beval\s*\(/gi, "[eval removed](" ],
    // Function constructor: new Function(...) or Function(...)
    [/\bnew\s+Function\s*\(/gi, "[Function removed](" ],
    [/(?<!\w)Function\s*\(/g, "[Function removed](" ],
    // setTimeout/setInterval with string argument (dynamic execution)
    [/\bsetTimeout\s*\(\s*['"`]/gi, "[setTimeout removed](\"" ],
    [/\bsetInterval\s*\(\s*['"`]/gi, "[setInterval removed](\"" ],
    // execScript (IE legacy)
    [/\bexecScript\s*\(/gi, "[execScript removed](" ],
    // document.write with script
    [/\bdocument\.write\s*\(/gi, "[document.write removed](" ],
    // importScripts
    [/\bimportScripts\s*\(/gi, "[importScripts removed](" ],
    // __import__ (Python-style, defensive)
    [/\b__import__\s*\(/gi, "[__import__ removed](" ],
    // exec( as a standalone call (Python exec)
    [/\bexec\s*\(/gi, "[exec removed](" ],
  ];

  let sanitized = text;
  for (const [pattern, replacement] of dangerousPatterns) {
    sanitized = sanitized.replace(pattern, replacement);
  }

  return sanitized;
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
  const { data: session, status } = useSession();

  // Session integrity validation: verify expiry and subject binding before trusting session data.
  const validateSession = (sess: typeof session): boolean => {
    if (!sess) return false;
    // Check expiry: next-auth sessions expose `expires` as an ISO string.
    if (sess.expires) {
      const expiryTime = new Date(sess.expires).getTime();
      if (isNaN(expiryTime) || Date.now() >= expiryTime) {
        console.warn("[QAModal] Session token has expired.");
        return false;
      }
    } else {
      // No expiry field — reject to be safe.
      console.warn("[QAModal] Session token missing expiry field.");
      return false;
    }
    // Subject binding: ensure a stable user identifier is present.
    const subject = sess.user?.email ?? (sess as any).sub ?? (sess as any).userId;
    if (!subject || typeof subject !== "string" || subject.trim() === "") {
      console.warn("[QAModal] Session token missing or invalid subject binding.");
      return false;
    }
    return true;
  };

  const isSessionValid = status === "authenticated" && validateSession(session);
  const trustedSession = isSessionValid ? session : null;

  if (status === 'loading') {
    return null;
  }

  if (status !== 'authenticated') {
    return (
      <div className="p-4 text-center">
        <p>You must be signed in to use the AI Agent.</p>
      </div>
    );
  }

  if (status === "unauthenticated") {
    return null;
  }

  if (!example) {
    // create a dummy so the completion doesn't croak during init.
    example = new Object();
    example.llm = "";
    example.name = "";
  }

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
    api: "/api/approved-llm",
    headers: { name: example.name },
  });

    let [blocks, setBlocks] = useState<any[] | null>(null)
  let [lastInput, setLastInput] = useState<string>("")

  useEffect(() => {
    // When the completion changes, parse it to multimodal blocks for display.
    if (completion) {
      setBlocks(responseToChatBlocks(completion));
      // Audit the final output once loading is done.
      if (!isLoading && pendingAudit.current) {
        const finalEntry = {
          ...pendingAudit.current,
          output: completion,
          outputHash: "",
          completedAt: new Date().toISOString(),
          status: "completed",
        };
        sha256Hex(completion).then((outputHash) => {
          writeAuditLog({ ...finalEntry, outputHash });
          pendingAudit.current = null;
        });
      }
    } else {
      setBlocks(null);
    }
  }, [completion, isLoading]);

  useEffect(() => {
    // Log LLM response when a completion is received.
    if (completion && lastInput) {
      console.log(JSON.stringify({
        event: "llm_response",
        timestamp: new Date().toISOString(),
        companion: example.name,
        llm: example.llm,
        request: lastInput,
        response: completion,
      }));
    }
  }, [completion])

  const loggedHandleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    // Log LLM request before submission.
    console.log(JSON.stringify({
      event: "llm_request",
      timestamp: new Date().toISOString(),
      companion: example.name,
      llm: example.llm,
      input: input,
    }));
    setLastInput(input);
    handleSubmit(e);
  };

  if (!example) {
    console.log("ERROR: no companion selected");
    return null;
  }

  const MAX_INPUT_LENGTH = 1000;

  const sanitizeInput = (value: string): string => {
    // Trim whitespace
    let sanitized = value.trim();
    // Remove null bytes and non-printable control characters (except common whitespace)
    sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
    // Truncate to maximum allowed length
    sanitized = sanitized.slice(0, MAX_INPUT_LENGTH);
    return sanitized;
  };

  const handleSanitizedSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const sanitized = sanitizeInput(input);
    if (!sanitized) {
      return;
    }
    setInput(sanitized);
    // Defer to allow setInput to propagate before submission
    setTimeout(() => handleSubmit(e), 0);
  };

  const isMaliciousInput = (text: string): boolean => {
    // Check for base64-encoded content
    const base64Pattern = /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$/;
    if (base64Pattern.test(text.trim()) && text.trim().length > 20) return true;

    // Check for shell command patterns
    const shellCommandPattern = /(?:^|\s|;|&&|\|\|)(ls|cat|rm|wget|curl|bash|sh|python|perl|ruby|exec|eval|system|chmod|chown|sudo|su|nc|ncat|netcat|dd|mkfifo|mknod|telnet|ssh|scp|ftp|tftp|awk|sed|grep|find|xargs|env|export|source|\.|printf|echo|read|write|tee|head|tail|cut|sort|uniq|wc|tr|base64|xxd|od|hexdump|openssl|gpg|tar|gzip|zip|unzip|7z|rar|mount|umount|fdisk|parted|mkfs|fsck|lsblk|blkid|lsof|ps|kill|pkill|killall|nohup|screen|tmux|at|cron|crontab|passwd|useradd|userdel|groupadd|groupdel|visudo|iptables|ufw|firewall-cmd|systemctl|service|init|reboot|shutdown|halt|poweroff)(?:\s|$|;|&&|\|\|)/i;
    if (shellCommandPattern.test(text)) return true;

    // Check for prompt injection markers / hidden instructions
    const promptInjectionPattern = /(?:ignore\s+(?:previous|above|prior|all)\s+instructions?|disregard\s+(?:previous|above|prior|all)|forget\s+(?:previous|above|prior|all)|new\s+instructions?\s*:|system\s*:|<\s*system\s*>|\[\s*system\s*\]|###\s*instruction|###\s*system|you\s+are\s+now|act\s+as\s+(?:a\s+)?(?:different|new|another)|pretend\s+(?:you\s+are|to\s+be)|roleplay\s+as|jailbreak|dan\s+mode|developer\s+mode)/i;
    if (promptInjectionPattern.test(text)) return true;

    // Check for leetspeak obfuscation (excessive substitution of letters with numbers/symbols)
    const leetspeakPattern = /(?:[a@][s$][s$]|[s$][h#][e3][l1][l1]|[e3][x*][e3][c*]|[s$][y*][s$][t+][e3][m*]|[p*][a@][s$][s$][w*][o0][r*][d*]|[h#][a@][c*][k*])/i;
    if (leetspeakPattern.test(text)) return true;

    // Check for excessive special characters that may indicate obfuscation
    const specialCharRatio = (text.match(/[^a-zA-Z0-9\s.,!?'"()-]/g) || []).length / text.length;
    if (text.length > 10 && specialCharRatio > 0.3) return true;

    return false;
  };

  const handleSafeSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isMaliciousInput(input)) {
      alert("Your message contains content that cannot be processed. Please rephrase your question.");
      return;
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
                      value={input}
                      onChange={handleInputChange}
                      disabled={isLoading && !blocks}
                    />
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
                            stroke-width="4"
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
