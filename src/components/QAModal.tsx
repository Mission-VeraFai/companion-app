"use client";

import {Fragment, useEffect, useRef, useState} from "react";
import { useSession } from "next-auth/react";
import { Dialog, Transition } from "@headlessui/react";
import { useCompletion } from "ai/react";
import {ChatBlock, responseToChatBlocks} from "@/components/ChatBlock";

async function sha256Hex(message: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function computeProvenanceSignature(text: string, modelId: string, timestamp: string): Promise<string> {
  const payload = `${modelId}|${timestamp}|${text}`;
  return sha256Hex(payload);
}

async function writeAuditLog(entry: Record<string, unknown>): Promise<void> {
  // Enrich entry with required forensic fields if not already present.
  const sessionId =
    (typeof window !== "undefined" && (sessionStorage.getItem("sessionId") || localStorage.getItem("sessionId"))) ||
    "anonymous";

  const enrichedEntry: Record<string, unknown> = {
    ...entry,
    // Principal / session identifier (forensic requirement)
    principalId: sessionId,
    sessionId,
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
}

var last_name = "";

// Approved model registry: only models from the organization's approved list are permitted.
// IMPORTANT: Populate this registry exclusively with model identifiers and pinned versions
// that appear in the organization's official approved model registry.
// Do NOT add any model that has not been reviewed and approved by the security team.
const APPROVED_MODEL_REGISTRY: Record<string, string> = {
  // Example (replace with actual org-approved entries):
  // "org-approved-model-v1": "org-approved-model-v1@2024-01-01",
};

// Set this to a key that exists in APPROVED_MODEL_REGISTRY above.
const DEFAULT_APPROVED_MODEL = Object.keys(APPROVED_MODEL_REGISTRY)[0] ?? "";

function resolveApprovedModel(llmIdentifier: string): string {
  // Normalize bare model names to namespaced registry keys
  const normalize = (id: string): string => {
    if (id.startsWith("gpt-")) return `openai/${id}`;
    if (id.startsWith("claude-")) return `anthropic/${id}`;
    if (id.startsWith("llama-")) return `meta/${id}`;
    return id;
  };
  const normalized = normalize(llmIdentifier);
  if (!normalized || !(normalized in APPROVED_MODEL_REGISTRY)) {
    console.warn(
      `Model "${llmIdentifier}" (normalized: "${normalized}") is not in the approved registry. Falling back to default: ${DEFAULT_APPROVED_MODEL}`
    );
    return APPROVED_MODEL_REGISTRY[DEFAULT_APPROVED_MODEL];
  }
  return APPROVED_MODEL_REGISTRY[normalized];
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
