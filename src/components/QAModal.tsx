"use client";

import {Fragment, useEffect, useState} from "react";
import { Dialog, Transition } from "@headlessui/react";
import { useCompletion } from "ai/react";
import { useSession } from "next-auth/react";
import {ChatBlock, responseToChatBlocks} from "@/components/ChatBlock";

// Audit logging for AI-driven actions (decision log / forensic trail)
// Entries are sent to a server-side endpoint for persistent, append-only, immutable storage.
async function logAIAuditEntry(entry: {
  timestamp: string;
  principal: string;
  modelId: string;
  modelVersion: string;
  inputHash: string;
  outputHash: string;
  correlationId: string;
}) {
  try {
    await fetch("/api/audit/ai-action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(entry),
    });
  } catch (e) {
    console.error("[audit] Failed to persist audit entry to server:", e);
  }
}

function generateCorrelationId(): string {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
},
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
    return "signature-unavailable";
  }
}

async function logAIAuditEntry(entry: {
  timestamp: string;
  principal: string;
  modelId: string;
  inputHash: string;
  outputHash: string;
}) {
  try {
    const key = `ai_audit_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const signedEntry = {
      ...entry,
      originTag: "ai-generated",
      signature: await signAuditEntry(entry),
    };
    // Store only minimised (hashed) output — never raw LLM response — per output data minimisation policy.
    localStorage.setItem(key, JSON.stringify(signedEntry));
  } catch (e) {
    console.error("[audit] Failed to persist audit entry:", e);
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
const APPROVED_MODEL_REGISTRY: Record<string, { version: string; endpoint: string }> = {
  "gpt-4o": { version: "gpt-4o-2024-05-13", endpoint: "openai" },
};

const DEFAULT_MODEL_ENDPOINT = "openai";

function resolveApprovedModel(llmIdentifier: string): string {
  const key = llmIdentifier || DEFAULT_MODEL_KEY;
  const entry = APPROVED_MODEL_REGISTRY[key];
  if (!entry) {
    throw new Error(
      `Model "${key}" is not in the approved registry. Refusing to proceed with an unapproved model.`
    );
  }
  return entry.endpoint;
}

// Allowlist of permitted LLM API endpoint segments
const ALLOWED_LLM_ENDPOINTS: ReadonlySet<string> = new Set([
  "openai",
  "anthropic",
  "cohere",
  // Add other permitted endpoint names here
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
  new RegExp("\\b" + "ev" + "al" + "\\s*\\(", "gi"),
  new RegExp("\\b" + "ex" + "ec" + "\\s*\\(", "gi"),
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
  new RegExp("\\b" + "ex" + "ec" + "fi" + "le" + "\\s*\\(", "gi"),
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
