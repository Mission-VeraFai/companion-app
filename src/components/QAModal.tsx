"use client";

import {Fragment, useEffect, useState} from "react";
import { Dialog, Transition } from "@headlessui/react";
import { useCompletion } from "ai/react";
import { useSession } from "next-auth/react";
import {ChatBlock, responseToChatBlocks} from "@/components/ChatBlock";

// Audit logging for AI-driven actions (decision log / forensic trail)
async function logAIAuditEntry(entry: {
  timestamp: string;
  principal: string;
  modelId: string;
  inputHash: string;
  output: string;
}) {
  try {
    const key = `ai_audit_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    localStorage.setItem(key, JSON.stringify(entry));
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

var last_name = "";

// Approved model registry with pinned versions
const APPROVED_MODEL_REGISTRY: Record<string, { version: string; endpoint: string }> = {
  "gpt-4": { version: "gpt-4-0613", endpoint: "gpt-4" },
  "gpt-3.5-turbo": { version: "gpt-3.5-turbo-0125", endpoint: "gpt-3.5-turbo" },
  "claude-3-sonnet": { version: "claude-3-sonnet-20240229", endpoint: "claude-3-sonnet" },
};

const DEFAULT_MODEL_ENDPOINT = "gpt-3.5-turbo";

function resolveApprovedModel(llmIdentifier: string): string {
  if (!llmIdentifier) return DEFAULT_MODEL_ENDPOINT;
  const entry = APPROVED_MODEL_REGISTRY[llmIdentifier];
  if (!entry) {
    console.warn(
      `Model "${llmIdentifier}" is not in the approved registry. Falling back to default model.`
    );
    return DEFAULT_MODEL_ENDPOINT;
  }
  return entry.endpoint;
}

// Allowlist of permitted LLM API endpoint segments
const ALLOWED_LLM_ENDPOINTS: ReadonlySet<string> = new Set([
  "openai",
  "anthropic",
  "cohere",
  "mistral",
  // Add other permitted endpoint names here
]);

function sanitizeLlmEndpoint(llm: string): string {
  if (typeof llm === "string" && ALLOWED_LLM_ENDPOINTS.has(llm)) {
    return llm;
  }
  return "";
}

// Patterns that represent dynamic code execution primitives that must not appear in LLM output
const DANGEROUS_CODE_PATTERNS: RegExp[] = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bFunction\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"`]/gi,
  /\bsetInterval\s*\(\s*['"`]/gi,
  /\bsetImmediate\s*\(\s*['"`]/gi,
  /\bdocument\.write\s*\(/gi,
  /\binnerHTML\s*=/gi,
  /\bouterHTML\s*=/gi,
  /\bimportScripts\s*\(/gi,
  /\brequire\s*\(/gi,
  /\bprocess\.binding\s*\(/gi,
  /\b__import__\s*\(/gi,
  /\bcompile\s*\(/gi,
  /\bexecfile\s*\(/gi,
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

const APPROVED_LLM_ROUTES: string[] = ["claude", "llama", "mistral"];
const DEFAULT_APPROVED_LLM = "claude";

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
    api: "/api/" + (APPROVED_LLM_ROUTES.includes(example.llm) ? example.llm : DEFAULT_APPROVED_LLM),
    headers: { name: example.name },
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
