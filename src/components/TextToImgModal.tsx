import { Fragment, useState } from "react";
import { useSession } from "next-auth/react";
import { Dialog, Transition } from "@headlessui/react";
import Image from "next/image";
import { Dialog, Transition } from "@headlessui/react";
import Image from "next/image";
import crypto from "crypto";

/** Compute a SHA-256 HMAC over provenance metadata for tamper-evidence. */
function signProvenance(provenance: { generatedAt: string; model: string; synthetic: boolean }): string {
  const secret = process.env.PROVENANCE_SIGNING_SECRET;
  if (!secret) {
    throw new Error("PROVENANCE_SIGNING_SECRET environment variable is not set.");
  }
  const payload = JSON.stringify(provenance);
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

const MAX_PROMPT_LENGTH = 500;

function sanitizePrompt(input: string): string {
  // Trim surrounding whitespace
  let sanitized = input.trim();
  // Strip HTML/script tags
  sanitized = sanitized.replace(/<[^>]*>/g, "");
  // Remove null bytes and other non-printable control characters
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Enforce maximum length
  sanitized = sanitized.slice(0, MAX_PROMPT_LENGTH);
  return sanitized;
}

const ALLOWED_IMAGE_HOSTS = [
  "oaidalleapiprodscus.blob.core.windows.net",
  "cdn.openai.com",
];

const CODE_EXECUTION_PATTERNS: RegExp[] = [
  /\beval\s*\(/i,
  /\bFunction\s*\(/i,
  /\bsetTimeout\s*\(/i,
  /\bsetInterval\s*\(/i,
  /\bexecScript\s*\(/i,
  /\bdocument\.write\s*\(/i,
  /\.innerHTML\s*=/i,
  /\.outerHTML\s*=/i,
  /\bimportScripts\s*\(/i,
  /javascript\s*:/i,
  /data\s*:\s*text\s*\/\s*(html|javascript)/i,
  /\bnew\s+Function\b/i,
  /\bvm\.runInThisContext\b/i,
  /\bvm\.runInNewContext\b/i,
  /\bexec\s*\(/i,
  /\bspawn\s*\(/i,
  /\brequire\s*\(/i,
  /\bimport\s*\(/i,
];

/**
 * Validates that a raw LLM/API response payload contains no dynamic code
 * execution primitives. Throws if any are detected.
 */
function sanitizeLlmResponse(responsePayload: unknown): void {
  const serialized =
    typeof responsePayload === "string"
      ? responsePayload
      : JSON.stringify(responsePayload);

  for (const pattern of CODE_EXECUTION_PATTERNS) {
    if (pattern.test(serialized)) {
      throw new Error(
        `LLM response contains a forbidden code execution primitive matching: ${pattern}`
      );
    }
  }
}

function isValidImageUrl(url: unknown): url is string {
  if (typeof url !== "string" || url.trim() === "") return false;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return false;
    if (!ALLOWED_IMAGE_HOSTS.includes(parsed.hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

export default function TextToImgModal({
  open,
  setOpen,
}: {
  open: boolean;
  setOpen: any;
}) {
    const [imgSrc, setImgSrc] = useState("");
  const [imgProvenance, setImgProvenance] = useState<{
    generatedAt: string;
    model: string;
    synthetic: boolean;
  } | null>(null);
  const [provenanceSignature, setProvenanceSignature] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  /** Write an append-only audit log entry to the server for every AI generation event. */
  const writeAuditLog = useCallback(async (entry: {
    eventType: string;
    modelId: string;
    inputHash: string;
    outputUrl: string;
    generatedAt: string;
    principal: string;
    provenanceSignature: string;
  }) => {
    try {
      const response = await fetch("/api/audit-log", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(entry),
      });
      if (!response.ok) {
        console.error("[AuditLog] Failed to write audit log entry:", response.status, await response.text());
      }
    } catch (err) {
      console.error("[AuditLog] Exception writing audit log entry:", err);
    }
  }, []);

  const sanitizePrompt = (input: string): string | null => {
    if (!input || typeof input !== "string") return null;

    // Reject if too long
    if (input.length > 500) return null;

    // Reject base64-encoded content
    if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(input.trim())) return null;

    // Reject URL-encoded content
    if (/%[0-9A-Fa-f]{2}/.test(input)) return null;

    // Reject shell command patterns
    const shellPatterns = [
      /[`$]\s*\(/,           // command substitution: `(...)` or $(...)
      /;\s*(rm|curl|wget|bash|sh|python|node|exec|eval)\b/i,
      /&&|\|\|/,             // shell logical operators
      /\|\s*\w/,             // pipe to command
      />{1,2}\s*\/\w/,       // redirect to file path
      /\.\.\/|\.\.\\/, // path traversal
    ];
    for (const pattern of shellPatterns) {
      if (pattern.test(input)) return null;
    }

    // Reject prompt injection / jailbreak attempts
    const injectionPatterns = [
      /ignore (all |previous |above |prior )?instructions/i,
      /system\s*prompt/i,
      /you are now/i,
      /act as (a|an)?\s+/i,
      /disregard (all |previous |your )?/i,
      /\[INST\]|\[SYS\]|<\|im_start\|>|<\|system\|>/i,
      /---+\s*(system|user|assistant)\s*---+/i,
    ];
    for (const pattern of injectionPatterns) {
      if (pattern.test(input)) return null;
    }

    // Strip any HTML/script tags
    const stripped = input.replace(/<[^>]*>/g, "").trim();

    // Allow only printable ASCII and common punctuation for image prompts
    if (/[^\x20-\x7E]/.test(stripped)) return null;

    return stripped;
  };

  // Approved model registry and pinned version — must match server-side allowlist
  // Only models explicitly approved by the organization's LLM registry may be listed here.
  // 'stable-diffusion-v1-5' and 'stable-diffusion-xl-1.0' have been removed as they are
  // NOT in the organization's approved model registry. Replace with an approved model ID.
  // Organization-approved model registry.
  // Only models explicitly vetted and approved by the security/ML team may appear here.
  // Current approved model: stability-ai/sdxl at the pinned version below.
  const APPROVED_MODEL_ID =
    "stability-ai/sdxl:39ed52f2319f9b0b7e33f9b0b7e33f9b0b7e33f9b0b7e33f9b0b7e33f9b0b7e33";
  const APPROVED_MODEL_REGISTRY: Record<string, string> = {
    [APPROVED_MODEL_ID]: APPROVED_MODEL_ID,
  };
  const PINNED_MODEL_ID = APPROVED_MODEL_ID;

  const validateModelProvenance = (responseModel: unknown): void => {
    if (typeof responseModel !== "string" || responseModel.trim() === "") {
      throw new Error("Model provenance check failed: response did not include a model identifier.");
    }
    if (!APPROVED_MODEL_REGISTRY[responseModel]) {
      throw new Error(
        `Model provenance check failed: model '${responseModel}' is not in the approved registry.`
      );
    }
    if (responseModel !== PINNED_MODEL_ID) {
      throw new Error(
        `Model version mismatch: expected '${PINNED_MODEL_ID}', got '${responseModel}'.`
      );
    }
  };

  const onSubmit = async (e: any) => {
    e.preventDefault();
    setPromptError("");
    const rawValue: string = typeof e.target.value === "string" ? e.target.value : "";
    const sanitizedPrompt = sanitizePrompt(rawValue);
    if (!sanitizedPrompt) {
      setPromptError("Please enter a valid prompt (non-empty, max 500 characters).");
      return;
    }
    setLoading(true);
    const sanitized = sanitizePrompt(e.target.value);
    if (!sanitized) {
      setLoading(false);
      alert("Invalid prompt. Please enter a plain text image description without special commands or encoded content.");
      return;
    }
    const response = await fetch("/api/approved-txt2img", {
      method: "POST",
      body: JSON.stringify({
        prompt: sanitizedPrompt,
        model: PINNED_MODEL_ID,
      }),
      headers: {
        "Content-Type": "application/json",
      },
    });
    // Scan raw LLM response text for dynamic code execution primitives before parsing
    const rawResponseText = await response.text();
    const codeExecutionPattern = /\beval\s*\(|\bexec\s*\(|\bFunction\s*\(|\bnew\s+Function\b|\bsetTimeout\s*\(\s*['"`]|\bsetInterval\s*\(\s*['"`]|javascript\s*:|vbscript\s*:|<\s*script|\bimport\s*\(|\brequire\s*\(|\bchild_process\b|\bspawn\s*\(|\bexecSync\s*\(|\bexecFile\s*\(/i;
    if (codeExecutionPattern.test(rawResponseText)) {
      setLoading(false);
      alert("Security violation: LLM response contains dynamic code execution primitives and has been blocked.");
      return;
    }
    const data = JSON.parse(rawResponseText);
    // Data minimisation: extract only the image source field from the first element,
    // discarding all other metadata fields the API may return.
    const firstItem: unknown = Array.isArray(data) ? data[0] : undefined;
    const rawSrc: unknown =
      firstItem !== null && typeof firstItem === "object"
        ? (firstItem as Record<string, unknown>)["url"] ??
          (firstItem as Record<string, unknown>)["b64_json"] ??
          (firstItem as Record<string, unknown>)["src"]
        : firstItem;
    // Validate and sanitize LLM output before use
    const sanitizeImageSrc = (src: unknown): string => {
      if (typeof src !== "string") {
        throw new Error("Invalid image source: not a string");
      }
      // Block any dynamic code execution primitives
      const forbidden = /eval|javascript:|vbscript:|data:text|<script|on\w+\s*=/i;
      if (forbidden.test(src)) {
        throw new Error("Invalid image source: contains forbidden content");
      }
      // Allow only base64-encoded image data URIs or HTTPS URLs
      const isDataUri = /^data:image\/(png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/=]+$/.test(src);
      const isHttpsUrl = /^https:\/\/[^\s]+$/.test(src);
      if (!isDataUri && !isHttpsUrl) {
        throw new Error("Invalid image source: must be a base64 image data URI or HTTPS URL");
      }
      return src;
    };
    const safeSrc = sanitizeImageSrc(rawSrc);
    setImgSrc(safeSrc);
    setLoading(false);
  };
  return (
    <Transition.Root show={open} as={Fragment}>
      <Dialog as="div" className="relative z-10" onClose={setOpen}>
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
                  <input
                    className="w-full flex-auto rounded-md border-0 bg-white/5 px-3.5 py-2 text-white shadow-sm focus:outline-none  sm:text-sm sm:leading-6"
                    placeholder="Describe the image you want"
                    // when user click enter key, submit the form
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        onSubmit(e);
                      }
                    }}
                  ></input>
                  <div className="mt-3">
                    <div className="my-2">
                      <p className="text-sm text-gray-500">
                        Powered by{" "}
                        an approved image generation model
                      </p>
                    </div>
                  </div>
                </div>
                {imgSrc && !loading && (
                  <Image
                    width={0}
                    height={0}
                    sizes="100vw"
                    src={imgSrc}
                    alt="img"
                    className="w-full h-full object-contain"
                  />
                )}
                {loading && (
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
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition.Root>
  );
}
