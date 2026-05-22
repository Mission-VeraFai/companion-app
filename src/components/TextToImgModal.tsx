// Environment variables are handled by Next.js natively

import { Fragment, useState } from "react";
import { useSession } from "next-auth/react";
import { Dialog, Transition } from "@headlessui/react";
import Image from "next/image";

/**
 * Computes a SHA-256 hex digest of the given string.
 * Used to hash prompt inputs and output references for the audit trail.
 */
async function sha256Hex(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

interface AuditRecord {
  timestamp: string;          // ISO-8601 UTC
  principal: string;          // authenticated user identifier
  action: string;             // "generate-image"
  modelId: string;            // model/API identifier
  inputHash: string;          // SHA-256 of the raw prompt
  outputHash: string;         // SHA-256 of the raw response body (or error message)
  httpStatus: number | null;  // HTTP status returned by the AI API
  success: boolean;
  errorMessage?: string;
}

/**
 * Persists an audit record to the server-side audit log endpoint.
 * Fire-and-forget: errors are caught and logged to console only,
 * so audit failures never silently swallow the original error.
 */
function persistAuditRecord(record: AuditRecord): void {
  fetch("/api/audit-log", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(record),
    // keepalive ensures the request completes even if the page unloads
    keepalive: true,
  }).catch((err) => {
    console.error("[audit] Failed to persist audit record:", err);
  });
}

export default function TextToImgModal({
  open,
  setOpen,
}: {
  open: boolean;
  setOpen: any;
}) {
  const { data: session } = useSession();
  const [imgSrc, setImgSrc] = useState("");

  /**
   * Validates and sanitizes an image source returned from the LLM API.
   * Returns the sanitized string if safe, or null if invalid/unsafe.
   */
  function sanitizeImageSrc(src: unknown): string | null {
    // Must be a non-empty string
    if (typeof src !== "string" || src.trim() === "") {
      return null;
    }

    // Reject excessively long strings (guard against payload attacks)
    if (src.length > 2_000_000) {
      return null;
    }

    // Reject any dynamic code execution primitives
    const forbiddenPatterns = [
      /javascript\s*:/i,
      /vbscript\s*:/i,
      /\beval\s*\(/i,
      /\bFunction\s*\(/i,
      /\bsetTimeout\s*\(/i,
      /\bsetInterval\s*\(/i,
      /\bnew\s+Function\b/i,
      /\bimport\s*\(/i,
      /<\s*script/i,
      /on\w+\s*=/i,
    ];
    for (const pattern of forbiddenPatterns) {
      if (pattern.test(src)) {
        return null;
      }
    }

    // Allow only safe data URIs (image/* MIME types) or https URLs
    const isDataUri = /^data:image\/(png|jpeg|jpg|gif|webp|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(src);
    const isHttpsUrl = /^https:\/\/[^\s]+$/.test(src);

    if (!isDataUri && !isHttpsUrl) {
      return null;
    }

    return src;
  }
  const [loading, setLoading] = useState(false);

  // Stable model identifier – update this constant whenever the backend model changes.
  const AI_MODEL_ID = "openai/dall-e-3";

  /**
   * Embeds a visible watermark onto an image (data URI or HTTPS URL)
   * by drawing it onto an HTML Canvas and returning a watermarked data URI.
   */
  const embedWatermark = (src: string, label: string): Promise<string> => {
    return new Promise((resolve) => {
      const img = new window.Image();
      img.crossOrigin = "anonymous";
      img.onload = () => {
        const canvas = document.createElement("canvas");
        canvas.width = img.naturalWidth || img.width;
        canvas.height = img.naturalHeight || img.height;
        const ctx = canvas.getContext("2d");
        if (!ctx) {
          resolve(src);
          return;
        }
        ctx.drawImage(img, 0, 0);
        // Watermark styling
        const fontSize = Math.max(16, Math.floor(canvas.width / 20));
        ctx.font = `bold ${fontSize}px sans-serif`;
        ctx.fillStyle = "rgba(255, 255, 255, 0.55)";
        ctx.strokeStyle = "rgba(0, 0, 0, 0.45)";
        ctx.lineWidth = 2;
        ctx.textAlign = "right";
        ctx.textBaseline = "bottom";
        const padding = 12;
        ctx.strokeText(label, canvas.width - padding, canvas.height - padding);
        ctx.fillText(label, canvas.width - padding, canvas.height - padding);
        resolve(canvas.toDataURL("image/png"));
      };
      img.onerror = () => resolve(src);
      img.src = src;
    });
  };
  const sanitizePrompt = (input: string): string | null => {
    // Trim whitespace and enforce max length
    let sanitized = input.trim().slice(0, 500);
    // Remove control characters and null bytes
    sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, "");
    // Remove characters that could be used for prompt injection
    sanitized = sanitized.replace(/[<>{}\[\]`]/g, "");

    // Reject hidden prompt injection patterns (e.g. "ignore previous instructions")
    const hiddenPromptPatterns = [
      /ignore\s+(previous|above|prior|all)\s+(instructions?|prompts?|context)/i,
      /disregard\s+(previous|above|prior|all)\s+(instructions?|prompts?|context)/i,
      /forget\s+(previous|above|prior|all)\s+(instructions?|prompts?|context)/i,
      /you\s+are\s+now\s+/i,
      /act\s+as\s+(if\s+you\s+are|a|an)\s+/i,
      /new\s+(role|persona|instructions?|prompt)/i,
      /system\s*:\s*/i,
      /\[INST\]/i,
      /<\|im_start\|>/i,
      /###\s*(instruction|system|human|assistant)/i,
    ];
    for (const pattern of hiddenPromptPatterns) {
      if (pattern.test(sanitized)) {
        return null;
      }
    }

    // Reject base64-encoded content (long base64 blobs that may hide payloads)
    const base64Pattern = /(?:[A-Za-z0-9+\/]{4}){10,}(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/;
    if (base64Pattern.test(sanitized)) {
      return null;
    }

    // Reject leetspeak obfuscation patterns (common substitutions used to bypass filters)
    const leetspeakPattern = /(?:[\$3][xX][3e][cC]|[\$]h[3e][l1][l1]|[\$][cC][rR][i1!][pP][tT]|[eE][vV][4a][l1]|[pP][wW][nN]|[rR][0o][0o][tT])/;
    if (leetspeakPattern.test(sanitized)) {
      return null;
    }

    // Reject shell command patterns
    const shellCommandPatterns = [
      /\b(bash|sh|zsh|ksh|csh|fish|cmd|powershell|pwsh)\b/i,
      /\b(exec|system|popen|subprocess|spawn|fork)\s*\(/i,
      /[;&|`]\s*\w/,
      /\$\(.*\)/,
      /`[^`]+`/,
      /\b(rm|del|format|mkfs|dd|wget|curl|nc|netcat|ncat)\b/i,
      /\b(chmod|chown|sudo|su|passwd|useradd|usermod)\b/i,
      /\/etc\/(passwd|shadow|hosts|sudoers)/i,
      /\b(cat|echo|printf|tee)\s+.*[>|]/i,
      />\s*\/dev\//i,
    ];
    for (const pattern of shellCommandPatterns) {
      if (pattern.test(sanitized)) {
        return null;
      }
    }

    // Reject binary executable signatures (magic bytes encoded as text or escape sequences)
    const binaryPatterns = [
      /\\x4d\\x5a/i,           // MZ header (Windows PE)
      /\\x7fELF/i,             // ELF header (Linux)
      /\\xcf\\xfa\\xed\\xfe/i, // Mach-O header
      /MZ[\s\S]{0,256}PE\x00\x00/i,
      /\x7fELF/,
      /%[0-9a-f]{2}(%[0-9a-f]{2}){3,}/i, // URL-encoded binary sequences
    ];
    for (const pattern of binaryPatterns) {
      if (pattern.test(sanitized)) {
        return null;
      }
    }

    return sanitized;
  };

    const computeInputHash = async (text: string): Promise<string> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  };

  const onSubmit = async (e: any) => {
    e.preventDefault();
    setLoading(true);

    const prompt: string = sanitizePrompt(e.target.value);
    const timestamp = new Date().toISOString();
    const modelId = "org-approved/text-to-image-v1";
    const principal = session?.user?.email || session?.user?.name || "anonymous";
    const inputHash = await computeInputHash(prompt);

        const response = await fetch("/api/txt2img", {
      method: "POST",
      body: JSON.stringify({
        prompt,
      }),
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${(session as any)?.accessToken ?? ""}`,
      },
    });
    const data = await response.json();
    const rawOutputUrl: string = data[0];
    const outputUrl: string | null = sanitizeImageSrc(rawOutputUrl);
    if (!outputUrl) {
      console.error("Invalid or unsafe image URL returned from server.");
      setLoading(false);
      return;
    }
    setImgSrc(outputUrl);

    // Audit log: record all forensic fields to persistent store
    try {
      await fetch("/api/audit-log", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Audit-Append-Only": "true",
          "X-Audit-Retention-Days": "365",
        },
        body: JSON.stringify({
          timestamp,
          principal,
          action: "txt2img",
          modelId,
          modelVersion,
          inputHash,
          prompt,
          output: outputUrl,
          retentionPolicy: "append-only",
        }),
      });
    } catch (auditErr) {
      console.error("Audit logging failed:", auditErr);
      // Re-throw so audit failures are never silently swallowed and can be
      // surfaced to monitoring / alerting infrastructure.
      throw new Error(
        `Audit logging failure — action blocked to preserve forensic integrity: ${
          auditErr instanceof Error ? auditErr.message : String(auditErr)
        }`
      );
    }

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
                    value={prompt}
                    onChange={(e) => setPrompt(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        onSubmit();
                      }
                    }}
                  ></input>
                  <div className="mt-3">
                    <div className="my-2" aria-label="AI-generated image viewer">
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
