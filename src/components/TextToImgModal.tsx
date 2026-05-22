import dotenv from "dotenv";

dotenv.config({ path: `.env.local` });

import { Fragment, useState } from "react";
import { useSession } from "next-auth/react";
import { Dialog, Transition } from "@headlessui/react";
import Image from "next/image";

export default function TextToImgModal({
  open,
  setOpen,
}: {
  open: boolean;
  setOpen: any;
}) {
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
  const sanitizePrompt = (input: string): string => {
    // Trim whitespace and enforce max length
    let sanitized = input.trim().slice(0, 500);
    // Remove control characters and null bytes
    sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, "");
    // Remove characters that could be used for prompt injection
    sanitized = sanitized.replace(/[<>{}\[\]`]/g, "");
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

    const prompt: string = e.target.value;
    const timestamp = new Date().toISOString();
    const modelId = "stability-ai/stable-diffusion";
    const principal =
      (typeof window !== "undefined" &&
        (sessionStorage.getItem("userId") ||
          localStorage.getItem("userId"))) ||
      "anonymous";
    const inputHash = await computeInputHash(prompt);

    const response = await fetch("/api/txt2img", {
      method: "POST",
      body: JSON.stringify({
        prompt,
      }),
      headers: {
        "Content-Type": "application/json",
      },
    });
    const data = await response.json();
    const outputUrl: string = data[0];
    setImgSrc(outputUrl);

    // Audit log: record all forensic fields to persistent store
    try {
      await fetch("/api/audit-log", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          timestamp,
          principal,
          action: "txt2img",
          modelId,
          inputHash,
          prompt,
          output: outputUrl,
        }),
      });
    } catch (auditErr) {
      console.error("Audit logging failed:", auditErr);
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
