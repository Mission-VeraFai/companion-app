"use client";
import { useEffect, useState } from "react";
import QAModal from "./QAModal";
import Image from "next/image";
import { Tooltip } from "react-tooltip";

import { getCompanions } from "./actions";

// Allowlist of trusted image hosting domains.
const ALLOWED_IMAGE_DOMAINS = [
  'localhost',
  'your-app-domain.com',
  'cdn.your-app-domain.com',
  'lh3.googleusercontent.com',
  'avatars.githubusercontent.com',
];

function isSafeImageUrl(url: string): boolean {
  if (!url || url.trim() === '') return false;
  // Allow relative paths (e.g. /images/avatar.png)
  if (url.startsWith('/')) return true;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
    return ALLOWED_IMAGE_DOMAINS.includes(parsed.hostname);
  } catch {
    return false;
  }
}

export default function Examples() {
  const [QAModalOpen, setQAModalOpen] = useState(false);
  const [CompParam, setCompParam] = useState({
    name: "",
    title: "",
    imageUrl: "",
  });
  const [examples, setExamples] = useState([
    {
      name: "",
      title: "",
      imageUrl: "",
      llm: "",
      telegramLink: null
    },
  ]);

    const FALLBACK_MODEL = "Approved Model (version-pinned)";

  // Approved model registry: maps IMMUTABLE pinned model IDs to display names.
  // Only models explicitly listed here are permitted.
  const APPROVED_MODEL_REGISTRY: Record<string, string> = {};

  // Returns the pinned display name for an approved model, or FALLBACK_MODEL if
  // the model is not in the registry. Unknown/unapproved models are rejected.
  const getApprovedModel = (llm: string): string => {
    if (!llm || typeof llm !== "string") return FALLBACK_MODEL;
    const key = llm.trim().toLowerCase();
    return APPROVED_MODEL_REGISTRY[key] ?? FALLBACK_MODEL;
  };

  const FALLBACK_MODEL = "Approved Model (version-pinned)";

  const getApprovedModel = (llm: string): string => {
    if (!llm || typeof llm !== "string") return FALLBACK_MODEL;
    const key = llm.trim().toLowerCase();
    return APPROVED_MODEL_REGISTRY[key] ?? FALLBACK_MODEL;
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        const companions = await getCompanions();
        // Sanitize text fields before they reach the AI prompt.
        const PROMPT_INJECTION_PATTERNS: RegExp[] = [
          // Hidden/system prompt injection attempts
          /ignore\s+(previous|above|prior|all)\s+(instructions?|prompts?|context)/i,
          /system\s*prompt/i,
          /you\s+are\s+(now|a|an)\s+/i,
          /act\s+as\s+(a|an)?\s+/i,
          /pretend\s+(you\s+are|to\s+be)/i,
          /jailbreak/i,
          /DAN\b/,
          // Base64 encoded content (long base64 strings are suspicious)
          /[A-Za-z0-9+/]{40,}={0,2}/,
          // Shell commands
          /[`$]\s*\(/,
          /;\s*(rm|ls|cat|curl|wget|bash|sh|python|node|exec)\b/i,
          /\|\s*(bash|sh|python|node|curl|wget)/i,
          // Binary / non-printable characters
          // eslint-disable-next-line no-control-regex
          /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/,
          // Leetspeak patterns for common injection keywords
          /1gn[o0]r[e3]\s+/i,
          /[e3]x[e3]c[u0]t[e3]/i,
          // Excessive special characters (potential obfuscation)
          /([^\w\s,.!?'-]){5,}/,
        ];

        function sanitizePromptField(value: unknown, fieldName: string): string {
          if (typeof value !== 'string') return '';
          const trimmed = value.trim();
          // Reject empty or excessively long values
          if (trimmed.length === 0) return '';
          if (trimmed.length > 200) {
            console.warn(`[Security] Field '${fieldName}' exceeds max length, rejecting.`);
            return '';
          }
          for (const pattern of PROMPT_INJECTION_PATTERNS) {
            if (pattern.test(trimmed)) {
              console.warn(`[Security] Field '${fieldName}' failed injection check (pattern: ${pattern}), rejecting value.`);
              return '';
            }
          }
          // Strip any remaining control characters
          // eslint-disable-next-line no-control-regex
          return trimmed.replace(/[\x00-\x1F\x7F]/g, '');
        }

        const rawEntries: Array<Record<string, unknown>> = JSON.parse(companions);
        const sanitiseTelegramLink = (value: unknown): string | null => {
          if (typeof value !== "string") return null;
          const trimmed = value.trim();
          return trimmed.startsWith("https://t.me/") ? trimmed : null;
        };
        let setme = rawEntries.map((entry: Record<string, unknown>) => ({
          name: typeof entry.name === "string" ? entry.name : "",
          title: typeof entry.title === "string" ? entry.title : "",
          imageUrl: typeof entry.imageUrl === "string" ? entry.imageUrl : "",
          llm: getApprovedModel(typeof entry.llm === "string" ? entry.llm : ""),
          telegramLink: sanitiseTelegramLink(entry.telegramLink),
        }));
        setExamples(setme);
      } catch (err) {
        console.log(err);
      }
    };

    fetchData();
  }, []);

  return (
    <div id="ExampleDiv">
      <QAModal
        open={QAModalOpen}
        setOpen={setQAModalOpen}
        example={CompParam}
      />
      <ul
        role="list"
        className="mt-14 m-auto max-w-3xl grid grid-cols-1 gap-6 lg:grid-cols-2"
      >
        {examples.map((example, i) => (
          <li
            key={example.name}
            onClick={() => {
              setCompParam(example);
              setQAModalOpen(true);
            }}
            className="col-span-2 flex flex-col rounded-lg bg-slate-800  text-center shadow relative ring-1 ring-white/10 cursor-pointer hover:ring-sky-300/70 transition"
          >
            <div className="absolute -bottom-px left-10 right-10 h-px bg-gradient-to-r from-sky-300/0 via-sky-300/70 to-sky-300/0"></div>
            <div className="flex flex-1 flex-col p-8">
              <Image
                width={0}
                height={0}
                sizes="100vw"
                className="mx-auto h-32 w-32 flex-shrink-0 rounded-full"
                src={isSafeImageUrl(example.imageUrl) ? example.imageUrl : '/placeholder-avatar.png'}
                alt=""
              />
              <span
                aria-label="AI-Generated Content"
                title="This companion and its content are AI-generated"
                className="inline-block mt-4 mb-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-sky-700/60 text-sky-200 ring-1 ring-sky-400/40 tracking-wide"
              >
                🤖 AI-Generated
              </span>
              <h3 className="mt-2 text-sm font-medium text-white">
                {example.name}
              </h3>
              <dl className="mt-1 flex flex-grow flex-col justify-between">
                <dt className="sr-only">AI-Generated Companion</dt>
                <dd className="text-sm text-slate-400">
                  {example.title}.{getApprovedLlmLabel(example.llm) ? <> Running on <b>{getApprovedLlmLabel(example.llm)}</b>.</> : null}
                  {example.telegramLink && isSafeTelegramUrl(example.telegramLink) && (
                    <span className="ml-1"><a onClick={(event) => {event?.stopPropagation(); event?.preventDefault();}} href={example.telegramLink} rel="noopener noreferrer" target="_blank">Chat on <b>Telegram</b></a>.</span>
                  )}
                </dd>
              </dl>
              <dl className="mt-1 flex flex-grow flex-col justify-between">
                <dt className="sr-only"></dt>
                {isPhoneNumber(example.phone) && (
                  <>
                    <dd
                      data-tip="Helpful tip goes here"
                      className="text-sm text-slate-400 inline-block"
                    >
                      📱Text me at: <b>{maskPhone(example.phone)}</b>
                      &nbsp;
                      <svg
                        data-tooltip-id="help-tooltip"
                        data-tooltip-content="Unlock this freature by clicking on 
                        your profile picture on the top right 
                        -> Manage Account -> Add a phone number."
                        data-tooltip-target="tooltip-default"
                        data-tip="Helpful tip goes here"
                        className="w-[15px] h-[15px] text-slate-400 inline-block cursor-pointer"
                        xmlns="http://www.w3.org/2000/svg"
                        fill="currentColor"
                        viewBox="0 0 20 20"
                      >
                        <path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5ZM9.5 4a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3ZM12 15H8a1 1 0 0 1 0-2h1v-3H8a1 1 0 0 1 0-2h2a1 1 0 0 1 1 1v4h1a1 1 0 0 1 0 2Z" />
                      </svg>
                      <Tooltip id="help-tooltip" />
                    </dd>
                  </>
                )}
              </dl>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function isPhoneNumber(input: string): boolean {
  const phoneNumberRegex = /^\+\d{1,11}$/;
  return phoneNumberRegex.test(input);
}

function isSafeUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

const ALLOWED_TELEGRAM_HOSTNAMES = ['t.me', 'telegram.me'];

function isSafeTelegramUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return (
      (parsed.protocol === 'https:' || parsed.protocol === 'http:') &&
      ALLOWED_TELEGRAM_HOSTNAMES.includes(parsed.hostname)
    );
  } catch {
    return false;
  }
}

/**
 * Masks a phone number for display, retaining only the leading '+' and
 * country-code digit(s) plus the last 2 digits. All middle digits are
 * replaced with '*' to minimise PII exposure in the UI.
 * Example: +12025550173 → +1*********73
 */
function maskPhone(phone: string): string {
  if (!isPhoneNumber(phone)) return '***';
  // Keep the '+' and first digit (country code), mask the middle, show last 2
  const prefix = phone.slice(0, 2);       // e.g. "+1"
  const suffix = phone.slice(-2);          // e.g. "73"
  const maskedLength = phone.length - prefix.length - suffix.length;
  const masked = '*'.repeat(Math.max(maskedLength, 0));
  return `${prefix}${masked}${suffix}`;
}

function maskPhoneNumber(phone: string): string {
  if (!phone || phone.length <= 4) return '****';
  const lastFour = phone.slice(-4);
  const masked = phone.slice(0, -4).replace(/\d/g, '*');
  return masked + lastFour;
}

function maskPhone(phone: string): string {
  // Keep the '+' and up to 3 leading digits, mask the middle, show last 2 digits
  if (phone.length <= 4) return '***';
  const prefix = phone.slice(0, 3);
  const suffix = phone.slice(-2);
  const masked = '*'.repeat(Math.max(phone.length - 5, 1));
  return `${prefix}${masked}${suffix}`;
}
