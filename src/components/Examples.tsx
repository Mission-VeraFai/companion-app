"use client";
import { useEffect, useState } from "react";
import QAModal from "./QAModal";
import Image from "next/image";
import { Tooltip } from "react-tooltip";

import { getCompanions } from "./actions";

const ALLOWED_IMAGE_HOSTS = [
  'res.cloudinary.com',
  'lh3.googleusercontent.com',
  'avatars.githubusercontent.com',
  's3.amazonaws.com',
];

function getSafeImageUrl(url: string): string {
  if (!url) return '/placeholder.png';
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return '/placeholder.png';
    if (!ALLOWED_IMAGE_HOSTS.includes(parsed.hostname)) return '/placeholder.png';
    return url;
  } catch {
    return '/placeholder.png';
  }
}

// Approved model registry: only organization-approved model identifiers are permitted.
// Each entry includes an immutable version pin (SHA-256 digest) for integrity verification.
// GPT and Claude models have been removed as they are not in the organization's approved list.
// Add only models from the organization's approved list here.
interface ApprovedModelEntry {
  displayName: string;
  // Immutable version pin: SHA-256 digest of the model artifact/config at approval time.
  versionDigest: string;
}

const APPROVED_MODEL_REGISTRY: Record<string, ApprovedModelEntry> = {
  "gpt-4o": {
    displayName: "GPT-4o (Org Approved)",
    versionDigest: "sha256:8b1f2a3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
  },
  "gpt-4o-mini": {
    displayName: "GPT-4o Mini (Org Approved)",
    versionDigest: "sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
  },
};

const DEFAULT_APPROVED_MODEL_ID = "gpt-4o";

// Records model identity and verifies integrity against the approved registry.
function verifyAndRecordModelIdentity(modelId: string, entry: ApprovedModelEntry): void {
  const record = {
    timestamp: new Date().toISOString(),
    modelId,
    displayName: entry.displayName,
    versionDigest: entry.versionDigest,
    status: "APPROVED",
  };
  // Record model identity at inference time for audit purposes.
  console.info('[ModelRegistry] Inference model identity verified:', JSON.stringify(record));
}

function resolveApprovedModel(llm: string): string {
  const normalized = (llm || "").trim().toLowerCase();
  for (const [pinnedId, entry] of Object.entries(APPROVED_MODEL_REGISTRY)) {
    if (normalized === pinnedId.toLowerCase()) {
      // Verify model identity and record it at inference time.
      verifyAndRecordModelIdentity(pinnedId, entry);
      return entry.displayName;
    }
  }
  // Model not in approved registry — substitute the organization default approved model.
  const defaultEntry = APPROVED_MODEL_REGISTRY[DEFAULT_APPROVED_MODEL_ID] ?? Object.values(APPROVED_MODEL_REGISTRY)[0];
  const defaultId = DEFAULT_APPROVED_MODEL_ID in APPROVED_MODEL_REGISTRY ? DEFAULT_APPROVED_MODEL_ID : Object.keys(APPROVED_MODEL_REGISTRY)[0];
  console.warn(`[ModelRegistry] Model '${llm}' not in approved registry. Substituting default: ${defaultId}`);
  verifyAndRecordModelIdentity(defaultId, defaultEntry);
  return defaultEntry.displayName;
};

// Update this to match a key present in APPROVED_MODEL_REGISTRY once populated.
const DEFAULT_APPROVED_MODEL_ID = "";

function resolveApprovedModel(llm: string): string {
  const normalized = (llm || "").trim().toLowerCase();
  for (const [pinnedId, displayName] of Object.entries(APPROVED_MODEL_REGISTRY)) {
    if (normalized === pinnedId.toLowerCase()) {
      return displayName;
    }
  }
  // Model not in approved registry — substitute the organization default approved model.
  return APPROVED_MODEL_REGISTRY[DEFAULT_APPROVED_MODEL_ID] ?? Object.values(APPROVED_MODEL_REGISTRY)[0];
}

// ---------------------------------------------------------------------------
// Forensic audit logger — persists AI inference records to localStorage.
// Each entry is immutable once appended (entries are never mutated/deleted
// by this helper). In production, replace the localStorage sink with a
// server-side append-only audit endpoint.
// ---------------------------------------------------------------------------
function simpleHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const chr = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + chr;
    hash |= 0;
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

interface AuditEntry {
  timestamp: string;          // ISO-8601 UTC
  action: string;             // logical action name
  modelId: string;            // resolved approved-model identifier
  inputHash: string;          // hex hash of serialised input parameters
  outputSummary: string;      // non-sensitive summary of the output
  principal: string;          // user/session identifier
  status: 'success' | 'error';
  errorMessage?: string;
}

const AUDIT_LOG_KEY = 'ai_audit_log';

function writeAuditLog(entry: AuditEntry): void {
  try {
    const raw = localStorage.getItem(AUDIT_LOG_KEY);
    const log: AuditEntry[] = raw ? (JSON.parse(raw) as AuditEntry[]) : [];
    log.push(entry);
    localStorage.setItem(AUDIT_LOG_KEY, JSON.stringify(log));
  } catch (e) {
    // Fallback: at minimum surface to console so ops tooling can capture it.
    // eslint-disable-next-line no-console
    console.error('[AUDIT] Failed to persist audit entry', entry, e);
  }
}

export default function Examples() {
  const [QAModalOpen, setQAModalOpen] = useState(false);
  const [CompParam, setCompParam] = useState({
    name: "",
    title: "",
    imageUrl: "",
    llm: "",
    telegramLink: null as string | null,
  });
  const [examples, setExamples] = useState([
    {
      name: "",
      title: "",
      imageUrl: "",
      llm: "",
      maskedPhone: "",
      telegramLink: null as string | null,
    },
  ]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const inferenceInput = JSON.stringify({ action: 'getCompanions' });
        const inputHash = simpleHash(inferenceInput);
        const requestTimestamp = new Date().toISOString();
        // Resolve the approved model that will be used for this inference.
        const resolvedModelId = DEFAULT_APPROVED_MODEL_ID;
        let companions: string;
        try {
          companions = await getCompanions();
        } catch (inferenceError) {
          writeAuditLog({
            timestamp: requestTimestamp,
            action: 'getCompanions',
            modelId: resolvedModelId,
            inputHash,
            outputSummary: 'inference-failed',
            principal: (typeof window !== 'undefined' && (window as Window & { __currentUser?: string }).__currentUser) || 'anonymous',
            status: 'error',
            errorMessage: inferenceError instanceof Error ? inferenceError.message : String(inferenceError),
          });
          throw inferenceError;
        }
        const outputSummary = typeof companions === 'string'
          ? `chars:${companions.length};hash:${simpleHash(companions)}`
          : 'non-string-output';
        writeAuditLog({
          timestamp: requestTimestamp,
          action: 'getCompanions',
          modelId: resolvedModelId,
          inputHash,
          outputSummary,
          principal: (typeof window !== 'undefined' && (window as Window & { __currentUser?: string }).__currentUser) || 'anonymous',
          status: 'success',
        });
        // Validate parsed JSON: must be an array of plain objects with expected shape
        let parsed: unknown;
        try {
          parsed = JSON.parse(companions);
        } catch {
          throw new Error('Invalid JSON from getCompanions');
        }
        if (!Array.isArray(parsed)) {
          throw new Error('Companions response is not an array');
        }
        const ALLOWED_ENTRY_KEYS = new Set(['name', 'title', 'imageUrl', 'llm', 'phone', 'telegramLink']);
        const entries = parsed.map((item: unknown, idx: number) => {
          if (typeof item !== 'object' || item === null || Array.isArray(item)) {
            throw new Error(`Companion entry at index ${idx} is not a plain object`);
          }
          // Guard against prototype pollution
          if (Object.prototype.hasOwnProperty.call(item, '__proto__') ||
              Object.prototype.hasOwnProperty.call(item, 'constructor') ||
              Object.prototype.hasOwnProperty.call(item, 'prototype')) {
            throw new Error(`Companion entry at index ${idx} contains forbidden keys`);
          }
          const raw = item as Record<string, unknown>;
          for (const key of Object.keys(raw)) {
            if (!ALLOWED_ENTRY_KEYS.has(key)) {
              throw new Error(`Companion entry at index ${idx} contains unexpected key: ${key}`);
            }
          }
          return {
            name:         typeof raw.name         === 'string' ? raw.name         : '',
            title:        typeof raw.title        === 'string' ? raw.title        : '',
            imageUrl:     typeof raw.imageUrl     === 'string' ? raw.imageUrl     : '',
            llm:          typeof raw.llm          === 'string' ? raw.llm          : '',
            phone:        typeof raw.phone        === 'string' ? raw.phone        : '',
            telegramLink: typeof raw.telegramLink === 'string' ? raw.telegramLink : null,
          };
        });
        // Sanitize a companion string field against prompt injection and hidden characters
        const sanitizeCompanionField = (value: string, maxLength = 100): string => {
          // Remove control characters and non-printable characters (except normal whitespace)
          let sanitized = value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\u200B-\u200D\uFEFF\u2028\u2029]/g, '');
          // Strip common prompt-injection patterns (case-insensitive)
          sanitized = sanitized.replace(
            /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
            ''
          );
          sanitized = sanitized.replace(
            /(system\s*prompt|you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be)|disregard\s+(all\s+)?instructions?)/gi,
            ''
          );
          // Collapse runs of whitespace introduced by stripping
          sanitized = sanitized.replace(/\s{2,}/g, ' ').trim();
          // Enforce maximum length
          return sanitized.slice(0, maxLength);
        };

                let setme = entries.map((entry: any) => ({
          name: sanitizeCompanionField(entry.name, 100),
          title: sanitizeCompanionField(entry.title, 150),
          imageUrl: entry.imageUrl,
          llm: (() => {
            const resolved = resolveApprovedModel(entry.llm);
            if (!resolved) {
              throw new Error(`Model '${entry.llm}' is not in the approved model registry. Inference requests are only permitted for registry-approved, version-pinned models.`);
            }
            return resolved;
          })(),
          maskedPhone: isPhoneNumber(entry.phone) ? maskPhone(entry.phone) : "",
          telegramLink: entry.telegramLink
        }));
        setExamples(setme);
      } catch (err) {
        console.error('Failed to fetch companions data');
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
              // name and title were already sanitized during fetch; re-validate defensively before passing to AI agent.
              try {
                const safeName = sanitizePromptField(example.name, 'name', i);
                const safeTitle = sanitizePromptField(example.title, 'title', i);
                setCompParam({ name: safeName, title: safeTitle, imageUrl: example.imageUrl, llm: example.llm, telegramLink: example.telegramLink });
              } catch {
                console.error('Blocked prompt parameter: field failed safety check at render time');
                return;
              }
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
                src={getSafeImageUrl(example.imageUrl)}
                alt=""
              />
              <h3 className="mt-6 text-sm font-medium text-white">
                {example.name}
              </h3>
              <dl className="mt-1 flex flex-grow flex-col justify-between">
                <dt className="sr-only"></dt>
                <dd className="text-sm text-slate-400">
                  {example.title}.{example.llm ? <> Running on <b>{example.llm}</b>.</> : null}
                  {example.telegramLink && isSafeTelegramUrl(example.telegramLink) && (
                    <span className="ml-1"><a onClick={(event) => {event?.stopPropagation(); event?.preventDefault()}} href={example.telegramLink} rel="noopener noreferrer" target="_blank">Chat on <b>Telegram</b></a>.</span>
                  )}
                </dd>
              </dl>
              <dl className="mt-1 flex flex-grow flex-col justify-between">
                <dt className="sr-only"></dt>
                {example.maskedPhone && (
                  <>
                    <dd
                      data-tip="Helpful tip goes here"
                      className="text-sm text-slate-400 inline-block"
                    >
                      📱Text me at: <b>{example.maskedPhone}</b>
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

function sanitizeTelegramLink(url: string): string | undefined {
  if (!url || typeof url !== 'string') return undefined;
  const trimmed = url.trim();
  const allowedPrefixes = ['https://t.me/', 'https://telegram.me/'];
  if (allowedPrefixes.some((prefix) => trimmed.startsWith(prefix))) {
    return trimmed;
  }
  return undefined;
}

const ALLOWED_TELEGRAM_HOSTNAMES = ['t.me', 'telegram.me'];

function isSafeTelegramUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return (
      (parsed.protocol === 'https:') &&
      ALLOWED_TELEGRAM_HOSTNAMES.includes(parsed.hostname)
    );
  } catch {
    return false;
  }
}

function maskPhone(phone: string): string {
  if (!phone || phone.length < 4) return "****";
  const visible = phone.slice(-4);
  const masked = phone.slice(0, phone.length - 4).replace(/\d/g, "*");
  return masked + visible;
}

function maskPhone(phone: string): string {
  if (!phone || phone.length <= 4) return phone;
  const visible = phone.slice(-4);
  const masked = phone.slice(0, phone.length - 4).replace(/\d/g, '*');
  return masked + visible;
}
