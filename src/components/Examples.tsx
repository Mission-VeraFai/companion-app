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
// GPT and Claude models have been removed as they are not in the organization's approved list.
// Add only models from the organization's approved list here.
const APPROVED_MODEL_REGISTRY: Record<string, string> = {
  // e.g. "org-approved-model-id": "Org Approved Model Display Name",
};

function resolveApprovedModel(llm: string): string | null {
  const normalized = (llm || "").trim().toLowerCase();
  for (const [pinnedId, displayName] of Object.entries(APPROVED_MODEL_REGISTRY)) {
    if (normalized === pinnedId.toLowerCase()) {
      return displayName;
    }
  }
  return null;
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
        const companions = await getCompanions();
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
                let setme = entries.map((entry: any) => ({
          name: entry.name,
          title: entry.title,
          imageUrl: entry.imageUrl,
          llm: resolveApprovedModel(entry.llm) ?? "[unregistered model]",
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
              setCompParam({ name: example.name, title: example.title, imageUrl: example.imageUrl, llm: example.llm, telegramLink: example.telegramLink });
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
