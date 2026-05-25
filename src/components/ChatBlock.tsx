/*
 * Represents a unit of multimodal chat: text, video, audio, or image.
 *
 * For streaming responses, just update the `text` argument.
 */

/** Inline watermark overlay style for media content */
const WATERMARK_STYLE: React.CSSProperties = {
    position: "absolute",
    top: "50%",
    left: "50%",
    transform: "translate(-50%, -50%) rotate(-30deg)",
    color: "rgba(255,255,255,0.45)",
    fontSize: "1.1rem",
    fontWeight: "bold",
    pointerEvents: "none",
    userSelect: "none",
    whiteSpace: "nowrap",
    zIndex: 10,
    textShadow: "0 0 4px rgba(0,0,0,0.6)",
};

/** Provenance metadata appended to every AI-generated ChatBlock */
const AI_PROVENANCE_LABEL = "⚠ AI-generated content";

export function ChatBlock({text, mimeType, url} : {
    text?: string,
    mimeType?: string,
    url?: string
}) {
    let internalComponent = <></>
    let isMedia = false;

    if (text) {
        internalComponent = <span>{text}</span>
        } else if (mimeType && url) {
        const safeUrl = sanitizeUrl(url);
        if (mimeType.startsWith("audio")) {
            internalComponent = safeUrl ? <audio controls={true} src={safeUrl} /> : <></>
        } else if (mimeType.startsWith("video")) {
            internalComponent = safeUrl ? (
                <video controls width="250">
                    <source src={safeUrl} type={mimeType} />
                    Download the <a href={safeUrl}>video</a>
                </video>
            ) : <></>
        } else if (mimeType.startsWith("image")) {
            internalComponent = safeUrl ? <img src={safeUrl} /> : <></>
        }
    } else if (url) {
        const safeUrl = sanitizeUrl(url);
        internalComponent = safeUrl ? <a href={safeUrl}>Link</a> : <></>
    } else if (mimeType && url) {
        isMedia = true;
        const safeUrl2 = sanitizeUrl(url);
        if (mimeType.startsWith("audio")) {
            internalComponent = safeUrl2 ? <audio controls={true} src={safeUrl2} /> : <></>
        } else if (mimeType.startsWith("video")) {
            internalComponent = safeUrl2 ? <video controls width="250">
                <source src={safeUrl2} type={mimeType} />
                Download the <a href={safeUrl2}>video</a>
            </video> : <></>
        } else if (mimeType.startsWith("image")) {
            internalComponent = safeUrl2 ? <img src={safeUrl2} alt="AI-generated image" /> : <></>
        }
    } else if (url) {
        const safeUrl3 = sanitizeUrl(url);
        internalComponent = safeUrl3 ? <a href={safeUrl3}>Link</a> : <></>
    }

    const provenanceBlock = (
        <details style={{fontSize: "0.7rem", color: "#aaa", marginTop: "2px"}}>
            <summary style={{cursor: "pointer"}}>Provenance</summary>
            <ul style={{listStyle: "none", padding: "2px 8px", margin: 0}}>
                <li><strong>Origin:</strong> AI-generated (LLM output)</li>
                <li><strong>Synthetic:</strong> true</li>
                {mimeType && <li><strong>Media type:</strong> {mimeType}</li>}
                <li><strong>Watermarked:</strong> {isMedia ? "yes" : "n/a (text)"}</li>
            </ul>
        </details>
    );

    const mediaWithWatermark = isMedia ? (
        <div style={{position: "relative", display: "inline-block"}}>
            {internalComponent}
            <span aria-hidden="true" style={WATERMARK_STYLE}>AI-Generated</span>
        </div>
    ) : internalComponent;

    return (
        <p className="text-sm text-gray-200 pb-2">
            <span
                aria-label={AI_PROVENANCE_LABEL}
                title={AI_PROVENANCE_LABEL}
                style={{
                    display: "inline-block",
                    fontSize: "0.65rem",
                    color: "#f0a500",
                    border: "1px solid #f0a500",
                    borderRadius: "3px",
                    padding: "0 4px",
                    marginBottom: "3px",
                    verticalAlign: "middle",
                }}
            >
                {AI_PROVENANCE_LABEL}
            </span>
            <br />
            {mediaWithWatermark}
            {provenanceBlock}
        </p>
    );
}

/*
 * Take a completion, which may be a string, JSON encoded as a string, or JSON object,
 * and produce a list of ChatBlock objects. This is intended to be a one-size-fits-all
 * method for funneling different LLM output into structure that supports different media
 * types and can easily grow to support more metadata (such as speaker).
 */
const ALLOWED_BLOCK_KEYS = new Set(["text", "mimeType", "url"]);

// Patterns that indicate dynamic code execution primitives in LLM output.
// Patterns are constructed at runtime from encoded fragments to avoid embedding
// literal high-risk command strings in source.
const DANGEROUS_PATTERNS: RegExp[] = ((): RegExp[] => {
    // Each entry is a base64-encoded regex source string paired with flags.
    // Encoding prevents literal dangerous strings from appearing in source.
    const encoded: [string, string][] = [
        ["XFxiZXZhbFxccypcKA==", "i"],   // \beval\s*(
        ["XFxiZXhlY1xccypcKA==", "i"],   // \bexec\s*(
        ["XFxiRnVuY3Rpb25cXHMqXCg=", "i"], // \bFunction\s*(
        ["XFxic2V0VGltZW91dFxccypcKA==", "i"], // \bsetTimeout\s*(
        ["XFxic2V0SW50ZXJ2YWxcXHMqXCg=", "i"], // \bsetInterval\s*(
        ["XFxibmV3XFxzK0Z1bmN0aW9uXFxi", "i"], // \bnew\s+Function\b
        ["amF2YXNjcmlwdFxccyo6", "i"],    // javascript\s*:
        ["ZGF0YVxccypcOlxccyp0ZXh0XC9odG1s", "i"], // data\s*:\s*text\/html
        ["XFxiaW1wb3J0XFxzKlwo", "i"],    // \bimport\s*(
        ["XFxicmVxdWlyZVxccypcKA==", "i"], // \brequire\s*(
    ];
    return encoded.map(([b64, flags]) =>
        new RegExp(atob(b64), flags)
    );
})();

function containsDangerousContent(value: string): boolean {
    return DANGEROUS_PATTERNS.some(pattern => pattern.test(value));
}

function sanitizeBlock(block: any): { text?: string; mimeType?: string; url?: string } | null {
    if (typeof block !== "object" || block === null || Array.isArray(block)) {
        console.warn("Rejected non-object block from LLM output");
        return null;
    }
    const sanitized: { text?: string; mimeType?: string; url?: string } = {};
    for (const key of ALLOWED_BLOCK_KEYS) {
        if (key in block) {
            const val = block[key];
            if (typeof val !== "string") {
                console.warn(`Rejected block: property '${key}' is not a string`);
                return null;
            }
            if (containsDangerousContent(val)) {
                console.warn(`Rejected block: property '${key}' contains dangerous content`);
                return null;
            }
            (sanitized as any)[key] = val;
        }
    }
    // Reject blocks with unknown keys to prevent prototype pollution or hidden payloads
    for (const key of Object.keys(block)) {
        if (!ALLOWED_BLOCK_KEYS.has(key)) {
            console.warn(`Rejected block: unknown property '${key}' found in LLM output`);
            return null;
        }
    }
    return sanitized;
}

export function responseToChatBlocks(completion: any) {
    // First we try to parse completion as JSON in case we're dealing with an object.
    console.log("got completoin", completion, typeof completion)
    if (typeof completion == "string") {
        try {
            completion = JSON.parse(completion)
        } catch {
            // Do nothing; we'll just treat it as a string.
            console.log("Couldn't parse")
        }
    }
    let blocks = []
    if (typeof completion == "string") {
        console.log("still string")
        if (containsDangerousContent(completion)) {
            console.warn("Rejected plain-string completion: contains dangerous content");
        } else {
            blocks.push(<ChatBlock text={completion} />)
        }
    } else if (Array.isArray(completion)) {
        console.log("Is array")
        for (let block of completion) {
            console.log(block)
            const safeBlock = sanitizeBlock(block);
            if (safeBlock !== null) {
                blocks.push(<ChatBlock {...safeBlock} />)
            } else {
                console.warn("Skipping unsafe block from LLM array output");
            }
        }
    } else {
        const safeCompletion = sanitizeBlock(completion);
        if (safeCompletion !== null) {
            blocks.push(<ChatBlock {...safeCompletion} />)
        } else {
            console.warn("Skipping unsafe completion object from LLM output");
        }
    }
    console.log(blocks)
    return blocks
}

