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
        if (mimeType.startsWith("audio")) {
            internalComponent = <audio controls={true} src={url} />
        } else if (mimeType.startsWith("video")) {
            internalComponent = <video controls width="250">
                <source src={url} type={mimeType} />
                Download the <a href={url}>video</a>
            </video>
        } else if (mimeType.startsWith("image")) {
            internalComponent = <img src={url} alt="AI-generated image" />
        }
    } else if (url) {
        internalComponent = <a href={url}>Link</a>
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

// Patterns that indicate dynamic code execution primitives in LLM output
const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bFunction\s*\(/i,
    /\bsetTimeout\s*\(/i,
    /\bsetInterval\s*\(/i,
    /\bnew\s+Function\b/i,
    /javascript\s*:/i,
    /data\s*:\s*text\/html/i,
    /\bimport\s*\(/i,
    /\brequire\s*\(/i,
];

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
        blocks.push(<ChatBlock text={completion} />)
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

