import { NextRequest, NextResponse } from "next/server";

const ETH_ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;
const MAX_SOURCE_CHARS = 50_000;
const API_TIMEOUT_MS = 30_000;

const AUDIT_PROMPT = `You are Sentinel, a senior smart-contract educator writing an educational
security review of a public, already-verified Ethereum contract.
This is defensive education only — help builders and investors understand
common risk patterns. Do not provide exploit instructions or attack steps.

Analyze the Solidity below for concerns such as reentrancy patterns,
access-control gaps, unchecked external calls, integer risks, denial-of-service
patterns, and risky logic. For each finding, note a historical parallel only
when it genuinely matches (e.g. The DAO 2016, Parity multisig freeze, Cream
Finance flash loans); otherwise use null.

Respond with ONLY valid JSON (no markdown, no code fences, no preamble) using
exactly this structure:

{
  "overallRiskScore": <integer 1-10, 10 = riskiest>,
  "summary": "<one plain-English sentence for a non-technical investor>",
  "issues": [
    {
      "title": "<short name>",
      "severity": "<Critical|High|Medium|Low|Info>",
      "plainEnglishExplanation": "<2-3 sentences, zero jargon, use an analogy>",
      "technicalDetail": "<1-2 technical sentences describing the concern>",
      "historicalMatch": "<matching incident name, or null>",
      "historicalMatchSummary": "<one sentence on that incident, or null>"
    }
  ]
}

If the contract looks well-hardened, return a low score and an empty issues array
with an encouraging summary.

Solidity source to review:
`;

type EtherscanSourceResult = {
  SourceCode?: string;
  ABI?: string;
  ContractName?: string;
};

type AuditIssue = {
  title: string;
  severity: string;
  plainEnglishExplanation: string;
  technicalDetail: string;
  historicalMatch: string | null;
  historicalMatchSummary: string | null;
};

type AuditReport = {
  overallRiskScore: number;
  summary: string;
  issues: AuditIssue[];
};

function stripMarkdownFences(text: string): string {
  let cleaned = text.trim();
  if (cleaned.startsWith("```")) {
    cleaned = cleaned.replace(/^```(?:json)?\s*/i, "");
    cleaned = cleaned.replace(/\s*```$/i, "");
  }
  return cleaned.trim();
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit,
  timeoutMs: number
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

function extractSourceCode(raw: string): string {
  if (!raw || raw.trim() === "") {
    return "";
  }

  // Etherscan sometimes wraps multi-file sources in {{...}} JSON
  let candidate = raw;
  if (candidate.startsWith("{{") && candidate.endsWith("}}")) {
    candidate = candidate.slice(1, -1);
  }

  try {
    const parsed = JSON.parse(candidate) as {
      sources?: Record<string, { content?: string }>;
      language?: string;
    };

    if (parsed.sources && typeof parsed.sources === "object") {
      return Object.entries(parsed.sources)
        .map(([path, file]) => {
          const content = file?.content ?? "";
          return `// ===== File: ${path} =====\n${content}`;
        })
        .join("\n\n");
    }
  } catch {
    // Not JSON — treat as plain Solidity source
  }

  return raw;
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function asNullableString(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed || trimmed.toLowerCase() === "null") return null;
    return trimmed;
  }
  return null;
}

function asScore(value: unknown): number | null {
  const num = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(num)) return null;
  return Math.max(1, Math.min(10, Math.round(num)));
}

function normalizeReport(raw: unknown): AuditReport | null {
  if (!raw || typeof raw !== "object") return null;

  const obj = raw as Record<string, unknown>;

  // Model sometimes returns a refusal object instead of the schema
  if (
    typeof obj.error === "string" &&
    !("overallRiskScore" in obj) &&
    !("issues" in obj)
  ) {
    return null;
  }

  const score =
    asScore(obj.overallRiskScore) ??
    asScore(obj.overall_risk_score) ??
    asScore(obj.riskScore);

  const summary =
    asString(obj.summary) ||
    asString(obj.overview) ||
    asString(obj.description);

  if (score === null || !summary.trim()) {
    return null;
  }

  const issuesRaw = Array.isArray(obj.issues)
    ? obj.issues
    : Array.isArray(obj.findings)
      ? obj.findings
      : [];

  const issues: AuditIssue[] = issuesRaw
    .map((item): AuditIssue | null => {
      if (!item || typeof item !== "object") return null;
      const issue = item as Record<string, unknown>;
      const title = asString(issue.title) || asString(issue.name);
      const severity = asString(issue.severity) || "Info";
      const plainEnglishExplanation =
        asString(issue.plainEnglishExplanation) ||
        asString(issue.explanation) ||
        asString(issue.description);
      const technicalDetail =
        asString(issue.technicalDetail) ||
        asString(issue.technical) ||
        asString(issue.details);

      if (!title.trim() || !plainEnglishExplanation.trim()) return null;

      return {
        title: title.trim(),
        severity: severity.trim() || "Info",
        plainEnglishExplanation: plainEnglishExplanation.trim(),
        technicalDetail:
          technicalDetail.trim() || plainEnglishExplanation.trim(),
        historicalMatch:
          asNullableString(issue.historicalMatch) ??
          asNullableString(issue.historical_match),
        historicalMatchSummary:
          asNullableString(issue.historicalMatchSummary) ??
          asNullableString(issue.historical_match_summary),
      };
    })
    .filter((item): item is AuditIssue => item !== null);

  return {
    overallRiskScore: score,
    summary: summary.trim(),
    issues,
  };
}

export async function POST(request: NextRequest) {
  try {
    const etherscanKey = process.env.ETHERSCAN_API_KEY;
    const geminiKey = process.env.GEMINI_API_KEY;

    if (!etherscanKey || !geminiKey) {
      return NextResponse.json(
        {
          error:
            "Server is missing API keys. Add ETHERSCAN_API_KEY and GEMINI_API_KEY to .env.local.",
        },
        { status: 500 }
      );
    }

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { error: 'Invalid JSON body. Send { "address": "0x..." }.' },
        { status: 400 }
      );
    }

    const address =
      typeof body === "object" &&
      body !== null &&
      "address" in body &&
      typeof (body as { address: unknown }).address === "string"
        ? (body as { address: string }).address.trim()
        : "";

    if (!ETH_ADDRESS_REGEX.test(address)) {
      return NextResponse.json(
        {
          error:
            "Invalid Ethereum address. It must start with 0x and be 42 characters long.",
        },
        { status: 400 }
      );
    }

    // --- Etherscan V2: fetch verified source (V1 endpoints are deprecated) ---
    const etherscanUrl = new URL("https://api.etherscan.io/v2/api");
    etherscanUrl.searchParams.set("chainid", "1"); // Ethereum mainnet
    etherscanUrl.searchParams.set("module", "contract");
    etherscanUrl.searchParams.set("action", "getsourcecode");
    etherscanUrl.searchParams.set("address", address);
    etherscanUrl.searchParams.set("apikey", etherscanKey);

    let etherscanRes: Response;
    try {
      etherscanRes = await fetchWithTimeout(
        etherscanUrl.toString(),
        { method: "GET" },
        API_TIMEOUT_MS
      );
    } catch (err) {
      const timedOut =
        err instanceof Error &&
        (err.name === "AbortError" || err.message.includes("abort"));
      return NextResponse.json(
        {
          error: timedOut
            ? "Etherscan request timed out. Please try again."
            : "Failed to reach Etherscan. Please try again.",
        },
        { status: 502 }
      );
    }

    if (!etherscanRes.ok) {
      return NextResponse.json(
        { error: "Etherscan returned an error. Please try again later." },
        { status: 502 }
      );
    }

    const etherscanData = (await etherscanRes.json()) as {
      status?: string;
      message?: string;
      result?: EtherscanSourceResult[] | string;
    };

    const resultEntry = Array.isArray(etherscanData.result)
      ? etherscanData.result[0]
      : undefined;

    const rawSource =
      typeof resultEntry?.SourceCode === "string" ? resultEntry.SourceCode : "";

    const sourceCode = extractSourceCode(rawSource);

    if (!sourceCode.trim()) {
      return NextResponse.json(
        {
          error:
            "This contract's source code isn't publicly verified, so it can't be scanned. Try a verified contract like USDC or Uniswap.",
        },
        { status: 404 }
      );
    }

    let sourceForPrompt = sourceCode;
    let truncated = false;
    if (sourceForPrompt.length > MAX_SOURCE_CHARS) {
      sourceForPrompt = sourceForPrompt.slice(0, MAX_SOURCE_CHARS);
      truncated = true;
    }

    const truncationNote = truncated
      ? `\n\n[NOTE: Source was truncated to ${MAX_SOURCE_CHARS} characters for analysis. Analyze the provided portion only.]\n`
      : "";

    const promptText = `${AUDIT_PROMPT}${truncationNote}\n${sourceForPrompt}`;

    // Prefer current free Flash model — older flash IDs reject newer API keys.
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key=${geminiKey}`;

    let geminiRes: Response;
    try {
      geminiRes = await fetchWithTimeout(
        geminiUrl,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [
              {
                role: "user",
                parts: [{ text: promptText }],
              },
            ],
            generationConfig: {
              temperature: 0.2,
              responseMimeType: "application/json",
            },
          }),
        },
        API_TIMEOUT_MS
      );
    } catch (err) {
      const timedOut =
        err instanceof Error &&
        (err.name === "AbortError" || err.message.includes("abort"));
      return NextResponse.json(
        {
          error: timedOut
            ? "AI analysis timed out. Please try again."
            : "Failed to reach Gemini. Please try again.",
        },
        { status: 502 }
      );
    }

    if (geminiRes.status === 429) {
      return NextResponse.json(
        {
          error:
            "Too many scans right now, please wait a moment and try again",
        },
        { status: 429 }
      );
    }

    if (!geminiRes.ok) {
      let detail = "";
      try {
        const errBody = (await geminiRes.json()) as {
          error?: { message?: string };
        };
        detail = errBody.error?.message ?? "";
      } catch {
        // ignore parse failure
      }
      return NextResponse.json(
        {
          error: detail
            ? `Gemini API error: ${detail}`
            : "Gemini API returned an error. Please try again.",
        },
        { status: 502 }
      );
    }

    const geminiData = (await geminiRes.json()) as {
      candidates?: Array<{
        content?: { parts?: Array<{ text?: string }> };
        finishReason?: string;
      }>;
      promptFeedback?: { blockReason?: string };
    };

    if (geminiData.promptFeedback?.blockReason) {
      return NextResponse.json(
        {
          error:
            "The AI safety filter blocked this analysis. Please try a different verified contract.",
        },
        { status: 502 }
      );
    }

    const rawText =
      geminiData.candidates?.[0]?.content?.parts?.[0]?.text ?? "";

    if (!rawText.trim()) {
      return NextResponse.json(
        { error: "Gemini returned an empty response. Please try again." },
        { status: 502 }
      );
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(stripMarkdownFences(rawText));
    } catch {
      return NextResponse.json(
        {
          error:
            "Could not parse the AI security report. Please try scanning again.",
        },
        { status: 502 }
      );
    }

    const report = normalizeReport(parsed);
    if (!report) {
      return NextResponse.json(
        {
          error:
            "The AI could not produce a structured security report for this contract. Please try again.",
        },
        { status: 502 }
      );
    }

    return NextResponse.json({
      address,
      contractName: resultEntry?.ContractName || null,
      truncated,
      report,
    });
  } catch (err) {
    console.error("Scan API unexpected error:", err);
    return NextResponse.json(
      { error: "Something went wrong while scanning. Please try again." },
      { status: 500 }
    );
  }
}
