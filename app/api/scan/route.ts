import { NextRequest, NextResponse } from "next/server";

const ETH_ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;
const MAX_SOURCE_CHARS = 50_000;
const API_TIMEOUT_MS = 30_000;

const AUDIT_PROMPT = `You are Sentinel, an expert smart contract security auditor. You will be
given Solidity source code. Analyze it for vulnerabilities including
reentrancy, integer overflow/underflow, unchecked external calls, access
control issues, front-running risk, denial of service vectors, and logic
errors.

For each issue, note if it resembles a well-known historical exploit (e.g.
The DAO reentrancy hack of 2016, Parity multisig freeze, Cream Finance flash
loan exploits) — only if it genuinely matches, don't force it.

Respond with ONLY valid JSON, no markdown, no code fences, no preamble.
Use exactly this structure:

{
  "overallRiskScore": <1-10, 10 = riskiest>,
  "summary": "<one sentence, plain English, for a non-technical investor>",
  "issues": [
    {
      "title": "<short name>",
      "severity": "<Critical|High|Medium|Low|Info>",
      "plainEnglishExplanation": "<2-3 sentences, zero jargon, use an analogy>",
      "technicalDetail": "<1-2 sentences, technical>",
      "historicalMatch": "<matching incident name, or null>",
      "historicalMatchSummary": "<one sentence on that incident, or null>"
    }
  ]
}

If no issues found, return an empty array and a low score with an
encouraging summary.

Here is the contract source code to analyze:
`;

type EtherscanSourceResult = {
  SourceCode?: string;
  ABI?: string;
  ContractName?: string;
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
        { error: "Invalid JSON body. Send { \"address\": \"0x...\" }." },
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

    // --- Gemini: security analysis ---
    // Prefer current free Flash model — gemini-2.5-flash rejects new API keys.
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
      }>;
    };

    const rawText =
      geminiData.candidates?.[0]?.content?.parts?.[0]?.text ?? "";

    if (!rawText.trim()) {
      return NextResponse.json(
        { error: "Gemini returned an empty response. Please try again." },
        { status: 502 }
      );
    }

    let report: unknown;
    try {
      report = JSON.parse(stripMarkdownFences(rawText));
    } catch {
      return NextResponse.json(
        {
          error:
            "Could not parse the AI security report. Please try scanning again.",
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
