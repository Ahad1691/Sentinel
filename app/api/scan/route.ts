import { NextResponse } from "next/server";

/**
 * POST /api/scan
 * Accepts { address: "0x..." } and will scan verified Solidity source.
 * Full Etherscan + Gemini logic lands in the next commit.
 */
export async function POST() {
  return NextResponse.json(
    {
      error: "Scan API not implemented yet. Coming soon.",
    },
    { status: 501 }
  );
}
