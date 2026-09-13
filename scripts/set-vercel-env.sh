#!/usr/bin/env bash
# One-time setup: push API keys to the Vercel project (requires `npx vercel login`).
set -euo pipefail

PROJECT_NAME="${1:-temporary-instant-oboe-qtws5k4}"
TEAM_SCOPE="${2:-ahad1691s-projects}"

if [[ -z "${ETHERSCAN_API_KEY:-}" || -z "${GEMINI_API_KEY:-}" ]]; then
  echo "Set ETHERSCAN_API_KEY and GEMINI_API_KEY in your shell first, then re-run."
  exit 1
fi

npx vercel link --yes --project "$PROJECT_NAME" --scope "$TEAM_SCOPE"

for ENV in production preview development; do
  echo "$ETHERSCAN_API_KEY" | npx vercel env add ETHERSCAN_API_KEY "$ENV" --yes || true
  echo "$GEMINI_API_KEY" | npx vercel env add GEMINI_API_KEY "$ENV" --yes || true
done

npx vercel env ls
echo "Redeploying production..."
npx vercel --prod --yes
echo "Done. Test: curl -X POST https://tryoutsentinelio.vercel.app/api/scan -H 'content-type: application/json' -d '{\"address\":\"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48\"}'"
