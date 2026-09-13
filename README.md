# Sentinel

AI-powered smart contract security scanner. Paste an Ethereum contract address,
fetch its verified Solidity source from Etherscan, and get a plain-English
security report powered by Google Gemini.

## Tech stack

- **Next.js 14** (App Router) + TypeScript
- **Tailwind CSS**
- **Stateless** — no database; scans are not stored
- **Etherscan API V2** — verified contract source on Ethereum mainnet
- **Google Gemini** (`gemini-3.6-flash`) — security analysis (free Flash tier)

## Prerequisites

- Node.js 18+ and npm
- An [Etherscan API key](https://etherscan.io/apis) (free)
- A [Google AI Studio / Gemini API key](https://aistudio.google.com/apikey) (free)

## Setup

1. Clone this repo and install dependencies:

```bash
npm install
```

2. Create your local environment file:

```bash
cp .env.local.example .env.local
```

3. Open `.env.local` and replace the placeholders with your real keys:

```
ETHERSCAN_API_KEY=...
GEMINI_API_KEY=...
```

4. Start the development server:

```bash
npm run dev
```

5. Open [http://localhost:3000](http://localhost:3000) in your browser.

## Vercel (production)

The live app at [tryoutsentinelio.vercel.app](https://tryoutsentinelio.vercel.app)
needs the same two keys in the Vercel project **Environment Variables**:

1. Open [Vercel → Project → Settings → Environment Variables](https://vercel.com/ahad1691s-projects/temporary-instant-oboe-qtws5k4/settings/environment-variables)
2. Add:
   - `ETHERSCAN_API_KEY` → your Etherscan key (Production + Preview + Development)
   - `GEMINI_API_KEY` → your Gemini key (Production + Preview + Development)
3. Redeploy (Deployments → … → Redeploy), or push to `main`

Or from a machine where you are logged into Vercel CLI:

```bash
export ETHERSCAN_API_KEY=...
export GEMINI_API_KEY=...
bash scripts/set-vercel-env.sh
```

## Scripts

| Command        | Description              |
| -------------- | ------------------------ |
| `npm run dev`  | Start local dev server   |
| `npm run build`| Production build         |
| `npm run start`| Run production server    |
| `npm run lint` | Run ESLint               |

## Privacy

Scans are not stored — your data stays private. API keys live only in
`.env.local` (local) or your host’s environment settings (e.g. Vercel).
