# Sentinel

AI-powered smart contract security scanner with a premium dark glassmorphic UI.
Paste an Ethereum contract address, fetch its verified Solidity source from
Etherscan, and get a plain-English security report powered by Google Gemini.

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
