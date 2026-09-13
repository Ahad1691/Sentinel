import type { Metadata } from "next";
import { Outfit, Syne } from "next/font/google";
import "./globals.css";

const outfit = Outfit({
  subsets: ["latin"],
  variable: "--font-body",
  display: "swap",
});

const syne = Syne({
  subsets: ["latin"],
  variable: "--font-display",
  weight: ["600", "700", "800"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "Sentinel — AI Smart Contract Security",
  description:
    "Premium AI-powered smart contract security scanner. Paste an Ethereum address and get a plain-English risk report powered by Google Gemini.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${outfit.variable} ${syne.variable} antialiased`}>
        {children}
      </body>
    </html>
  );
}
