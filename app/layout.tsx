import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL(
    process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000"
  ),
  title: {
    default: "SentinelX",
    template: "%s | SentinelX",
  },
  description:
    "SentinelX is an AI-powered cybersecurity intelligence platform for monitoring threats, protecting assets, and improving security operations.",
  applicationName: "SentinelX",
  keywords: [
    "SentinelX",
    "cybersecurity",
    "AI cybersecurity",
    "security intelligence",
    "threat detection",
    "security operations",
    "risk management",
    "vulnerability management",
  ],
  authors: [
    {
      name: "SentinelX",
    },
  ],
  creator: "SentinelX",
  publisher: "SentinelX",
  robots: {
    index: true,
    follow: true,
  },
  icons: {
    icon: "/favicon.ico",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
