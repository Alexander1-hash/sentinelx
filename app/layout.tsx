import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "SentinelX",
    template: "%s | SentinelX",
  },
  description:
    "AI-powered cybersecurity intelligence for modern businesses.",
  applicationName: "SentinelX",
  keywords: [
    "cybersecurity",
    "security intelligence",
    "threat detection",
    "AI security",
    "SentinelX",
  ],
  robots: {
    index: true,
    follow: true,
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
