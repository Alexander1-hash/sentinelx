import type { Metadata } from "next";
import "./globals.css";
import MobileNavigation from "./components/mobile-navigation";

export const metadata: Metadata = {
  metadataBase: new URL(
    process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000"
  ),
  title: {
    default: "Trinorin",
    template: "%s | Trinorin",
  },
  description:
    "Trinorin is an AI-powered cybersecurity intelligence platform for monitoring threats, protecting assets, and improving security operations.",
  applicationName: "Trinorin",
  keywords: [
    "Trinorin",
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
      name: "Trinorin",
    },
  ],
  creator: "Trinorin",
  publisher: "Trinorin",
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
      <body>{children}<MobileNavigation /></body>
    </html>
  );
}
