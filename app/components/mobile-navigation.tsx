"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Bot, Boxes, BrainCircuit, History, Link2, MoreHorizontal, Radar, Settings, ShieldAlert, X } from "lucide-react";

const items = [
  { label: "Command", href: "/", icon: Radar },
  { label: "Assets", href: "/assets", icon: Boxes },
  { label: "Brain", href: "/brain", icon: BrainCircuit },
  { label: "AI", href: "/ai-security", icon: Bot },
  { label: "Actions", href: "/actions", icon: ShieldAlert },
];

export default function MobileNavigation() {
  const pathname = usePathname();
  const [moreOpen, setMoreOpen] = useState(false);
  if (pathname === "/login" || pathname.startsWith("/auth")) return null;

  const moreItems = [
    { label: "Security Analyst", href: "/analyst", icon: BrainCircuit },
    { label: "Integrations", href: "/integrations", icon: Link2 },
    { label: "Security History", href: "/history", icon: History },
    { label: "Settings", href: "/settings", icon: Settings },
  ];

  return (
    <nav aria-label="Primary navigation" className="fixed inset-x-3 bottom-3 z-[70] grid grid-cols-5 gap-1 rounded-2xl border border-white/10 bg-[#0b151f] p-1.5 shadow-2xl shadow-black/40 lg:hidden">
      {items.map(({ label, href, icon: Icon }) => {
        const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
        return (
          <Link key={href} href={href} aria-current={active ? "page" : undefined} className={"flex min-w-0 flex-col items-center justify-center gap-1 rounded-xl px-1 py-2 text-[9px] font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/60 " + (active ? "bg-cyan-400/10 text-cyan-200" : "text-slate-400 hover:bg-white/5 hover:text-white")}>
            <Icon className="h-4 w-4" />
            <span>{label}</span>
          </Link>
        );
      })}
      {moreOpen ? (
        <div className="absolute bottom-[calc(100%+0.5rem)] right-0 w-[min(82vw,18rem)] rounded-2xl border border-white/10 bg-[#0b151f] p-2 shadow-2xl shadow-black/50">
          <div className="mb-1 flex items-center justify-between px-2 py-1">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Security tools</span>
            <button
              type="button"
              aria-label="Close security tools"
              onClick={() => setMoreOpen(false)}
              className="rounded-lg p-1 text-slate-500 hover:bg-white/5 hover:text-white"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          {moreItems.map(({ label, href, icon: Icon }) => {
            const active = pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                aria-current={active ? "page" : undefined}
                onClick={() => setMoreOpen(false)}
                className={"flex items-center gap-3 rounded-xl px-3 py-2.5 text-xs transition " + (active ? "bg-cyan-400/10 text-cyan-200" : "text-slate-300 hover:bg-white/5 hover:text-white")}
              >
                <Icon className="h-4 w-4" />
                <span>{label}</span>
              </Link>
            );
          })}
        </div>
      ) : null}

      <button
        type="button"
        aria-label="More security tools"
        aria-expanded={moreOpen}
        onClick={() => setMoreOpen((open) => !open)}
        className={"flex min-w-0 flex-col items-center justify-center gap-1 rounded-xl px-1 py-2 text-[9px] font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/60 " + (moreOpen ? "bg-cyan-400/10 text-cyan-200" : "text-slate-400 hover:bg-white/5 hover:text-white")}
      >
        <MoreHorizontal className="h-4 w-4" />
        <span>More</span>
      </button>
    </nav>
  );
}
