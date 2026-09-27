"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Bot, Boxes, BrainCircuit, Radar, ShieldAlert } from "lucide-react";

const items = [
  { label: "Command", href: "/", icon: Radar },
  { label: "Assets", href: "/assets", icon: Boxes },
  { label: "Brain", href: "/brain", icon: BrainCircuit },
  { label: "AI", href: "/ai-security", icon: Bot },
  { label: "Actions", href: "/actions", icon: ShieldAlert },
];

export default function MobileNavigation() {
  const pathname = usePathname();
  if (pathname === "/login" || pathname.startsWith("/auth")) return null;

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
    </nav>
  );
}
