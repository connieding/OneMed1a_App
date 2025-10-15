"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { useState, useEffect } from "react";

/**
 * MediaNavigation component for navigating between media tabs: Movies, TV, Books, Audio.
 * Highlights the active tab based on the current pathname.
 * Preserves the search query parameter 'q' when switching tabs.
 *
 * Used in the navigation bar of the application.
 * @returns
 */
export default function MediaNavigation() {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  // Only the four media tabs live here (centered)
  const tabs = [
    { name: "Movies", href: "/movie" },
    { name: "TV", href: "/tv" },
    { name: "Books", href: "/books" },
    { name: "Audio", href: "/audio" },
  ];

  // Persist current q param on tab switches
  const initialQ = searchParams?.get("q") ?? "";
  const [q, setQ] = useState(initialQ);
  useEffect(() => {
    setQ(searchParams?.get("q") ?? "");
  }, [searchParams]);

  return (
    <nav
      className="flex items-center justify-center"
      role="navigation"
      aria-label="Media categories"
    >
      <div className="flex flex-col items-center lg:flex-row lg:justify-center gap-1.5">
        {tabs.map((t) => {
          // Determine if this tab is active based on the current pathname
          const active = pathname?.startsWith(t.href);
          return (
            <Link
              key={t.name}
              href={t.href + (q ? `?q=${encodeURIComponent(q)}` : "")}
              aria-current={active ? "page" : undefined}
              className={`px-4 py-1.5 text-sm font-semibold uppercase tracking-wide transition-colors
              ${active ? "text-red-600" : "text-black hover:text-red-600"}`}
            >
              {t.name}
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
