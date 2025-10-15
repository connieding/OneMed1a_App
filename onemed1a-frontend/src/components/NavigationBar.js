"use client";

import { useState, useEffect } from "react";
import { usePathname } from "next/navigation";

import Link from "next/link";
import Logo from "./Logo";
import MediaNavigation from "./MediaNavigation";
import SearchBar from "./SearchBar";

/**
 * NavigationBar component for the application layout.
 * Only shows logo on authentication routes (login, signup).
 * @returns NavigationBar component that includes the logo, media navigation tabs, search bar, and recommendations link.
 */
export default function NavigationBar() {
  const pathname = usePathname() || "/";
  const isAuthRoute =
    pathname.startsWith("/login") || pathname.startsWith("/signup");

  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    setIsOpen(false);
  }, [pathname]);

  return (
    <>
      <header className="sticky top-0 z-50 bg-white border-b border-neutral-200 shadow-sm">
        <div className="mx-auto max-w-7xl px-4 py-3 flex items-center justify-between gap-6">
          {/* Logo (always visible) */}
          <div className="flex-shrink-0">
            <Logo isAuth={isAuthRoute} />
          </div>

          {/* Only show the rest of the navigation bar if not on auth routes */}
          {!isAuthRoute && (
            <>
              {/* Menu button */}
              <button
                className="lg:hidden flex items-center px-3 py-2 border rounded text-gray-600 border-gray-400 hover:text-black hover:border-black"
                onClick={() => setIsOpen((prev) => !prev)}
                aria-label="Open navigation"
              >
                <svg
                  className="fill-current h-4 w-4"
                  viewBox="0 0 20 20"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <title>Menu</title>
                  <path d="M0 3h20v2H0V3zm0 6h20v2H0V9zm0 6h20v2H0v-2z" />
                </svg>
              </button>

              {/* Desktop navigation */}
              <div className="hidden lg:flex items-center justify-between gap-6 flex-1">
                <div className="flex-1 flex justify-center">
                  <SearchBar />
                </div>

                {/* MediaNavigation */}
                <div className="flex-shrink-0 flex items-center">
                  <MediaNavigation />
                </div>

                {/* Recommendations Link */}
                <div className="flex-shrink-0 flex items-center gap-3">
                  <Link
                    href="/recommendations"
                    className="px-4 py-1.5 text-sm font-semibold uppercase tracking-wide rounded-full bg-red-600 text-white hover:bg-red-700 whitespace-nowrap"
                  >
                    Recommendations
                  </Link>
                </div>
                <div className="flex-shrink-0 flex items-center gap-3">
                  <Link href="/profile" className="hover-red">
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                      strokeWidth={2}
                      stroke="black"
                      className="size-10 hover:stroke-red-600"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M17.982 18.725A7.488 7.488 0 0 0 12 15.75a7.488 7.488 0 0 0-5.982 2.975m11.963 0a9 9 0 1 0-11.963 0m11.963 0A8.966 8.966 0 0 1 12 21a8.966 8.966 0 0 1-5.982-2.275M15 9.75a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"
                      />
                    </svg>
                  </Link>
                </div>
              </div>
            </>
          )}
        </div>
      </header>

      {/* Navigation Sidebar */}
      {!isAuthRoute && (
        <>
          {isOpen && (
            <button
              type="button"
              className="fixed inset-0 bg-black bg-opacity-50 z-40"
              aria-label="Close navigation overlay"
              onClick={() => setIsOpen(false)}
              tabIndex={0}
              style={{
                border: "none",
                background: "transparent",
                padding: 0,
                margin: 0,
              }}
            />
          )}
          <div
            className={`fixed top-0 left-0 h-full w-64 bg-white z-50 p-6 transform transition-transform duration-300 ease-in-out ${
              isOpen ? "translate-x-0" : "-translate-x-full"
            } lg:hidden`}
          >
            <div className="flex justify-center mb-6">
              <Logo isAuth={false} />
            </div>

            {/* Navigation Bar Items */}
            <div className="flex flex-col items-center space-y-6">
              <SearchBar />
              <MediaNavigation />
              <Link
                href="/recommendations"
                className="block px-4 py-2 text-sm font-semibold uppercase tracking-wide rounded-full bg-red-600 text-white hover:bg-red-700"
              >
                Recommendations
              </Link>
              <Link href="/profile" className="block hover-red">
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                  strokeWidth={2}
                  stroke="black"
                  className="size-10 hover:stroke-red-600"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M17.982 18.725A7.488 7.488 0 0 0 12 15.75a7.488 7.488 0 0 0-5.982 2.975m11.963 0a9 9 0 1 0-11.963 0m11.963 0A8.966 8.966 0 0 1 12 21a8.966 8.966 0 0 1-5.982-2.275M15 9.75a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"
                  />
                </svg>
              </Link>
            </div>
          </div>
        </>
      )}
    </>
  );
}
