"use client";

import { useEffect } from "react";

import { I18nextProvider } from "react-i18next";

import i18n, { DEFAULT_LANG, LANG_STORAGE_KEY, isLangCode } from "@/i18n/config";

// The first frame uses DEFAULT_LANG uniformly (consistent with static-export prerendering, avoiding hydration text mismatch),
// after mount, read the user-selected language from localStorage and switch, also syncing <html lang>.
export function I18nProvider({ children }: { readonly children: React.ReactNode }) {
  useEffect(() => {
    const stored = typeof window === "undefined" ? null : localStorage.getItem(LANG_STORAGE_KEY);
    const lang = isLangCode(stored) ? stored : DEFAULT_LANG;
    if (i18n.language !== lang) void i18n.changeLanguage(lang);
    if (typeof document !== "undefined") document.documentElement.lang = lang;
  }, []);

  return <I18nextProvider i18n={i18n}>{children}</I18nextProvider>;
}
