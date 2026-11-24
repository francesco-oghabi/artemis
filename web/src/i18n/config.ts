import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import enUS from "./locales/en-US.json";
import itIT from "./locales/it-IT.json";

// Lingue supportate. label usa il nome nella lingua madre (non va mai tradotto),
// mostrato nel selettore di lingua.
export const LANGS = [
  { code: "en-US", label: "English" },
  { code: "it-IT", label: "Italiano" },
] as const;

export type LangCode = (typeof LANGS)[number]["code"];

export const DEFAULT_LANG: LangCode = "en-US";
export const LANG_STORAGE_KEY = "artemis-lang";

export function isLangCode(v: string | null | undefined): v is LangCode {
  return !!v && LANGS.some((l) => l.code === v);
}

// Resources are bundled directly (not async-loaded): static-export friendly, no Suspense, consistent SSR/first paint.
if (!i18n.isInitialized) {
  void i18n.use(initReactI18next).init({
    resources: {
      "it-IT": { translation: itIT },
      "en-US": { translation: enUS },
    },
    lng: DEFAULT_LANG,
    fallbackLng: DEFAULT_LANG,
    interpolation: { escapeValue: false },
    returnNull: false,
  });
}

export default i18n;
