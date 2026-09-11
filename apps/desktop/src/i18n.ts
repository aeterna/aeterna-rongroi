// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// Adding a language: `cargo xtask new-locale <bcp47>`, then add it to `resources` below (docs/translating.md).

import i18next from "i18next";
import { initReactI18next } from "react-i18next";
import enCommon from "./locales/en/common.json";
import enReport from "./locales/en/report.json";
import thCommon from "./locales/th/common.json";
import thReport from "./locales/th/report.json";

export const resources = {
  en: { common: enCommon, report: enReport },
  th: { common: thCommon, report: thReport },
} as const;

export const supportedLanguages = Object.keys(resources) as (keyof typeof resources)[];

export const languageNames: Record<keyof typeof resources, string> = {
  en: "English",
  th: "ไทย",
};

export function initI18n(lng: string = "en") {
  return i18next.use(initReactI18next).init({
    resources,
    lng,
    fallbackLng: "en",
    defaultNS: "common",
    interpolation: { escapeValue: false },
  });
}

export default i18next;
