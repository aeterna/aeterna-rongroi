// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { type ElevateOutcome, relaunchElevated, reportHeader } from "./api";
import { languageNames, supportedLanguages } from "./i18n";
import type { Mode, ReportHeader } from "./types";
import { About } from "./views/About";
import { Consent } from "./views/Consent";
import { Report } from "./views/Report";
import { UnofficialBanner } from "./views/UnofficialBanner";

type Screen = "start" | "consent" | "declined" | "about" | { report: Mode };

export function App() {
  const { t, i18n } = useTranslation();
  const [header, setHeader] = useState<ReportHeader | null>(null);
  const [screen, setScreen] = useState<Screen>("start");
  // The screen About & code was opened from, so Back returns there: an open report keeps its mode,
  // and an SS report does not ask for consent again.
  const [beforeAbout, setBeforeAbout] = useState<Exclude<Screen, "about">>("start");
  const [elevation, setElevation] = useState<ElevateOutcome | null>(null);

  useEffect(() => {
    void reportHeader().then(setHeader);
  }, []);

  return (
    <main>
      <header className="top">
        <div>
          <h1>{t("app.name")}</h1>
          <p className="muted">{t("app.tagline")}</p>
        </div>
        <div className="top-actions">
          <button
            type="button"
            className="nav"
            onClick={() => {
              if (screen !== "about") {
                setBeforeAbout(screen);
              }
              setScreen("about");
            }}
          >
            {t("nav.about")}
          </button>
          <label className="language">
            {t("language.label")}{" "}
            <select
              value={i18n.language}
              onChange={(e) => void i18n.changeLanguage(e.target.value)}
            >
              {supportedLanguages.map((lang) => (
                <option key={lang} value={lang}>
                  {languageNames[lang]}
                </option>
              ))}
            </select>
          </label>
        </div>
      </header>

      {header && !header.provenance.official && <UnofficialBanner />}

      {screen === "start" && (
        <section className="start">
          <h2>{t("start.title")}</h2>
          <div className="choices">
            <button type="button" className="choice" onClick={() => setScreen({ report: "self" })}>
              <span className="choice-title">{t("start.self_button")}</span>
              <span className="muted">{t("start.self_hint")}</span>
            </button>
            <button type="button" className="choice" onClick={() => setScreen("consent")}>
              <span className="choice-title">{t("start.ss_button")}</span>
              <span className="muted">{t("start.ss_hint")}</span>
            </button>
          </div>
          {/* Only worth offering while this scan ran without the rights some checks need. */}
          {header?.elevated === false && (
            <>
              <button type="button" onClick={() => void relaunchElevated().then(setElevation)}>
                {t("start.elevate_button")}
              </button>
              <p className="muted">{t("start.elevate_hint")}</p>
              {/* Declining is a choice, so it is a plain sentence and not an alert (ADR 0012). */}
              {elevation === "declined" && <p className="muted">{t("start.elevate_declined")}</p>}
              {elevation === "failed" && <p className="note">{t("start.elevate_failed")}</p>}
            </>
          )}
          <p className="note">{t("start.scan_note")}</p>
        </section>
      )}

      {screen === "consent" && (
        <Consent
          onAgree={() => setScreen({ report: "ss" })}
          onRefuse={() => setScreen("declined")}
        />
      )}

      {screen === "declined" && (
        <section>
          <h2>{t("declined.title")}</h2>
          <p>{t("declined.body")}</p>
        </section>
      )}

      {screen === "about" && <About onBack={() => setScreen(beforeAbout)} />}

      {typeof screen === "object" && (
        <Report mode={screen.report} onBack={() => setScreen("start")} />
      )}

      <footer className="muted">{t("footer.evidence_only")}</footer>
    </main>
  );
}
