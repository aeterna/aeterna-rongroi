// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { Evidence, Observation, RuleFiles, RuleText } from "../types";
import { CodeLink } from "./CodeLink";

interface Props {
  item: Evidence;
  text: RuleText | undefined;
  /** `https://…/blob/<commit>` for an official build, `null` otherwise. */
  fileBase: string | null;
  /** `https://…/tree/<commit>` for an official build, `null` otherwise. */
  treeBase: string | null;
  /** Whether `codeLinks()` has arrived (successfully or not) — `false` while still in flight. */
  linksKnown: boolean;
  technicalAll: boolean;
}

/**
 * One piece of evidence in three layers (ADR 0045): the row; what it means; technical details and
 * where it is in the code. A match starts open, because the sentence saying a rule proves no
 * cheating usually ends the description, which the two-line cut of a closed row hides.
 */
export function EvidenceRow({ item, text, fileBase, treeBase, linksKnown, technicalAll }: Props) {
  const { t } = useTranslation("report");
  const [open, setOpen] = useState(item.state === "found");
  const [technical, setTechnical] = useState(false);
  const shown = open || technicalAll;
  const showTechnical = technical || technicalAll;
  // A reason the rule itself declared in `unmeasured_when` is a different statement from one it did
  // not, and the reason alone does not tell them apart (ADR 0027).
  const stateKey =
    item.state === "unmeasured"
      ? item.expected
        ? "unmeasured_expected"
        : "unmeasured_unexpected"
      : item.state;

  return (
    <li className={`row row-${item.state}`}>
      <button
        type="button"
        className="row-head"
        aria-expanded={shown}
        // Carried fix (c): while every row is already forced open by the technical switch, a click
        // here must not silently change the row's own hidden `open` state for when it is switched off.
        disabled={technicalAll}
        onClick={() => setOpen(!shown)}
      >
        <span className={`mark mark-${item.state}`} aria-hidden="true" />
        <span className="title">
          {t("check")}: {text?.title ?? item.rule_id}
        </span>
        <span className="state">{t(`state.${stateKey}`)}</span>
        {!shown && text?.description && <span className="clamp">{text.description}</span>}
      </button>
      {shown && (
        <div className="row-body">
          {text?.description && (
            <p className="description">
              {t("description")}: {text.description}
            </p>
          )}
          <Meaning item={item} text={text} />
          <button
            type="button"
            className="disclosure"
            aria-expanded={showTechnical}
            disabled={technicalAll}
            onClick={() => setTechnical(!technical)}
          >
            {t("layers.technical")}
          </button>
          {showTechnical && (
            <Technical
              item={item}
              text={text}
              fileBase={fileBase}
              treeBase={treeBase}
              linksKnown={linksKnown}
            />
          )}
        </div>
      )}
    </li>
  );
}

function Meaning({ item, text }: { item: Evidence; text: RuleText | undefined }) {
  const { t } = useTranslation("report");
  switch (item.state) {
    case "found": {
      // What legitimately produces the same evidence goes beside a match (ADR 0027).
      const causes = text?.falsepositives ?? [];
      return causes.length === 0 ? null : (
        <div className="falsepositives">
          <p className="muted">{t("falsepositives")}:</p>
          <ul>
            {causes.map((cause) => (
              <li key={cause}>{cause}</li>
            ))}
          </ul>
        </div>
      );
    }
    case "not_found":
      // The report keeps the English source text; the rule text carries the translation.
      return (
        <p className="detail">
          {t("retention")}: {text?.retention ?? item.retention}
        </p>
      );
    case "unmeasured":
      return <p className="detail">{t(`reason.${item.reason}`)}</p>;
  }
}

function Technical({
  item,
  text,
  fileBase,
  treeBase,
  linksKnown,
}: {
  item: Evidence;
  text: RuleText | undefined;
  fileBase: string | null;
  treeBase: string | null;
  linksKnown: boolean;
}) {
  const { t } = useTranslation("report");
  const observations: Observation[] = item.state === "found" ? item.observations : [];
  return (
    <div className="technical">
      {observations.map((observation) => (
        <table className="fields" key={JSON.stringify(observation.fields)}>
          <caption>{t("layers.observation")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("layers.field")}</th>
              <th scope="col">{t("layers.value")}</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(observation.fields).map(([field, value]) => (
              <tr key={field}>
                <th scope="row">{field}</th>
                <td>
                  <code className="selectable">{String(value)}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
      <dl className="facts">
        <dt>{t("layers.rule_id")}</dt>
        <dd>
          <code className="selectable">{item.rule_id}</code>
        </dd>
        {text && (
          <>
            <dt>{t("layers.status")}</dt>
            <dd>
              <code>{text.status}</code>
            </dd>
          </>
        )}
        <dt>{t("layers.collector")}</dt>
        <dd>
          <code>{item.collector}</code>
        </dd>
        <dt>{t("layers.strength")}</dt>
        <dd>
          {t(`strength.${item.strength}`)} (<code>{item.strength}</code>)
        </dd>
        {item.state === "unmeasured" && (
          <>
            <dt>{t("layers.reason")}</dt>
            <dd>
              <code>
                {item.reason} · expected={String(item.expected)}
              </code>
            </dd>
          </>
        )}
      </dl>
      {text && (
        <Files files={text.files} fileBase={fileBase} treeBase={treeBase} linksKnown={linksKnown} />
      )}
    </div>
  );
}

function Files({
  files,
  fileBase,
  treeBase,
  linksKnown,
}: {
  files: RuleFiles;
  fileBase: string | null;
  treeBase: string | null;
  linksKnown: boolean;
}) {
  const { t } = useTranslation("report");
  const paths: [string, string, string | null][] = [
    ["layers.rule_file", files.rule, fileBase && `${fileBase}/${files.rule}`],
    ["layers.fixtures", files.fixtures, treeBase && `${treeBase}/${files.fixtures}`],
    ["layers.collector_file", files.collector, fileBase && `${fileBase}/${files.collector}`],
  ];
  return (
    <section className="rule-files" aria-label={t("layers.code_title")}>
      <p className="muted">
        {t("layers.code_title")}
        {/* Carried fix (b): neither statement until it is known whether this build's commit is
            known — a call still in flight, or one that failed, is not evidence either way. */}
        {linksKnown && (
          <> · {fileBase ? t("layers.files_at_commit") : t("layers.files_unknown_build")}</>
        )}
      </p>
      <ul>
        {paths.map(([label, path, link]) => (
          <li key={label}>
            <span className="muted">{t(label)}</span> <CodeLink text={path} copy={link} />
          </li>
        ))}
        {files.references.map((url) => (
          <li key={url}>
            <span className="muted">{t("layers.reference")}</span>{" "}
            <CodeLink text={url} copy={url} />
          </li>
        ))}
      </ul>
    </section>
  );
}
