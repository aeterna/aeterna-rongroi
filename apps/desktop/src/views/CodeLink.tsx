// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { codeLinkQr } from "../api";

interface Props {
  /** What is shown, selectable. */
  text: string;
  /** What the Copy button copies and the QR code encodes; no button when `null`. */
  copy: string | null;
  qr?: boolean;
}

/**
 * A link the window cannot open: selectable text, a Copy button and, where asked, a QR code drawn in
 * Rust. There is no network code and no plugin to open a browser with (ADR 0003, ADR 0045).
 */
export function CodeLink({ text, copy, qr = false }: Props) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");
  const [image, setImage] = useState<string | null>(null);

  useEffect(() => {
    if (!qr || !copy) {
      return;
    }
    void codeLinkQr(copy).then((svg) =>
      setImage(svg ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}` : null),
    );
  }, [qr, copy]);

  async function onCopy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied("copied");
    } catch {
      // Refused or unavailable: the text beside the button stays selectable.
      setCopied("failed");
    }
  }

  return (
    <span className="code-link">
      <code className="selectable">{text}</code>
      {copy && (
        <button type="button" className="copy" onClick={() => void onCopy(copy)}>
          {t(`code.copy_${copied}`)}
        </button>
      )}
      {image && copy && (
        <img
          className="qr"
          src={image}
          alt={t("code.qr_alt", { url: copy })}
          width={160}
          height={160}
        />
      )}
    </span>
  );
}
