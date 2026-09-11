# Translating

English is the source language. Everything else falls back to English key by key, so a partial translation
is useful from day one.

## Two kinds of text

| Text | Files | License |
|---|---|---|
| App interface (buttons, consent screen, labels) | `apps/desktop/src/locales/<lang>/*.json` | GPL-3.0-or-later |
| Rule `title`, `description`, `falsepositives`, `retention` (look-back note) | `rules/i18n/<lang>.yaml`, keyed by rule id | CC-BY-SA-4.0 |

## Add a language

```bash
cargo xtask new-locale <bcp47>     # e.g. vi, id, pt-BR
```

This copies the English UI files and creates an empty rule translation file. Then:

1. Translate the values in `apps/desktop/src/locales/<lang>/`. Do not rename keys.
2. Register the language in `apps/desktop/src/i18n.ts`.
3. Translate rules in `rules/i18n/<lang>.yaml` — as many or as few as you like.
4. Run `cargo xtask check-locales` and `cargo xtask check-rules`.

`check-locales` treats missing keys as warnings and extra keys or files as errors.

## Keep these untranslated

- **UNOFFICIAL BUILD** — staff look for this exact token (ADR 0007).
- `%USERPROFILE%`, `Get-FileHash`, `SHA256SUMS`, file paths, registry keys and rule ids.
- Product names: aeterna-rongroi, Windows, Secure Boot, WebView2, FiveM.

## Tone

Plain, calm, non-accusing. The tool shows evidence; it never says someone cheated or that a PC is clean.
