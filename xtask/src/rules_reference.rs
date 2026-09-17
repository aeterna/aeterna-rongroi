// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask rules-reference`: one Markdown page per language describing every rule in the rules
//! bundle, and `--check`, which fails when a committed page no longer matches the rules.
//!
//! The bundle is read with `collect_bundle_json` and `Bundle::from_bundle_json` — the function
//! `rongroi-core`'s build script includes to embed the rules, and the loader the program parses the
//! embedded copy with — so the page describes the bytes the program ships and not a second reading of
//! the YAML. Rule text in another language comes from `Bundle::text`, the call the program shows it
//! with. The words for a strength and an unmeasured reason come from the desktop app's
//! `report.json`, so the page and the report use the same words for them.
//!
//! The page renders rule text and nothing else: what a rule looks at, never how to avoid it.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, bail};
use rongroi_core::bundle::{Bundle, BundleError, BundleInfo};
use rongroi_core::rules::{
    MatchKey, Operator, RelatedKind, Rule, RuleFiles, RuleText, SourcedRule, Status,
    parse_match_key,
};
use rongroi_core::source_tree::collect_bundle_json;

/// The command a stale page is fixed with. Printed by `--check`, and written into the page itself.
pub const COMMAND: &str = "cargo xtask rules-reference";

const LOCALES: &str = "apps/desktop/src/locales";

/// Every page this command writes, by language.
const PAGES: [(Lang, &str); 2] = [
    (Lang::En, "docs/rules-reference.md"),
    (Lang::Th, "docs/rules-reference.th.md"),
];

#[derive(clap::Args)]
pub struct Args {
    /// Do not write anything; fail if a committed page differs from what the rules produce.
    #[arg(long)]
    check: bool,
}

pub fn run(root: &Path, args: &Args) -> anyhow::Result<()> {
    let pages = render_pages(root)?;
    if args.check {
        let problems = stale_pages(root, &pages)?;
        if problems.is_empty() {
            println!(
                "rules-reference: {} page(s) match the rules bundle",
                pages.len()
            );
            return Ok(());
        }
        for problem in &problems {
            eprintln!("error: {problem}");
        }
        eprintln!(
            "note: the pages are written from rules/**/rule.yaml, rules/i18n/*.yaml and the strength and \
             reason words in {LOCALES}/*/report.json; a change to any of them changes the pages"
        );
        bail!(
            "rules-reference: {} page(s) out of date — run `{COMMAND}` and commit the result",
            problems.len()
        );
    }
    for (path, text) in &pages {
        std::fs::write(root.join(path), text).with_context(|| format!("writing {path}"))?;
        println!("rules-reference: wrote {path}");
    }
    Ok(())
}

/// Every page, rendered from the rules and the report labels under `root`.
fn render_pages(root: &Path) -> anyhow::Result<Vec<(&'static str, String)>> {
    let json = collect_bundle_json(&root.join("rules"))?;
    let bundle = match Bundle::from_bundle_json(&json) {
        Ok(bundle) => bundle,
        Err(BundleError::Invalid(problems)) => bail!(
            "rules-reference: the rules bundle does not load ({} problem(s)); `cargo xtask check-rules` names them",
            problems.len()
        ),
        Err(error) => bail!("rules-reference: {error}"),
    };
    let english = read_labels(root, "en")?
        .with_context(|| format!("rules-reference: {LOCALES}/en/report.json does not exist"))?;
    PAGES
        .iter()
        .map(|(lang, path)| {
            let own = match lang {
                Lang::En => None,
                Lang::Th => read_labels(root, lang.code())?,
            };
            let labels = Labels {
                own,
                english: english.clone(),
            };
            Ok((*path, render(&bundle, *lang, &labels)))
        })
        .collect()
}

/// A message for every page that is missing or differs from `pages`.
fn stale_pages(root: &Path, pages: &[(&'static str, String)]) -> anyhow::Result<Vec<String>> {
    let mut problems = Vec::new();
    for (path, expected) in pages {
        let file = root.join(path);
        if !file.is_file() {
            problems.push(format!("{path} does not exist"));
            continue;
        }
        let committed = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {path}"))?
            .replace("\r\n", "\n");
        if &committed != expected {
            problems.push(format!(
                "{path} does not match what the rules bundle produces"
            ));
        }
    }
    Ok(problems)
}

fn read_labels(root: &Path, lang: &str) -> anyhow::Result<Option<serde_json::Value>> {
    let file = root.join(LOCALES).join(lang).join("report.json");
    if !file.is_file() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
    let value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
    Ok(Some(value))
}

/// The desktop app's report words, in a page's language with English beneath, as the app falls back.
struct Labels {
    own: Option<serde_json::Value>,
    english: serde_json::Value,
}

impl Labels {
    fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.own
            .as_ref()
            .and_then(|own| label_in(own, section, key))
            .or_else(|| label_in(&self.english, section, key))
    }
}

/// `value[section][key]`, or `value[key]` when `section` is empty, as text.
fn label_in<'a>(value: &'a serde_json::Value, section: &str, key: &str) -> Option<&'a str> {
    let found = if section.is_empty() {
        value.get(key)
    } else {
        value.get(section).and_then(|inner| inner.get(key))
    };
    found.and_then(serde_json::Value::as_str)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lang {
    En,
    Th,
}

impl Lang {
    fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Th => "th",
        }
    }

    fn words(self) -> &'static Words {
        match self {
            Self::En => &EN,
            Self::Th => &TH,
        }
    }
}

/// One comparison, read aloud: the words before a single value, before a list of values, and after.
struct Phrase {
    one: &'static str,
    any: &'static str,
    after: &'static str,
}

/// The fixed words of a page. What a rule or the report already words is not repeated here.
struct Words {
    intro: fn(&BundleInfo) -> String,
    contents: &'static str,
    collector_heading: &'static str,
    id: &'static str,
    file: &'static str,
    collector: &'static str,
    strength: &'static str,
    status: &'static str,
    tags: &'static str,
    written: &'static str,
    modified: &'static str,
    english_title: Option<&'static str>,
    shown_in_english: &'static str,
    matches: &'static str,
    unmeasured: &'static str,
    unmeasured_none: &'static str,
    allow: &'static str,
    allow_sha256: &'static str,
    allow_cert: &'static str,
    related: &'static str,
    references: &'static str,
    text_folded: &'static str,
    text_cased: &'static str,
    equals: Phrase,
    starts_with: Phrase,
    ends_with: Phrase,
    contains: Phrase,
    number: [Phrase; 4],
    instant: [Phrase; 4],
    present: &'static str,
    absent: &'static str,
    /// A `match_lists` condition's values: how many, and the file (ADR 0048).
    listed_in: fn(usize, &str) -> String,
    statuses: [&'static str; 4],
    related_kinds: [&'static str; 5],
    /// The heading and the paragraph above the timeline selectors (ADR 0051).
    selectors_heading: &'static str,
    selectors_intro: &'static str,
    /// The fact line that says a file is a timeline selector.
    role: &'static str,
    role_timeline: &'static str,
    /// The heading of a timeline selector's ordinary causes, which it shows beside every entry.
    selector_causes: &'static str,
}

const fn one(words: &'static str) -> Phrase {
    Phrase {
        one: words,
        any: words,
        after: "",
    }
}

const EN: Words = Words {
    intro: intro_en,
    contents: "Contents",
    collector_heading: "Collector",
    id: "Id",
    file: "File",
    collector: "Collector",
    strength: "Strength",
    status: "Status",
    tags: "Tags",
    written: "Written",
    modified: "changed",
    english_title: None,
    shown_in_english: "",
    matches: "Matches when all of these hold for one observation",
    unmeasured: "Not measured, and named by the rule as ordinary on some machines",
    unmeasured_none: "The rule names none.",
    allow: "Legitimate software excluded (`allow`)",
    allow_sha256: "the file whose SHA-256 is",
    allow_cert: "files signed with the certificate whose SHA-256 is",
    related: "Related rules",
    references: "References",
    text_folded: "text, ASCII case ignored",
    text_cased: "text, compared exactly: case matters",
    equals: Phrase {
        one: "is",
        any: "is one of",
        after: "",
    },
    starts_with: Phrase {
        one: "starts with",
        any: "starts with one of",
        after: "",
    },
    ends_with: Phrase {
        one: "ends with",
        any: "ends with one of",
        after: "",
    },
    contains: Phrase {
        one: "contains",
        any: "contains one of",
        after: "",
    },
    number: [
        one("is greater than"),
        one("is at least"),
        one("is less than"),
        one("is at most"),
    ],
    instant: [
        one("is later than"),
        one("is at or after"),
        one("is earlier than"),
        one("is at or before"),
    ],
    present: "the field is present",
    absent: "the field is absent",
    listed_in: listed_in_en,
    statuses: [
        "being developed",
        "believed correct; has a positive and a negative fixture",
        "proven on real traffic; has a positive and a negative fixture",
        "kept for history; never evaluated",
    ],
    related_kinds: [
        "renamed from",
        "replaces",
        "derived from",
        "merges",
        "similar to",
    ],
    selectors_heading: "Timeline selectors",
    selectors_intro: "A timeline selector is written like a rule and produces no evidence: the observations it matches put \
        their times on the report's timeline, in Self and SS mode, each with the text and the ordinary causes \
        below. It is never Found, Not found or Not measured, and never counted (ADR 0051). A timeline selector \
        may choose Prefetch, BAM and Program Compatibility Assistant records by name, which a rule may not \
        (ADR 0034): a name says nothing about which program it was, and each one says so.",
    role: "Role",
    role_timeline: "a timeline selector: its matches are times on the timeline, never evidence",
    selector_causes: "Ordinary things behind these times",
};

const TH: Words = Words {
    intro: intro_th,
    contents: "สารบัญ",
    collector_heading: "collector",
    id: "id",
    file: "ไฟล์",
    collector: "collector",
    strength: "strength",
    status: "status",
    tags: "tag",
    written: "เขียนเมื่อ",
    modified: "แก้ไขล่าสุด",
    english_title: Some("ชื่อภาษาอังกฤษ"),
    shown_in_english: " *(แสดงข้อความภาษาอังกฤษ)*",
    matches: "ตรงเมื่อทุกข้อต่อไปนี้เป็นจริงกับสิ่งที่เห็นชิ้นเดียวกัน",
    unmeasured: "ยังไม่ได้วัด ในกรณีที่ rule ระบุไว้ว่าเป็นเรื่องปกติของบางเครื่อง",
    unmeasured_none: "rule นี้ไม่ได้ระบุไว้",
    allow: "ซอฟต์แวร์ที่ถูกต้องซึ่งยกเว้นไว้ (`allow`)",
    allow_sha256: "ไฟล์ที่มี SHA-256 เป็น",
    allow_cert: "ไฟล์ที่เซ็นด้วยใบรับรองที่มี SHA-256 เป็น",
    related: "rule ที่เกี่ยวข้อง",
    references: "แหล่งอ้างอิง",
    text_folded: "ข้อความ ไม่สนตัวพิมพ์เล็กใหญ่ของอักษร ASCII",
    text_cased: "ข้อความ เทียบตรงทุกตัว ตัวพิมพ์เล็กใหญ่มีผล",
    equals: Phrase {
        one: "เป็น",
        any: "เป็นค่าใดค่าหนึ่งใน",
        after: "",
    },
    starts_with: Phrase {
        one: "ขึ้นต้นด้วย",
        any: "ขึ้นต้นด้วยค่าใดค่าหนึ่งใน",
        after: "",
    },
    ends_with: Phrase {
        one: "ลงท้ายด้วย",
        any: "ลงท้ายด้วยค่าใดค่าหนึ่งใน",
        after: "",
    },
    contains: Phrase {
        one: "มี",
        any: "มีค่าใดค่าหนึ่งใน",
        after: " อยู่ในข้อความ",
    },
    number: [
        one("มากกว่า"),
        Phrase {
            one: "ตั้งแต่",
            any: "ตั้งแต่",
            after: " ขึ้นไป",
        },
        one("น้อยกว่า"),
        one("ไม่เกิน"),
    ],
    instant: [
        one("หลัง"),
        Phrase {
            one: "ตั้งแต่",
            any: "ตั้งแต่",
            after: " เป็นต้นไป",
        },
        one("ก่อน"),
        one("ไม่หลัง"),
    ],
    present: "มีฟิลด์นี้",
    absent: "ไม่มีฟิลด์นี้",
    listed_in: listed_in_th,
    statuses: [
        "อยู่ระหว่างพัฒนา",
        "เชื่อว่าถูกต้อง มี fixture ทั้งแบบเจอและแบบไม่เจอ",
        "พิสูจน์แล้วกับการใช้งานจริง มี fixture ทั้งแบบเจอและแบบไม่เจอ",
        "เก็บไว้เป็นประวัติ ไม่ถูกประเมิน",
    ],
    related_kinds: ["เปลี่ยนชื่อมาจาก", "ใช้แทน", "ดัดแปลงมาจาก", "รวมมาจาก", "คล้ายกับ"],
    selectors_heading: "timeline selector",
    selectors_intro: "timeline selector เขียนแบบเดียวกับ rule แต่ไม่สร้างหลักฐาน สิ่งที่เห็นที่มันเลือกจะเอาเวลาของตัวเองไปวางบน \
        timeline ของรายงาน ทั้งโหมด Self และ SS พร้อมข้อความและเรื่องปกติด้านล่าง มันไม่เคยเป็น เจอ ไม่เจอ หรือ \
        ยังไม่ได้วัด และไม่ถูกนับ (ADR 0051) timeline selector เลือกบันทึกของ Prefetch, BAM และ Program \
        Compatibility Assistant ตามชื่อได้ ซึ่ง rule ทำไม่ได้ (ADR 0034) ชื่อไม่ได้บอกว่าเป็นโปรแกรมไหน และทุกตัวเขียนบอกไว้",
    role: "บทบาท",
    role_timeline: "timeline selector: สิ่งที่ตรงคือเวลาบน timeline ไม่ใช่หลักฐาน",
    selector_causes: "เรื่องปกติที่อยู่เบื้องหลังเวลาเหล่านี้",
};

fn listed_in_en(count: usize, file: &str) -> String {
    format!("the {count} values in the first column of `{file}`, a file beside the rule")
}

fn listed_in_th(count: usize, file: &str) -> String {
    format!("{count} ค่าในคอลัมน์แรกของ `{file}` ซึ่งเป็นไฟล์ที่อยู่ข้าง rule")
}

fn generated_comment() -> String {
    format!(
        "<!-- Generated by `{COMMAND}` from rules/. Do not edit by hand: change the rule and run the command. -->\n"
    )
}

fn intro_en(info: &BundleInfo) -> String {
    format!(
        "{comment}
# Rule reference

> **This page is generated.** `{COMMAND}` writes it from the rules bundle: the
> `rule.yaml` files and the `rules/i18n/` translations that are compiled into the program. Do not edit
> it by hand. Change the rule, run `{COMMAND}`, and commit this page with the rule.
> CI runs `{COMMAND} --check` and fails when the page and the rules disagree.

อ่านภาษาไทย: [rules-reference.th.md](rules-reference.th.md)

Every rule the program ships, in the words the program shows. A rule says which observations are worth
showing and what they can show. It never decides that someone cheated. Each result is **Found**, **Not
found** together with how far back its source can see, or **Not measured** together with a reason, and
beside every Found row the program shows the ordinary things that also produce it.

| Rules bundle | |
|---|---|
| Rule format | {schema} |
| Rules | {count} |
| SHA-256 | `{sha}` |

A report header shows its rule count and bundle SHA-256. A report with a different SHA-256 came from a
program with a different set of rules: read this page at the commit that program was built from.

## How to read a rule

- **Matches when** lists conditions on one observation, something a collector saw. All of them must
  hold. Text is compared without regard to ASCII case unless the condition says it is compared
  exactly.
- If the collector could not read a field a condition names, the rule is **Not measured**, never Not
  found.
- **Not measured, and named by the rule as ordinary on some machines** lists the reasons the rule's
  author said carry no information on such a machine. SS mode counts them instead of listing them (ADR 0027).
- **Strength** says what the evidence can show: `execution`, a program ran; `presence`, a file or
  program existed; `tamper`, traces were removed or altered; `posture`, a machine setting that makes
  cheating easier; `context`, background for the reviewer.

Writing or changing a rule: [rules-authoring.md](rules-authoring.md). Checking a PC over a
screenshare: [screenshare-guide.md](screenshare-guide.md).
",
        comment = generated_comment(),
        schema = info.schema_version,
        count = info.rule_count,
        sha = info.sha256,
    )
}

fn intro_th(info: &BundleInfo) -> String {
    format!(
        "{comment}
# คู่มืออ้างอิง rule

> **หน้านี้สร้างขึ้นอัตโนมัติ** `{COMMAND}` เขียนหน้านี้จาก rules bundle คือไฟล์ `rule.yaml`
> และคำแปลใน `rules/i18n/` ที่ถูกคอมไพล์รวมไว้ในโปรแกรม อย่าแก้หน้านี้ด้วยมือ ให้แก้ที่ rule
> แล้วรัน `{COMMAND}` และ commit หน้านี้ไปพร้อมกับ rule
> · CI รัน `{COMMAND} --check` และจะไม่ผ่านถ้าหน้านี้กับ rule ไม่ตรงกัน

Read in English: [rules-reference.md](rules-reference.md)

rule ทุกตัวที่มากับโปรแกรม ด้วยข้อความเดียวกับที่โปรแกรมแสดง rule บอกว่าสิ่งที่เห็นแบบไหนควรแสดง และแสดงอะไรได้
rule ไม่เคยตัดสินว่าใครโกง ผลแต่ละข้อเป็น **เจอ**, **ไม่เจอ** พร้อมบอกว่าแหล่งนั้นย้อนดูได้ไกลแค่ไหน หรือ
**ยังไม่ได้วัด** พร้อมเหตุผล และข้างทุกแถวที่ **เจอ** โปรแกรมจะแสดงเรื่องปกติที่ทำให้เกิดผลแบบเดียวกันได้

| rules bundle | |
|---|---|
| รูปแบบ rule | {schema} |
| จำนวน rule | {count} |
| SHA-256 | `{sha}` |

ส่วนหัวของรายงานแสดงจำนวน rule และ SHA-256 ของ bundle ถ้า SHA-256 ในรายงานไม่ตรงกับค่านี้ แปลว่าโปรแกรมนั้นมี
ชุด rule ต่างจากที่หน้านี้อธิบาย ให้อ่านหน้านี้ที่ commit ที่โปรแกรมนั้น build มา

## วิธีอ่าน rule

- **ตรงเมื่อ** คือเงื่อนไขกับสิ่งที่ collector เห็นหนึ่งชิ้น ต้องเป็นจริงทุกข้อ ข้อความเทียบแบบไม่สนตัวพิมพ์เล็กใหญ่ของอักษร
  ASCII เว้นแต่เงื่อนไขนั้นบอกว่าเทียบตรงทุกตัว
- ถ้า collector อ่านฟิลด์ที่เงื่อนไขพูดถึงไม่ได้ rule นั้นจะเป็น **ยังไม่ได้วัด** ไม่ใช่ ไม่เจอ
- **ยังไม่ได้วัด ในกรณีที่ rule ระบุไว้ว่าเป็นเรื่องปกติของบางเครื่อง** คือเหตุผลที่ผู้เขียน rule บอกว่าไม่ได้บอกอะไรเลยบนบางเครื่อง
  โหมด SS นับจำนวนไว้แทนที่จะแสดงเป็นรายการ (ADR 0027)
- **strength** บอกว่าหลักฐานแสดงอะไรได้: `execution` มีโปรแกรมรัน · `presence` มีไฟล์หรือโปรแกรมอยู่ ·
  `tamper` ร่องรอยถูกล้างหรือแก้ · `posture` การตั้งค่าเครื่องที่ทำให้โกงง่ายขึ้น · `context` ข้อมูลประกอบให้ผู้ตรวจ

เขียนหรือแก้ rule: [rules-authoring.md](rules-authoring.md) (ภาษาอังกฤษ) · ตรวจเครื่องผ่านการแชร์หน้าจอ:
[screenshare-guide.th.md](screenshare-guide.th.md)
",
        comment = generated_comment(),
        schema = info.schema_version,
        count = info.rule_count,
        sha = info.sha256,
    )
}

/// Files of one role, grouped by collector and then by category, in path order.
type Groups<'b> = BTreeMap<&'b str, BTreeMap<&'b str, Vec<&'b SourcedRule>>>;

fn groups_of(bundle: &Bundle, timeline: bool) -> Groups<'_> {
    let mut groups: Groups<'_> = BTreeMap::new();
    for sourced in bundle.rules() {
        if sourced.rule.is_timeline_selector() != timeline {
            continue;
        }
        let category = sourced.path.split('/').nth(1).unwrap_or_default();
        groups
            .entry(sourced.rule.collector.as_str())
            .or_default()
            .entry(category)
            .or_default()
            .push(sourced);
    }
    for categories in groups.values_mut() {
        for rules in categories.values_mut() {
            rules.sort_by(|a, b| a.path.cmp(&b.path));
        }
    }
    groups
}

/// One page: every rule in `bundle`, grouped by collector and then by category, in path order, and
/// then every timeline selector the same way, in a section of its own (ADR 0051).
fn render(bundle: &Bundle, lang: Lang, labels: &Labels) -> String {
    let words = lang.words();
    let rules = groups_of(bundle, false);
    let selectors = groups_of(bundle, true);

    let mut out = (words.intro)(bundle.info());
    let _ = writeln!(out, "\n## {}\n", words.contents);
    let contents = |out: &mut String, groups: &Groups<'_>, indent: &str| {
        for (collector, categories) in groups {
            let _ = writeln!(out, "{indent}- {}", code(collector));
            for sourced in categories.values().flatten() {
                let title = title(bundle, &sourced.rule, lang);
                let _ = writeln!(
                    out,
                    "{indent}  - [{}](#{}) — {} · {}",
                    prose_line(&title),
                    anchor(&sourced.rule.id),
                    code(sourced.rule.strength.as_str()),
                    code(status_code(sourced.rule.status)),
                );
            }
        }
    };
    contents(&mut out, &rules, "");
    if !selectors.is_empty() {
        let _ = writeln!(out, "- {}", words.selectors_heading);
        contents(&mut out, &selectors, "  ");
    }

    for (collector, categories) in &rules {
        let _ = writeln!(out, "\n## {} {}", words.collector_heading, code(collector));
        for (category, rules) in categories {
            let _ = writeln!(out, "\n### {} / {}", code(collector), code(category));
            for sourced in rules {
                render_rule(&mut out, bundle, sourced, lang, labels);
            }
        }
    }
    if !selectors.is_empty() {
        let _ = writeln!(
            out,
            "\n## {}\n\n{}",
            words.selectors_heading,
            prose_block(words.selectors_intro, "")
        );
        for (collector, categories) in &selectors {
            for (category, rules) in categories {
                let _ = writeln!(out, "\n### {} / {}", code(collector), code(category));
                for sourced in rules {
                    render_rule(&mut out, bundle, sourced, lang, labels);
                }
            }
        }
    }
    out
}

fn render_rule(
    out: &mut String,
    bundle: &Bundle,
    sourced: &SourcedRule,
    lang: Lang,
    labels: &Labels,
) {
    let words = lang.words();
    let rule = &sourced.rule;
    let text = bundle
        .text(&rule.id, lang.code())
        .unwrap_or_else(|| RuleText {
            title: rule.title.clone(),
            description: rule.description.clone(),
            falsepositives: rule.falsepositives.clone(),
            retention: rule.retention.clone(),
            status: rule.status,
            files: RuleFiles::of(sourced),
        });
    // `Bundle::text` falls back to English per field; the page says where it did.
    let marker = |same: bool| {
        if lang != Lang::En && same {
            words.shown_in_english
        } else {
            ""
        }
    };

    let _ = writeln!(
        out,
        "\n<a id=\"{}\"></a>\n\n#### {}{}\n",
        anchor(&rule.id),
        prose_line(&text.title),
        marker(text.title == rule.title)
    );
    if let Some(label) = words.english_title
        && text.title != rule.title
    {
        let _ = writeln!(out, "- {label}: {}", prose_line(&rule.title));
    }
    render_facts(out, sourced, words, labels);

    let _ = writeln!(
        out,
        "\n**{}**{}\n\n{}",
        prose_line(labels.get("", "description").unwrap_or("About this check")),
        marker(text.description == rule.description),
        prose_block(&text.description, "")
    );

    let _ = writeln!(out, "\n**{}**\n", words.matches);
    for (key, value) in &rule.matcher {
        let _ = writeln!(out, "- {}", condition(rule, key, value, words));
    }

    let _ = writeln!(
        out,
        "\n**{}**{}\n\n{}",
        prose_line(labels.get("", "retention").unwrap_or("Look-back")),
        marker(text.retention == rule.retention),
        prose_block(&text.retention, "")
    );

    // A timeline selector makes no `unmeasured` row and may declare no reason (ADR 0051).
    if !rule.is_timeline_selector() {
        render_unmeasured(out, rule, words, labels);
    }

    let causes = if rule.is_timeline_selector() {
        words.selector_causes
    } else {
        labels
            .get("", "falsepositives")
            .unwrap_or("Ordinary things that also produce this")
    };
    let _ = writeln!(
        out,
        "\n**{}**{}\n",
        prose_line(causes),
        marker(text.falsepositives == rule.falsepositives)
    );
    for item in &text.falsepositives {
        let _ = writeln!(out, "- {}", prose_block(item, "  "));
    }

    render_links(out, bundle, rule, lang);
}

/// The reasons a rule named as ordinary on some machines.
fn render_unmeasured(out: &mut String, rule: &Rule, words: &Words, labels: &Labels) {
    let _ = writeln!(out, "\n**{}**\n", words.unmeasured);
    if rule.unmeasured_when.is_empty() {
        let _ = writeln!(out, "{}", words.unmeasured_none);
    }
    for reason in &rule.unmeasured_when {
        let reason = reason.as_str();
        let _ = writeln!(
            out,
            "- {}",
            with_label(reason, labels.get("reason", reason))
        );
    }
}

/// The short facts under a rule's heading: id, file, collector, strength, status, tags, dates.
fn render_facts(out: &mut String, sourced: &SourcedRule, words: &Words, labels: &Labels) {
    let rule = &sourced.rule;
    let _ = writeln!(out, "- {}: {}", words.id, code(&rule.id));
    let _ = writeln!(
        out,
        "- {}: [{}](../rules/{})",
        words.file,
        code(&format!("rules/{}", sourced.path)),
        sourced.path
    );
    if rule.is_timeline_selector() {
        let _ = writeln!(
            out,
            "- {}: {} — {}",
            words.role,
            code(rule.role.as_str()),
            words.role_timeline
        );
    }
    let _ = writeln!(out, "- {}: {}", words.collector, code(&rule.collector));
    let strength = rule.strength.as_str();
    let _ = writeln!(
        out,
        "- {}: {}",
        words.strength,
        with_label(strength, labels.get("strength", strength))
    );
    let status = status_code(rule.status);
    let _ = writeln!(
        out,
        "- {}: {} — {}",
        words.status,
        code(status),
        words.statuses[status_index(rule.status)]
    );
    if !rule.tags.is_empty() {
        let tags: Vec<String> = rule.tags.iter().map(|tag| code(tag)).collect();
        let _ = writeln!(out, "- {}: {}", words.tags, tags.join(", "));
    }
    match &rule.modified {
        Some(modified) => {
            let _ = writeln!(
                out,
                "- {}: {} · {}: {}",
                words.written, rule.date, words.modified, modified
            );
        }
        None => {
            let _ = writeln!(out, "- {}: {}", words.written, rule.date);
        }
    }
}

/// What a rule points at: the software it excludes, the rules it is related to, its sources.
fn render_links(out: &mut String, bundle: &Bundle, rule: &Rule, lang: Lang) {
    let words = lang.words();
    if !rule.allow.is_empty() {
        let _ = writeln!(out, "\n**{}**\n", words.allow);
        for allow in &rule.allow {
            if let Some(hash) = &allow.sha256 {
                let _ = writeln!(out, "- {} {}", words.allow_sha256, code(hash));
            }
            if let Some(hash) = &allow.signer_cert_sha256 {
                let _ = writeln!(out, "- {} {}", words.allow_cert, code(hash));
            }
        }
    }

    if !rule.related.is_empty() {
        let _ = writeln!(out, "\n**{}**\n", words.related);
        for related in &rule.related {
            let kind = words.related_kinds[related_index(related.kind)];
            match bundle.text(&related.id, lang.code()) {
                Some(other) => {
                    let _ = writeln!(
                        out,
                        "- {kind} [{}](#{})",
                        prose_line(&other.title),
                        anchor(&related.id)
                    );
                }
                None => {
                    let _ = writeln!(out, "- {kind} {}", code(&related.id));
                }
            }
        }
    }

    if !rule.references.is_empty() {
        let _ = writeln!(out, "\n**{}**\n", words.references);
        for reference in &rule.references {
            let _ = writeln!(out, "- {}", reference_line(reference));
        }
    }
}

fn title(bundle: &Bundle, rule: &Rule, lang: Lang) -> String {
    bundle
        .text(&rule.id, lang.code())
        .map_or_else(|| rule.title.clone(), |text| text.title)
}

/// One `match` entry read aloud: the key as written, what it asks, and how text is compared.
fn condition(rule: &Rule, key: &str, value: &serde_json::Value, words: &Words) -> String {
    let (field, operator) = match parse_match_key(key) {
        MatchKey::Known { field, operator } => (field, operator),
        // `validate` refuses these, so a loaded bundle never has one; show it as written.
        MatchKey::UnknownOperator { .. } => return format!("{}: {}", code(key), value_code(value)),
    };
    let values: Vec<&serde_json::Value> = match value.as_array() {
        Some(list) => list.iter().collect(),
        None => vec![value],
    };
    let is_list = value.is_array();
    let holds_text = values.iter().any(|value| value.is_string());
    let phrase = match operator {
        Operator::Equals => Some(&words.equals),
        Operator::StartsWith => Some(&words.starts_with),
        Operator::EndsWith => Some(&words.ends_with),
        Operator::Contains => Some(&words.contains),
        Operator::GreaterThan | Operator::AtLeast | Operator::LessThan | Operator::AtMost => {
            let index = match operator {
                Operator::GreaterThan => 0,
                Operator::AtLeast => 1,
                Operator::LessThan => 2,
                _ => 3,
            };
            Some(if holds_text {
                &words.instant[index]
            } else {
                &words.number[index]
            })
        }
        Operator::Exists => None,
    };
    let case = if operator.compares_text() && holds_text {
        if rule.cased.contains(field) {
            format!(" ({})", words.text_cased)
        } else {
            format!(" ({})", words.text_folded)
        }
    } else {
        String::new()
    };
    if let Some(file) = rule.match_lists.get(field) {
        return format!(
            "{}: {} {}{case}",
            code(key),
            words.equals.any,
            (words.listed_in)(values.len(), file)
        );
    }
    let reading = match phrase {
        Some(phrase) => {
            let shown: Vec<String> = values.iter().map(|value| value_code(value)).collect();
            format!(
                "{} {}{}",
                if is_list { phrase.any } else { phrase.one },
                shown.join(", "),
                phrase.after
            )
        }
        None => match value.as_bool() {
            Some(true) => words.present.to_owned(),
            Some(false) => words.absent.to_owned(),
            None => value_code(value),
        },
    };
    format!("{}: {reading}{case}", code(key))
}

fn status_code(status: Status) -> &'static str {
    match status {
        Status::Experimental => "experimental",
        Status::Test => "test",
        Status::Stable => "stable",
        Status::Deprecated => "deprecated",
    }
}

fn status_index(status: Status) -> usize {
    match status {
        Status::Experimental => 0,
        Status::Test => 1,
        Status::Stable => 2,
        Status::Deprecated => 3,
    }
}

fn related_index(kind: RelatedKind) -> usize {
    match kind {
        RelatedKind::Renamed => 0,
        RelatedKind::Obsolete => 1,
        RelatedKind::Derived => 2,
        RelatedKind::Merged => 3,
        RelatedKind::Similar => 4,
    }
}

fn anchor(id: &str) -> String {
    format!("rule-{id}")
}

/// A code, followed by the report's word for it when that word says something the code does not.
fn with_label(code_text: &str, label: Option<&str>) -> String {
    match label {
        Some(label) if label != code_text => format!("{} — {}", code(code_text), prose_line(label)),
        _ => code(code_text),
    }
}

fn value_code(value: &serde_json::Value) -> String {
    match value.as_str() {
        Some("") => "`\"\"`".to_owned(),
        Some(text) => code(text),
        None => code(&value.to_string()),
    }
}

fn reference_line(reference: &str) -> String {
    let is_url = (reference.starts_with("https://") || reference.starts_with("http://"))
        && !reference.contains(|c: char| c.is_whitespace() || c == '<' || c == '>');
    if is_url {
        format!("<{reference}>")
    } else {
        prose_line(reference)
    }
}

/// `text` as an inline code span that shows every character as written, backticks included.
fn code(text: &str) -> String {
    let text = text.replace(['\n', '\r'], " ");
    let mut longest = 0;
    let mut run = 0;
    for c in text.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let fence = "`".repeat(longest + 1);
    if longest > 0 || text.starts_with(' ') || text.ends_with(' ') {
        format!("{fence} {text} {fence}")
    } else {
        format!("{fence}{text}{fence}")
    }
}

/// Plain text as Markdown that renders as the same text: one line, nothing in it read as markup.
fn prose_line(text: &str) -> String {
    let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = String::with_capacity(joined.len());
    for c in joined.chars() {
        if matches!(
            c,
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '#' | '~' | '|'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    escape_block_start(&out)
}

/// Plain text that may hold blank-line paragraphs; later paragraphs are indented by `indent` so they
/// stay inside a list item.
fn prose_block(text: &str, indent: &str) -> String {
    let mut paragraphs = Vec::new();
    let mut current = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                paragraphs.push(prose_line(&current.join(" ")));
                current.clear();
            }
        } else {
            current.push(line);
        }
    }
    if !current.is_empty() {
        paragraphs.push(prose_line(&current.join(" ")));
    }
    paragraphs.join(&format!("\n\n{indent}"))
}

/// A line that would start a list item, a heading or a quote is escaped at its first character.
fn escape_block_start(line: &str) -> String {
    if line.starts_with(['-', '+', '=']) {
        return format!("\\{line}");
    }
    let digits = line.chars().take_while(char::is_ascii_digit).count();
    if digits > 0 && line[digits..].starts_with(['.', ')']) {
        return format!("{}\\{}", &line[..digits], &line[digits..]);
    }
    line.to_owned()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    const ENGLISH_LABELS: &str = r#"{
      "strength": { "posture": "posture", "tamper": "tamper", "presence": "presence" },
      "reason": { "not_windows": "not running on Windows", "access_denied": "Windows refused to open this" },
      "retention": "Look-back",
      "description": "About this check",
      "falsepositives": "Ordinary things that also produce this"
    }"#;

    const THAI_LABELS: &str = r#"{
      "strength": { "posture": "สถานะเครื่อง", "presence": "มีไฟล์อยู่" },
      "reason": { "not_windows": "ไม่ได้รันบน Windows" },
      "retention": "ย้อนดูได้",
      "description": "เกี่ยวกับการตรวจนี้",
      "falsepositives": "เรื่องปกติที่ทำให้เกิดผลแบบนี้ได้เหมือนกัน"
    }"#;

    /// A plugin-folder rule using every operator shape the page reads aloud. Its text is written for
    /// this test and is not a rule of this project.
    const PLUGIN_RULE: &str = r#"id: 3b2d6c1e-8f4a-4d5b-9c7e-1a2b3c4d5e6f
title: A plugin file with no valid embedded signature
description: >-
  A file in a *plugin* folder has no valid signature_state. 1. It does not
  show that the file was loaded.

  A second folded line.
status: experimental
collector: fivem_dir
strength: presence
match:
  path|endswith: ['.asi', '.dll']
  path|contains: '\plugins\'
  signature: [invalid, no_embedded_signature]
  sha256|exists: true
  location: Legacy_ASI
cased: [location]
allow:
  - sha256: 0000000000000000000000000000000000000000000000000000000000000000
  - signer_cert_sha256: 1111111111111111111111111111111111111111111111111111111111111111
retention: What is in the folder now.
unmeasured_when: [not_windows, access_denied]
falsepositives:
  - Overlays and graphics tools that ship unsigned plugins
  - "- A line that starts like a list item"
references:
  - https://example.org/plugins
  - A manual page with no address
author: tests
date: 2026-09-13
modified: 2026-09-14
tags: [fivem, plugins]
related:
  - id: 7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7
    type: similar
"#;

    const POSTURE_RULE: &str = "id: 7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7\ntitle: Secure Boot is turned off\ndescription: Windows reports that Secure Boot is off.\nstatus: test\ncollector: posture\nstrength: posture\nmatch:\n  secure_boot: disabled\nretention: Current setting only.\nfalsepositives: [Legacy BIOS]\nauthor: tests\ndate: 2026-09-11\ntags: [posture, boot]\n";

    const PREFETCH_RULE: &str = "id: 9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d\ntitle: Ran at least twice after a date\ndescription: Counted runs.\nstatus: experimental\ncollector: prefetch\nstrength: execution\nmatch:\n  run_count|gte: 2\n  last_run|gt: \"2026-01-01T00:00:00Z\"\n  run_count|lt: 100\nretention: What Prefetch still holds.\nfalsepositives: [Any program run twice]\nauthor: tests\ndate: 2026-09-12\n";

    const THAI_RULES: &str = "7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7:\n  title: Secure Boot ถูกปิดอยู่\n  retention: เป็นค่าที่ตั้งไว้ตอนนี้เท่านั้น\n";

    fn bundle_json() -> String {
        // Out of path order on purpose: the page must not depend on the order it was handed.
        serde_json::json!({
            "rules": [
                { "path": "prefetch/runs/ran-twice/rule.yaml", "yaml": PREFETCH_RULE },
                { "path": "posture/boot/secure-boot-disabled/rule.yaml", "yaml": POSTURE_RULE },
                { "path": "fivem_dir/plugins/unsigned-plugin/rule.yaml", "yaml": PLUGIN_RULE },
            ],
            "i18n": [{ "lang": "th", "yaml": THAI_RULES }],
        })
        .to_string()
    }

    fn bundle() -> Bundle {
        Bundle::from_bundle_json(&bundle_json()).unwrap()
    }

    fn labels(lang: Lang) -> Labels {
        Labels {
            own: (lang == Lang::Th).then(|| serde_json::from_str(THAI_LABELS).unwrap()),
            english: serde_json::from_str(ENGLISH_LABELS).unwrap(),
        }
    }

    #[test]
    fn english_page() {
        insta::assert_snapshot!(render(&bundle(), Lang::En, &labels(Lang::En)));
    }

    #[test]
    fn thai_page() {
        insta::assert_snapshot!(render(&bundle(), Lang::Th, &labels(Lang::Th)));
    }

    const SELECTOR: &str = "id: 4d3c2b1a-0f9e-4d8c-8b7a-6f5e4d3c2b1a\ntitle: When Prefetch recorded a program named game.exe\ndescription: Puts a time on the timeline.\nstatus: experimental\nrole: timeline\ncollector: prefetch\nstrength: context\nmatch:\n  name: game.exe\nretention: What Prefetch still holds.\nfalsepositives: [Any program of that name]\nauthor: tests\ndate: 2026-09-17\n";

    /// ADR 0051: timeline selectors are listed after the rules, in a section of their own, with their
    /// role and without an unmeasured block, which they may not have.
    #[test]
    fn timeline_selectors_have_their_own_section() {
        let mut json: serde_json::Value = serde_json::from_str(&bundle_json()).unwrap();
        json["rules"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "path": "prefetch/timeline/game-by-name/rule.yaml",
                "yaml": SELECTOR,
            }));
        let bundle = Bundle::from_bundle_json(&json.to_string()).unwrap();
        let page = render(&bundle, Lang::En, &labels(Lang::En));
        let (before, section) = page.split_once("\n## Timeline selectors\n").unwrap();
        assert!(
            before.contains("- Timeline selectors\n  - `prefetch`"),
            "{before}"
        );
        assert!(!before.contains("game.exe`"), "{before}");
        assert!(
            section.contains("- Role: `timeline` — a timeline selector"),
            "{section}"
        );
        assert!(
            section.contains("**Ordinary things behind these times**"),
            "{section}"
        );
        let own = section.split_once("4d3c2b1a").unwrap().1;
        assert!(!own.contains("Not measured, and named"), "{own}");

        let without = render(&self::bundle(), Lang::En, &labels(Lang::En));
        assert!(!without.contains("Timeline selectors"), "{without}");
    }

    #[test]
    fn page_is_the_same_whatever_order_the_rules_arrive_in() {
        let reversed: serde_json::Value = serde_json::from_str(&bundle_json()).unwrap();
        let mut reversed = reversed;
        reversed["rules"].as_array_mut().unwrap().reverse();
        let other = Bundle::from_bundle_json(&reversed.to_string()).unwrap();
        // The SHA-256 in the header is of the raw bundle, so compare everything after it.
        let body = |page: String| page.split_once("## Contents").unwrap().1.to_owned();
        assert_eq!(
            body(render(&bundle(), Lang::En, &labels(Lang::En))),
            body(render(&other, Lang::En, &labels(Lang::En)))
        );
    }

    fn reading(key: &str, value: &serde_json::Value, cased: &[&str], lang: Lang) -> String {
        let mut rule: Rule = a_rule();
        rule.cased = cased.iter().map(|field| (*field).to_owned()).collect();
        condition(&rule, key, value, lang.words())
    }

    /// A rule to hang `cased` on; only that field matters to `condition`.
    fn a_rule() -> Rule {
        bundle()
            .rules()
            .iter()
            .find(|sourced| sourced.rule.collector == "posture")
            .unwrap()
            .rule
            .clone()
    }

    #[test]
    fn every_operator_is_read_aloud() {
        let en = |key: &str, value: serde_json::Value| reading(key, &value, &[], Lang::En);
        assert_eq!(
            en("tpm", "absent".into()),
            "`tpm`: is `absent` (text, ASCII case ignored)"
        );
        assert_eq!(
            en("event_id", serde_json::json!([1102, 104])),
            "`event_id`: is one of `1102`, `104`"
        );
        assert_eq!(
            en("run_count|gt", 2.into()),
            "`run_count|gt`: is greater than `2`"
        );
        assert_eq!(
            en("run_count|gte", 2.into()),
            "`run_count|gte`: is at least `2`"
        );
        assert_eq!(
            en("run_count|lt", 2.into()),
            "`run_count|lt`: is less than `2`"
        );
        assert_eq!(
            en("run_count|lte", 2.into()),
            "`run_count|lte`: is at most `2`"
        );
        assert_eq!(
            en("last_run|gt", "2026-01-01T00:00:00Z".into()),
            "`last_run|gt`: is later than `2026-01-01T00:00:00Z`"
        );
        assert_eq!(
            en("last_run|lte", "2026-01-01T00:00:00Z".into()),
            "`last_run|lte`: is at or before `2026-01-01T00:00:00Z`"
        );
        assert_eq!(
            en("path|startswith", "C:\\Users\\".into()),
            "`path|startswith`: starts with `C:\\Users\\` (text, ASCII case ignored)"
        );
        assert_eq!(
            en("path|endswith", serde_json::json!([".asi", ".dll"])),
            "`path|endswith`: ends with one of `.asi`, `.dll` (text, ASCII case ignored)"
        );
        assert_eq!(
            en("path|contains", "Temp".into()),
            "`path|contains`: contains `Temp` (text, ASCII case ignored)"
        );
        assert_eq!(
            en("path|exists", true.into()),
            "`path|exists`: the field is present"
        );
        assert_eq!(
            en("path|exists", false.into()),
            "`path|exists`: the field is absent"
        );
    }

    #[test]
    fn a_cased_field_says_case_matters() {
        assert_eq!(
            reading("channel", &"Security".into(), &["channel"], Lang::En),
            "`channel`: is `Security` (text, compared exactly: case matters)"
        );
        assert_eq!(
            reading("channel|contains", &"Sec".into(), &["channel"], Lang::Th),
            "`channel|contains`: มี `Sec` อยู่ในข้อความ (ข้อความ เทียบตรงทุกตัว ตัวพิมพ์เล็กใหญ่มีผล)"
        );
    }

    #[test]
    fn thai_reads_an_ordinal_with_its_trailing_words() {
        assert_eq!(
            reading("run_count|gte", &2.into(), &[], Lang::Th),
            "`run_count|gte`: ตั้งแต่ `2` ขึ้นไป"
        );
    }

    #[test]
    fn prose_renders_as_the_text_it_was() {
        assert_eq!(prose_line("a *b* [c] <d>"), "a \\*b\\* \\[c\\] \\<d\\>");
        assert_eq!(prose_line("C:\\Users\\"), "C:\\\\Users\\\\");
        assert_eq!(prose_line("- not a list"), "\\- not a list");
        assert_eq!(prose_line("1. not a list"), "1\\. not a list");
        assert_eq!(prose_line("# not a heading"), "\\# not a heading");
        assert_eq!(prose_block("one\ntwo\n\nthree", "  "), "one two\n\n  three");
    }

    #[test]
    fn code_spans_survive_backticks() {
        assert_eq!(code("plain"), "`plain`");
        assert_eq!(code("a`b"), "`` a`b ``");
        assert_eq!(code("two\nlines"), "`two lines`");
    }

    #[test]
    fn untranslated_text_is_marked_on_the_thai_page() {
        let page = render(&bundle(), Lang::Th, &labels(Lang::Th));
        assert!(page.contains("#### Secure Boot ถูกปิดอยู่"), "{page}");
        // The Thai file above translates the title and retention of this rule and nothing else.
        assert!(
            page.contains("**เกี่ยวกับการตรวจนี้** *(แสดงข้อความภาษาอังกฤษ)*"),
            "{page}"
        );
        assert!(page.contains("**ย้อนดูได้**\n\nเป็นค่าที่ตั้งไว้ตอนนี้เท่านั้น"), "{page}");
    }

    /// A directory under the OS temp dir, unique per test, deleted on drop.
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after the epoch")
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "aeterna-rongroi-xtask-rules-reference-{}-{label}-{n}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("create temp root");
            Self(dir)
        }

        fn write(&self, relative: &str, text: &str) {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().expect("path has a parent")).expect("create dirs");
            fs::write(path, text).expect("write file");
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn repository(label: &str) -> TempRoot {
        let tmp = TempRoot::new(label);
        tmp.write(
            "rules/posture/boot/secure-boot-disabled/rule.yaml",
            POSTURE_RULE,
        );
        tmp.write("rules/i18n/th.yaml", THAI_RULES);
        tmp.write(&format!("{LOCALES}/en/report.json"), ENGLISH_LABELS);
        tmp.write(&format!("{LOCALES}/th/report.json"), THAI_LABELS);
        fs::create_dir_all(tmp.0.join("docs")).expect("create docs");
        tmp
    }

    #[test]
    fn written_pages_pass_the_check() {
        let tmp = repository("fresh");
        run(&tmp.0, &Args { check: false }).unwrap();
        run(&tmp.0, &Args { check: true }).unwrap();
        let committed = fs::read_to_string(tmp.0.join("docs/rules-reference.md")).unwrap();
        assert!(committed.contains(&format!("`{COMMAND}`")), "{committed}");
    }

    #[test]
    fn a_rule_change_makes_the_check_fail_and_name_the_command() {
        let tmp = repository("stale");
        run(&tmp.0, &Args { check: false }).unwrap();
        tmp.write(
            "rules/posture/boot/secure-boot-disabled/rule.yaml",
            &POSTURE_RULE.replace("Current setting only.", "Only the current setting."),
        );

        let pages = render_pages(&tmp.0).unwrap();
        let problems = stale_pages(&tmp.0, &pages).unwrap();
        assert_eq!(
            problems,
            vec![
                "docs/rules-reference.md does not match what the rules bundle produces".to_owned(),
                "docs/rules-reference.th.md does not match what the rules bundle produces"
                    .to_owned(),
            ]
        );
        let error = run(&tmp.0, &Args { check: true }).unwrap_err().to_string();
        assert_eq!(
            error,
            "rules-reference: 2 page(s) out of date — run `cargo xtask rules-reference` and commit the result"
        );
    }

    #[test]
    fn a_missing_page_fails_the_check() {
        let tmp = repository("missing");
        let pages = render_pages(&tmp.0).unwrap();
        let problems = stale_pages(&tmp.0, &pages).unwrap();
        assert_eq!(problems[0], "docs/rules-reference.md does not exist");
    }

    #[test]
    fn a_page_checked_out_with_crlf_still_matches() {
        let tmp = repository("crlf");
        run(&tmp.0, &Args { check: false }).unwrap();
        let path = tmp.0.join("docs/rules-reference.md");
        let text = fs::read_to_string(&path).unwrap().replace('\n', "\r\n");
        fs::write(&path, text).unwrap();
        run(&tmp.0, &Args { check: true }).unwrap();
    }

    /// ADR 0048: a CSV directly beside a `rule.yaml` travels with that rule, and a CSV at the top of
    /// `rules/` — `known-fps.csv`, `unconfronted.csv` — beside no rule does not.
    #[test]
    fn the_bundle_carries_the_csv_files_beside_a_rule_and_no_other() {
        let tmp = TempRoot::new("bundle-data");
        tmp.write("posture/memory-integrity/listed/rule.yaml", "id: x\n");
        tmp.write(
            "posture/memory-integrity/listed/states.csv",
            "hvci\r\ndisabled\r\n",
        );
        tmp.write("posture/memory-integrity/listed/notes.txt", "not data\n");
        tmp.write("known-fps.csv", "rule_id\n");

        let json: serde_json::Value =
            serde_json::from_str(&collect_bundle_json(&tmp.0).unwrap()).unwrap();

        let rules = json["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]["data"],
            serde_json::json!({ "states.csv": "hvci\ndisabled\n" })
        );
    }

    /// ADR 0048: a listed condition is read aloud as the file and how many values it holds, never as
    /// the values — 1,847 hashes on the reference page would be a data dump, not rule text.
    #[test]
    fn a_listed_condition_names_its_file_and_row_count() {
        let hash_a = "a".repeat(64);
        let hash_b = "b".repeat(64);
        let json = serde_json::json!({
            "rules": [{
                "path": "driver_service/vulnerable-driver/listed/rule.yaml",
                "yaml": "id: 7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7\ntitle: T\ndescription: D.\nstatus: test\ncollector: driver_service\nstrength: posture\nmatch_lists:\n  sha256: hashes.csv\nretention: Now.\nfalsepositives: [F]\nauthor: tests\ndate: 2026-09-15\n",
                "data": { "hashes.csv": format!("sha256\n{hash_a}\n{hash_b}\n") },
            }],
            "i18n": [],
        })
        .to_string();
        let bundle = rongroi_core::bundle::Bundle::from_bundle_json(&json).unwrap();
        let rule = &bundle.rules()[0].rule;
        let value = rule.matcher["sha256"].clone();

        let en = condition(rule, "sha256", &value, &EN);
        assert!(
            en.contains("the 2 values in the first column of `hashes.csv`"),
            "{en}"
        );
        assert!(!en.contains(&hash_a), "{en}");
        let th = condition(rule, "sha256", &value, &TH);
        assert!(th.contains("2 ค่าในคอลัมน์แรกของ `hashes.csv`"), "{th}");
    }
}
