In `fixture/prefetch_name.rs`, implement `pub fn parse_prefetch_name(file: &str) -> Option<(String, u32)>`.

It reads a Prefetch file name such as `A-1A2B3C4D-0BADF00D.pf` and returns the name part and the hash part. The rules:

- `file` must be a bare file name. If it contains `\` or `/`, return `None`.
- It must end in `.pf`. The extension is matched ASCII-case-insensitively.
- The stem (the file name without `.pf`) is split at its last `-`. The part before that dash is the name, and the part after it is the hash.
- The hash must be exactly 8 ASCII hex digits. Either case is allowed. A `0x` prefix is not allowed.
- The name must be non-empty. It is returned as written, and it may contain non-ASCII characters.
- Anything else returns `None`.

The cases the tests check are:

- `A-1A2B3C4D-0BADF00D.pf` returns `Some(("A-1A2B3C4D", 0x0BADF00D))`.
- `FAKEAPP.EXE-0BADF00D.PF` returns `Some(("FAKEAPP.EXE", 0x0BADF00D))`, because the extension is case-insensitive.
- `x-1a2b3c4d.pf` returns `Some(("x", 0x1a2b3c4d))`, because lowercase hex is accepted.
- `A-B-0000000F.pf` returns `Some(("A-B", 0xF))`, because the stem splits at the last dash.
- `ทดสอบ-FFFFFFFF.pf` returns `Some(("ทดสอบ", 0xFFFF_FFFF))`.
- `A-00000000.pf` returns `Some(("A", 0))`.
- `None` for `C:\Temp\A-1A2B3C4D-0BADF00D.pf` and for `dir/A-1A2B3C4D-0BADF00D.pf`, because the name contains a path separator.
- `None` for `A-1A2B3C4.pf` (7 hex digits), `A-1A2B3C4DE.pf` (9 hex digits), `A-0x12345678.pf` (a `0x` prefix), and `A-1A2B3C4G.pf` (a non-hex character).
- `None` for `-0BADF00D.pf`, because the name is empty.
- `None` for `NODASH.pf` (no dash) and `.pf` (empty stem).
- `None` for `A-1A2B3C4D-0BADF00D.exe`, `A-1A2B3C4D-0BADF00D` (no `.pf`), and `A-1A2B3C4D-0BADF00D.pf.bak`.

Only edit files under `fixture/`. Do not touch `check/`.
