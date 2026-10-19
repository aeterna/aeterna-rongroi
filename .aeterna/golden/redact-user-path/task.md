In `fixture/redact_user_path.rs`, implement `pub fn redact_user_path(path: &str) -> String`.

It replaces the user name in a Windows user-profile path with `<user>`. A path is changed only when it starts with:

- one ASCII letter, then `:\`;
- then `Users`, matched ASCII-case-insensitively and kept as written;
- then `\`;
- then a non-empty name that ends at the next `\` or at the end of the path.

The name becomes `<user>`. Any name is redacted, including `Public`, and a name may contain non-ASCII characters. Every other byte is unchanged, including the drive letter and the spelling of `Users`.

Every other input is returned unchanged. The cases the tests check are:

- `C:\Users\tester\Documents\notes.txt` becomes `C:\Users\<user>\Documents\notes.txt`.
- `C:\Users\tester` becomes `C:\Users\<user>`, because the name runs to the end of the path.
- `C:\Users\tester\` becomes `C:\Users\<user>\`, because the separator after the name is kept.
- `C:\Users\Public\Desktop` becomes `C:\Users\<user>\Desktop`.
- `D:\Users\ทดสอบ\AppData\Local` becomes `D:\Users\<user>\AppData\Local`.
- `c:\USERS\tester\a` becomes `c:\USERS\<user>\a`.
- Unchanged: `C:\Users` and `C:\Users\`, because the name is missing.
- Unchanged: `C:\Users\\x`, because the name is empty.
- Unchanged: `C:\UsersX\a`, because `Users` must be followed by `\`.
- Unchanged: `C:/Users/tester/a`, because only `\` separates the parts.
- Unchanged: `\\?\C:\Users\tester\a`, because the path must start with a drive letter.
- Unchanged: `1:\Users\tester\a` and `É:\Users\tester\a`, because the drive must be an ASCII letter.

Only edit files under `fixture/`. Do not touch `check/`.
