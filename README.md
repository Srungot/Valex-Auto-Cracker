# Valex Patcher (XYLERA)

Minimal patcher for Valex External. You must provide the original, unmodified Valex from the official website.

## Get the original Valex
- Download from: https://valex.io/
- File expected: `Valex_External.exe`

## Usage
- Drag and drop:
  - Drag `Valex_External.exe` onto `xylera.exe`.
  - Output: `patched_Valex_External.exe` next to the input file.
- Command line:
  - `xylera.exe Valex_External.exe`
  - Output: `patched_Valex_External.exe`

## Build (Windows)
- Open a command prompt and run the `builder.bat` script.
- Produces `xylera.exe`.

## Notes
- This tool does not include or redistribute Valex. Always use the genuine file from the official site.
- Patching is done in-place to a copy written as `patched_Valex_External.exe`.

## Disclaimer
- For research/educational purposes only. You are responsible for how you use this tool.

## Changelog
- v2.0.1
  - Code more readable.
  - Added g++ fallback.
  - Added comments to retrive yourself the signatures.
- v1.0.0
  - Initial release.

## Signatures
- `pattern_call` -> `E8 ? ? ? ? 84 C0 0F 85 8D 00 00 00`
- `pattern_version` -> `48 8D 0D ? ? ? ? 48 89 08 48 8D 0D`
- `pattern_jnz` -> `0F 85 8D 00 00 00 48 8D 05`
- `pattern_jnz_before_links` -> `0F 85 0D 01 00 00 48 8D 15`
- `pattern_target_jnz_links` -> `48 8B C8 FF 15 ? ? ? ? 90 C7 44 24 28 05 00 00 00`
- `pattern_debug_range` -> No more ADB into valex
- `pattern_str_ref` -> `48 8D 35 ? ? ? ? 4C 8B CE 0F 14 C1 66 49 0F 7E C0`
- `old_url` -> `https://1cheats.com/store/product/41-Valex-external-key-bypass-lifetime-license/`
- `new_url` -> `https://nizzix.ovh/discord`
- `from_str` -> `VALEX V5`
- `to_str` -> `Cracked`
- `replacement_banner_str` -> `Valex cracked by xylera`
- `neutralize_targets` -> `https://discord.gg/Valex` and `https://extkey.Valex.io/`
- `pattern_avmadb_jnz` -> `84 C0 0F 85`
- `pattern_avmadb_jz` -> `84 C0 0F 84`

[![release](https://img.shields.io/github/v/release/USER/REPO)](https://github.com/USER/REPO/releases)
[![downloads](https://img.shields.io/github/downloads/USER/REPO/total)](https://github.com/USER/REPO/releases)
[![build](https://img.shields.io/github/actions/workflow/status/USER/REPO/auto-release.yml?branch=main)](https://github.com/USER/REPO/actions)
[![discord](https://img.shields.io/discord/YOUR_DISCORD_ID?logo=discord&label=discord)](https://discord.gg/YOUR_INVITE)

## Support
- Discord -> https://nizzix.ovh/discord | <@483948013547683861>
