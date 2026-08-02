# AGENTS.md

## Project overview

PADD (Pi-hole Ad Detection Display) is a terminal dashboard that displays Pi-hole statistics, designed for anything from tiny attached displays up to full-size terminals. It is a single POSIX shell script, `padd.sh`, which reads its data from FTL's `/padd` REST API endpoint.

## Dev environment tips

- **POSIX sh only.** The shebang is `#!/usr/bin/env sh` and the script must run under dash, ash/busybox and other minimal shells. No bashisms: no arrays, no `[[ ]]`, no `${var//}` substitutions.
- Minimal dependencies. PADD runs on very constrained devices; do not add required external tools without good reason.
- All data comes from FTL's API (the `/padd` endpoint). Do not scrape files or invoke `pihole` commands for data; if a statistic is missing, it needs adding to the API in the FTL repository first.
- The layout adapts to terminal size (from mini displays upwards).

## Testing instructions

- There is no automated test suite. Verify changes by running `padd.sh` against a live Pi-hole instance (a Docker container works).
- Test at several terminal sizes; a change that looks fine full-screen can break the small layouts.
- Lint with: `shellcheck -s sh padd.sh`

## PR instructions

- Base all work on the `development` branch; pull requests target `development`.
- Read the [contributors guide](https://docs.pi-hole.net/guides/github/contributing/)
- Every commit must be signed off (DCO): use `git commit -s`.
- Run shellcheck before committing.
- Use Unix line endings (LF).
- Code is licensed under the EUPL 1.2; contributions must be compatible.
- The correct project spelling is "Pi-hole" (capital P, lowercase h, hyphen).

## Common pitfalls

- Introducing bashisms into a POSIX sh script.
- Testing only at one terminal size.
- Forgetting the DCO sign-off on commits.
