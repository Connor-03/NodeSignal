# Releasing NodeSignal

A release is three installers and a checksum file, built by
`.github/workflows/release.yml` and attached to a GitHub Release under stable
names, so `releases/latest/download/<asset>` always points at the newest one:

- `NodeSignal-Setup-windows-x64.exe`
- `nodesignal-linux-amd64.deb`
- `nodesignal-linux-arm64.deb`
- `SHA256SUMS.txt`

Only the maintainer publishes a release. Everything below up to step 4 is safe
to do at any time.

## 1. Check the version agrees everywhere

The workflow refuses to publish unless these match (for 1.3.0):

- `package.json` `"version": "1.3.0"`
- `nodesignald.js` `const UA = '/NodeSignal:1.3/'` (major.minor of the release)
- `CHANGELOG.md` has a `## 1.3.0` section. Its body becomes the "What
  changed" part of the release notes.

## 2. Dry run (publishes nothing)

GitHub, in the browser: Actions > Release > Run workflow. Pick the branch,
enter the version (for example `1.3.0`) and leave **Dry run** ticked.

The run builds all three installers, runs every test suite and the Windows
selftest, installs the amd64 .deb, and writes the release notes and
`SHA256SUMS.txt` into an artifact called `release-notes`. It creates no tag and
no release. Read the notes in that artifact before going on.

## 3. Date the CHANGELOG

Change the heading `## 1.3.0 (not yet released)` to the release date, for
example `## 1.3.0 (2026-10-07)`, and merge that to `main`. A real release stops
with an error while the heading still says "not yet released"; a dry run only
warns.

## 4. Publish

Tag the merge commit on `main` and push the tag. Linux or macOS terminal (or
Git Bash on Windows), in an up-to-date clone:

    git checkout main
    git pull
    git tag v1.3.0
    git push origin v1.3.0

The tag push starts the same workflow with publishing on. When it finishes,
the release page lists the four files.

Alternatively, run the workflow by hand as in step 2 with **Dry run**
unticked; it creates the tag at the chosen commit if it does not exist.

## 5. Check the published files

Linux, in an empty folder:

    curl -fLO https://github.com/Connor-03/NodeSignal/releases/latest/download/SHA256SUMS.txt
    curl -fLO https://github.com/Connor-03/NodeSignal/releases/latest/download/nodesignal-linux-amd64.deb
    sha256sum -c SHA256SUMS.txt --ignore-missing

Windows PowerShell, in the download folder:

    Get-FileHash .\NodeSignal-Setup-windows-x64.exe -Algorithm SHA256

Compare the hash with the line in `SHA256SUMS.txt`.

## Not covered by CI

Before calling a release tested, a person should still:

- install the .exe on a real Windows 10 or 11 PC, double-click it normally, and
  check that the administrator refusal, SmartScreen warning, sign-in start and
  firewall prompt behave as WindowsInstallGuide.txt describes;
- install the .deb beside a real bitcoind, restart bitcoind when told to, and
  check `nodesignal status` reports the RPC connected;
- if anyone uses arm64 or router port mapping, try them on real hardware.

None of the binaries is code-signed.
