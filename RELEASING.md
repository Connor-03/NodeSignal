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

## 0. Once: the release signing key (for in-app updates)

From 1.4, installed copies can update themselves from the console, but only
to a release whose manifest (`nodesignal-release.json`, the installers'
SHA-256 and sizes) is signed with a key listed in `release-keys.json`. A
copy only trusts the keys it shipped with, so the key must be in
`release-keys.json` before the release that should be updatable from.

On your own computer (Linux, macOS or Git Bash on Windows), in a clone:

    node tools/release-key.js new ~/nodesignal-release-key.pem

It writes the private key (mode 0600) and prints one JSON line. Then:

1. Add that line to the `keys` list in `release-keys.json` and commit it.
2. Store the private key as the Actions secret the release workflow reads.
   Same computer, with the GitHub CLI logged in:

       gh secret set NODESIGNAL_RELEASE_SIGNING_KEY < ~/nodesignal-release-key.pem

3. Keep an offline copy of the .pem (a USB stick in a drawer). Losing it
   means adding a new key and one more by-hand install for everyone; a leak
   means rotating it (add the new key in a release, remove the old one in the
   next).

Without the secret, releases still publish an unsigned manifest and installed
copies only announce the new version. Anyone who can run this repository's
workflows with secrets can sign; a GitHub environment with required reviewers
on the publish job narrows that.

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
the release page lists the four files, plus `nodesignal-release.json` and,
when the signing key secret is set, `nodesignal-release.json.sig`. The
workflow checks that signature against `release-keys.json` before uploading.

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
