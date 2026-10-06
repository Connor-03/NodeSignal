// win-resources.js: the Windows version resource and icon of the executable.
// ============================================================================
// Used by packaging/build-sea.js for Windows builds only. It rewrites two
// resources of the copied node.exe, the version information (what Explorer's
// Properties > Details and Task Manager show) and the icon group, and leaves
// every other resource exactly as it was (Node's application manifest).
//
// It must run BEFORE postject injects the SEA blob: postject adds the blob as
// an RCDATA resource named NODE_SEA_BLOB, so editing resources afterwards
// would rewrite the very section that holds the blob. Run first, this step
// leaves postject's work untouched. build-sea.js calls verify() on the
// finished file to prove it: version, icon, Node's manifest and the blob are
// all present.
//
// The editor is resedit (pure JavaScript, MIT, any OS, no wine), fetched at
// BUILD time into the build's scratch folder, pinned to an exact version
// together with its one dependency, pe-library. Like postject it is never
// shipped and never becomes a runtime dependency (package.json "dependencies"
// stays empty): the finished executable contains Node.js and NodeSignal's own
// files, nothing else. npm checks each package against the registry's
// integrity hash; install scripts are disabled.
// ============================================================================
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { pathToFileURL } = require('url');

const RESEDIT = { name: 'resedit', version: '3.1.0' };
const PE_LIBRARY = { name: 'pe-library', version: '2.0.1' };   // resedit's only dependency

const RT_ICON = 3, RT_RCDATA = 10, RT_GROUP_ICON = 14, RT_VERSION = 16;
const SEA_RESOURCE = 'NODE_SEA_BLOB';
const EN_US = 1033, UNICODE = 1200;

function npmCli() {
  const dir = path.dirname(process.execPath);
  return [
    path.join(dir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(dir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ].find((p) => fs.existsSync(p));
}

// Fetch the pinned resedit into <workDir>/resedit and import it.
async function loadResedit(workDir) {
  const dir = path.join(workDir, 'resedit');
  fs.mkdirSync(dir, { recursive: true });
  const specs = [RESEDIT, PE_LIBRARY].map((p) => `${p.name}@${p.version}`);
  const args = ['install', '--prefix', dir, '--no-save', '--no-package-lock', '--ignore-scripts', '--no-audit', '--no-fund', ...specs];
  const cli = npmCli();
  const r = cli
    ? spawnSync(process.execPath, [cli, ...args], { stdio: 'inherit' })
    : spawnSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', args, { stdio: 'inherit', shell: process.platform === 'win32' });
  if (r.status !== 0) throw new Error(`could not fetch ${specs.join(' ')}` + (r.error ? ': ' + r.error.message : ''));
  for (const p of [RESEDIT, PE_LIBRARY]) {
    const got = JSON.parse(fs.readFileSync(path.join(dir, 'node_modules', p.name, 'package.json'), 'utf8')).version;
    if (got !== p.version) throw new Error(`${p.name} ${got} was installed, ${p.version} is pinned`);
  }
  return import(pathToFileURL(path.join(dir, 'node_modules', RESEDIT.name, 'dist', 'index.js')).href);
}

// "1.3.0" or "1.3.0-rc.1" -> [1, 3, 0, 0] for the numeric fields
function numericVersion(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?/.exec(v);
  if (!m) throw new Error(`version "${v}" does not start with x.y.z`);
  const n = [m[1], m[2], m[3], m[4] || '0'].map(Number);
  if (n.some((x) => x > 65535)) throw new Error(`version "${v}" has a part above 65535`);
  return n;
}

// The copyright line and holder, read from LICENSE so they cannot drift.
function licenseHolder(licenseText) {
  const line = (licenseText.match(/^Copyright\b.*$/m) || [])[0];
  if (!line) throw new Error('no Copyright line in LICENSE');
  const holder = line.replace(/^Copyright\s*(\(c\)|©)?\s*[\d\s,-]*/i, '').trim();
  if (!holder) throw new Error('LICENSE has no copyright holder');
  return { line: line.trim(), holder };
}

// The string table. Nothing here is invented: the holder and licence come
// from LICENSE, the version from package.json (or --version), the homepage
// is the repository the releases come from.
function versionStrings({ version, originalFilename, nodeVersion, licenseText, homepage }) {
  const lic = licenseHolder(licenseText);
  return {
    ProductName: 'NodeSignal',
    FileDescription: 'NodeSignal: encrypted chat between Bitcoin node operators',
    CompanyName: lic.holder,
    LegalCopyright: `${lic.line}. MIT License.`,
    ProductVersion: version,
    FileVersion: version,
    OriginalFilename: originalFilename,
    InternalName: 'nodesignal',
    Comments: `Includes Node.js ${nodeVersion} (Copyright Node.js contributors, MIT License). Source: ${homepage}`,
  };
}

const sha = (ab) => crypto.createHash('sha256').update(Buffer.from(ab)).digest('hex');
const key = (e) => `${e.type}/${e.id}/${e.lang}`;

function readResources(R, file) {
  const exe = R.NtExecutable.from(fs.readFileSync(file), { ignoreCert: true });
  return { exe, res: R.NtExecutableResource.from(exe) };
}

// Node.js version recorded in a node.exe's own version resource (so a build
// can refuse a node.exe that does not match the Node making the SEA blob).
function nodeVersionOf(R, file) {
  const { res } = readResources(R, file);
  const vi = R.Resource.VersionInfo.fromEntries(res.entries)[0];
  if (!vi) return null;
  const s = vi.getStringValues(vi.getAllLanguagesForStringValues()[0] || { lang: EN_US, codepage: UNICODE });
  return s.ProductName === 'Node.js' ? s.ProductVersion : null;
}

// Rewrite the version resource and icon of `file` in place. Returns what
// verify() needs: the strings, and a hash of every resource left untouched.
function stamp(R, file, { strings, icoBuffer }) {
  const { exe, res } = readResources(R, file);
  const kept = {};
  for (const e of res.entries) if (![RT_ICON, RT_GROUP_ICON, RT_VERSION].includes(e.type)) kept[key(e)] = sha(e.bin);

  // version: reuse Node's own resource (its language, file type, flags)
  const vi = R.Resource.VersionInfo.fromEntries(res.entries)[0] || R.Resource.VersionInfo.createEmpty();
  const lang = { lang: Number(vi.lang) || EN_US, codepage: UNICODE };
  for (const l of vi.getAllLanguagesForStringValues()) vi.removeAllStringValues(l, true);
  const [a, b, c, d] = numericVersion(strings.FileVersion);
  vi.setFileVersion(a, b, c, d, lang.lang);
  vi.setProductVersion(a, b, c, d, lang.lang);
  vi.setStringValues(lang, strings, true);   // after: the numeric setters wrote "a.b.c.d" strings
  vi.outputToResourceEntries(res.entries);   // replaces Node's entry in place

  // icon: replace Node's icon group in place (same id and language), which
  // also drops Node's icon images
  const group = res.entries.find((e) => e.type === RT_GROUP_ICON) || { id: 1, lang: lang.lang };
  const ico = R.Data.IconFile.from(icoBuffer);
  R.Resource.IconGroupEntry.replaceIconsForResource(res.entries, group.id, group.lang, ico.icons.map((i) => i.data));

  // allowShrink: the smaller section is also shrunk on disk, so its raw data
  // never runs past its virtual size into the next section (.reloc), which
  // made LIEF, inside postject, misread the relocation table
  res.outputResource(exe, false, true);
  fs.writeFileSync(file, Buffer.from(exe.generate()));
  return { strings, kept, iconSizes: ico.icons.map((i) => i.width || 256), iconGroup: { id: group.id, lang: group.lang } };
}

// Problems with the finished executable, [] when all is well.
function verify(R, file, stamped, { seaBlob = true } = {}) {
  const problems = [];
  const { res } = readResources(R, file);
  const vi = R.Resource.VersionInfo.fromEntries(res.entries);
  if (vi.length !== 1) problems.push(`expected one version resource, found ${vi.length}`);
  else {
    const langs = vi[0].getAllLanguagesForStringValues();
    const s = langs.length ? vi[0].getStringValues(langs[0]) : {};
    for (const [k, v] of Object.entries(stamped.strings)) if (s[k] !== v) problems.push(`version string ${k} is ${JSON.stringify(s[k])}, expected ${JSON.stringify(v)}`);
    const [a, b, c, d] = numericVersion(stamped.strings.FileVersion);
    const f = vi[0].fixedInfo;
    if (f.fileVersionMS !== ((a << 16) | b) || f.fileVersionLS !== ((c << 16) | d)) problems.push('numeric file version does not match');
    if (f.productVersionMS !== ((a << 16) | b) || f.productVersionLS !== ((c << 16) | d)) problems.push('numeric product version does not match');
  }
  const groups = R.Resource.IconGroupEntry.fromEntries(res.entries);
  const g = groups.find((x) => x.id === stamped.iconGroup.id && x.lang === stamped.iconGroup.lang);
  if (!g) problems.push('the icon group is missing');
  else {
    const sizes = g.icons.map((i) => i.width || 256);
    if (sizes.join() !== stamped.iconSizes.join()) problems.push(`icon sizes are ${sizes.join(',')}, expected ${stamped.iconSizes.join(',')}`);
    for (const i of g.icons) if (!res.entries.some((e) => e.type === RT_ICON && e.id === i.iconID)) problems.push(`icon image ${i.iconID} is missing`);
  }
  const now = {};
  for (const e of res.entries) now[key(e)] = sha(e.bin);
  for (const [k, h] of Object.entries(stamped.kept)) {
    if (!(k in now)) problems.push(`resource ${k} from node.exe is missing`);
    else if (now[k] !== h) problems.push(`resource ${k} from node.exe changed`);
  }
  if (seaBlob && !res.entries.some((e) => e.type === RT_RCDATA && e.id === SEA_RESOURCE)) problems.push(`the ${SEA_RESOURCE} resource is missing`);
  return problems;
}

module.exports = { RESEDIT, PE_LIBRARY, loadResedit, numericVersion, licenseHolder, versionStrings, nodeVersionOf, stamp, verify };
