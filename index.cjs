// Verify Node.js supply-chain compliance against the BCC "Securing the supply
// chain in the JavaScript ecosystem" guideline.
//
// Discovers Node.js projects from:
//   1. Files       - package.json, lock-files, .npmrc, pnpm-workspace.yaml.
//   2. Workflows   - `run:` steps in .github/workflows/** and composite action.yml.
//   3. Dockerfiles - RUN instructions.
//   4. Scripts     - shell/PowerShell scripts invoked (transitively) from any of
//                    the above, plus local `uses: ./...` composite actions.
//
// Paths in workflows, Dockerfiles and scripts are used as written, relative to
// the workspace. Checkouts of *other* repositories are reported as not scanned
// rather than silently verified.
//
// Zero external dependencies on purpose: this keeps the action itself from being
// a Node.js project that would need its own lock-file / .npmrc to stay compliant.

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = process.env.GITHUB_WORKSPACE || process.cwd();
const posix = path.posix;
const MINUTES_PER_DAY = 1440;

// ---------------------------------------------------------------------------
// Policy - the single source of truth for every requirement.
// `releaseAgeDays` is the only caller-tunable value and can only be raised.
// ---------------------------------------------------------------------------

const MIN_RELEASE_AGE_DAYS = 7;

function buildPolicy(releaseAgeDays) {
  return {
    releaseAgeDays,
    npm: {
      engineMin: '11.10.0',
      lockfiles: ['package-lock.json', 'npm-shrinkwrap.json'],
      npmrc: {
        'engine-strict': { equals: 'true' },
        'allow-git': { equals: 'root' },
        'allow-remote': { equals: 'root' },
        'min-release-age': { atLeast: releaseAgeDays },
        'ignore-scripts': { equals: 'true' },
      },
    },
    pnpm: {
      engineMin: '11.0.0',
      engineNpm: 'disallow',
      lockfiles: ['pnpm-lock.yaml'],
      npmrc: {
        'engine-strict': { equals: 'true' },
      },
      workspace: {
        pmOnFail: { equals: 'error' },
        packageManagerStrictVersion: { equals: 'true' },
        minimumReleaseAge: { atLeast: releaseAgeDays * MINUTES_PER_DAY },
        minimumReleaseAgeStrict: { equals: 'true' },
        trustPolicy: { equals: 'no-downgrade' },
        blockExoticSubdeps: { equals: 'true' },
        strictDepBuilds: { equals: 'true' },
      },
    },
    disallowedManagers: ['yarn', 'bun'],
  };
}

const PROJECT_MARKERS = new Set([
  'package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml',
  'yarn.lock', 'bun.lockb', 'bun.lock', '.npmrc', 'pnpm-workspace.yaml',
]);

const IGNORE_DIRS = new Set([
  '.git', 'node_modules', '.terraform', 'dist', 'build', 'out', '.next',
  '.nuxt', 'coverage', '.cache', 'vendor', 'tmp', '.venv', '__pycache__',
  '.pnpm-store', '.yarn',
]);

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const abs = (rel) => path.join(ROOT, rel);

function readText(rel) {
  try {
    return fs.readFileSync(abs(rel), 'utf8');
  } catch {
    return null;
  }
}

function exists(rel) {
  try {
    return fs.existsSync(abs(rel));
  } catch {
    return false;
  }
}

function dirOf(rel) {
  const d = posix.dirname(rel);
  return d === '' ? '.' : d;
}

function joinDir(dir, name) {
  return dir === '.' ? name : `${dir}/${name}`;
}

function ancestors(dir) {
  const out = [];
  let cur = dir;
  while (cur !== '.' && cur !== '' && cur !== '/') {
    const parent = posix.dirname(cur);
    out.push(parent === '' ? '.' : parent);
    if (parent === cur) break;
    cur = parent;
  }
  return out;
}

function unquote(v) {
  return v.replace(/^["']|["']$/g, '');
}

function isFile(rel) {
  try {
    return fs.statSync(abs(rel)).isFile();
  } catch {
    return false;
  }
}

// Normalises a path as written, resolved against `base`.
function normalizeDir(value, base = '.') {
  let raw = String(value).trim().replace(/^["']|["']$/g, '').replace(/\\/g, '/');
  raw = raw.replace(/\$\{\{[^}]*\}\}/g, '').replace(/\$[A-Za-z_][\w]*/g, '');
  if (!raw) return base;
  const joined = raw.startsWith('/') || base === '.' ? raw : `${base}/${raw}`;
  const resolved = posix.normalize(joined);
  if (resolved === '.' || resolved === './') return '.';
  return resolved.replace(/\/+$/, '') || '.';
}

function parseVersion(value) {
  const m = String(value).match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  return m ? [Number(m[1]), Number(m[2] || 0), Number(m[3] || 0)] : null;
}

function cmpVersion(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

// Lower bound guaranteed by a single comparator, or null when it guarantees none.
function comparatorLowerBound(comparator) {
  const token = comparator.trim();
  if (!token || /^(\*|x|X|latest)$/.test(token)) return null;
  const m = token.match(/^(>=|<=|>|<|\^|~|=|v)?\s*v?(\d+(?:\.\d+){0,2})/);
  if (!m) return null;
  if (m[1] === '<' || m[1] === '<=') return null; // upper bound only
  return parseVersion(m[2]);
}

// True only when every branch of the range guarantees at least `minimum`.
function guaranteesMinimum(range, minimum) {
  if (typeof range !== 'string' || !range.trim()) return false;
  const min = parseVersion(minimum);
  if (!min) return false;

  for (const alternative of range.split('||')) {
    // A hyphen range's floor is its left-hand side.
    const hyphen = alternative.match(/^\s*(\S+)\s+-\s+\S+\s*$/);
    const comparators = hyphen ? [hyphen[1]] : alternative.trim().split(/\s+/);

    let best = null;
    for (const comparator of comparators) {
      const bound = comparatorLowerBound(comparator);
      if (bound && (!best || cmpVersion(bound, best) > 0)) best = bound;
    }
    if (!best || cmpVersion(best, min) < 0) return false;
  }
  return true;
}

function meetsRequirement(actual, requirement) {
  if (actual == null) return false;
  if (requirement.equals !== undefined) {
    return String(actual).trim().toLowerCase() === String(requirement.equals).toLowerCase();
  }
  const parsed = Number(String(actual).trim());
  return Number.isFinite(parsed) && parsed >= requirement.atLeast;
}

function describeRequirement(requirement) {
  return requirement.equals !== undefined ? requirement.equals : `${requirement.atLeast} (minimum)`;
}

function lineOfMatch(text, regex) {
  if (!text) return undefined;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (regex.test(lines[i])) return i + 1;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Config-file parsers (tolerant, no dependencies)
// ---------------------------------------------------------------------------

function parseNpmrc(text) {
  const map = {};
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    line = line.replace(/\s+[#;].*$/, ''); // strip inline comment
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim().toLowerCase();
    const value = unquote(line.slice(eq + 1).trim());
    map[key] = value;
  }
  return map;
}

// Reads only the top-level scalar keys, which is all the guideline requires.
function parseTopLevelYamlScalars(text) {
  const map = {};
  for (const raw of text.split(/\r?\n/)) {
    if (/^\s/.test(raw) || raw.trim().startsWith('#')) continue;
    const line = raw.replace(/\s+#.*$/, '');
    const m = line.match(/^([A-Za-z0-9_.-]+):\s*(.*)$/);
    if (m && m[2].trim() !== '') map[m[1]] = unquote(m[2].trim());
  }
  return map;
}

function parseJsonSafe(text) {
  try {
    return { value: JSON.parse(text), error: null };
  } catch (err) {
    return { value: null, error: err.message };
  }
}

// ---------------------------------------------------------------------------
// GitHub Actions output helpers
// ---------------------------------------------------------------------------

function escapeData(s) {
  return String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function escapeProp(s) {
  return String(s)
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A')
    .replace(/:/g, '%3A')
    .replace(/,/g, '%2C');
}

function annotate(level, message, props = {}) {
  const rendered = Object.entries(props)
    .filter(([, v]) => v !== undefined && v !== '')
    .map(([k, v]) => `${k}=${escapeProp(v)}`)
    .join(',');
  console.log(`::${level}${rendered ? ' ' + rendered : ''}::${escapeData(message)}`);
}

function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return;
  const delimiter = `ghadelimiter_${Math.random().toString(36).slice(2)}`;
  fs.appendFileSync(file, `${name}<<${delimiter}\n${value}\n${delimiter}\n`);
}

function writeSummary(markdown) {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (!file) return;
  fs.appendFileSync(file, markdown + '\n');
}

function getInput(name, fallback) {
  const key = 'INPUT_' + name.replace(/[ -]/g, '_').toUpperCase();
  const raw = process.env[key];
  return raw === undefined || raw.trim() === '' ? fallback : raw.trim();
}

function readReleaseAgeDays(notes) {
  const raw = getInput('release-age-days', String(MIN_RELEASE_AGE_DAYS));
  const parsed = Number(raw);
  if (!Number.isInteger(parsed)) {
    notes.push(`"release-age-days" is not an integer ("${raw}"); using ${MIN_RELEASE_AGE_DAYS}.`);
    return MIN_RELEASE_AGE_DAYS;
  }
  if (parsed < MIN_RELEASE_AGE_DAYS) {
    notes.push(`"release-age-days" (${parsed}) is below the mandatory minimum; using ${MIN_RELEASE_AGE_DAYS}.`);
    return MIN_RELEASE_AGE_DAYS;
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

function collectFiles(roots) {
  const seen = new Set();
  const files = [];
  const stack = [...roots];
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(abs(cur), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const rel = cur === '.' ? entry.name : `${cur}/${entry.name}`;
      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name)) continue;
        stack.push(rel);
      } else if (entry.isFile() && !seen.has(rel)) {
        seen.add(rel);
        files.push(rel);
      }
    }
  }
  return files;
}

function isWorkflowFile(rel) {
  return /^\.github\/workflows\/[^/]+\.ya?ml$/.test(rel);
}

function isActionFile(rel) {
  return /(^|\/)action\.ya?ml$/.test(rel);
}

function isDockerfile(rel) {
  const name = posix.basename(rel);
  return /^(?:Dockerfile|Containerfile)(?:\..+)?$/i.test(name)
    || /\.(?:Dockerfile|Containerfile)$/i.test(name);
}

// ---------------------------------------------------------------------------
// Shell command analysis
// ---------------------------------------------------------------------------

const GLOBAL_FLAG = /(?:^|\s)(?:-g|--global)(?:\s|$)/;

const INSTALLING_SUBCOMMANDS = new Set([
  'install', 'i', 'ci', 'add', 'update', 'up', 'fetch', 'import', 'rebuild', 'dedupe',
]);

const SCRIPT_INVOCATION_PATTERNS = [
  /(?:^|\s)(?:bash|sh|zsh|dash)\s+(?:-\S+\s+)*(\S+\.(?:sh|bash|zsh))/,
  /(?:^|\s)(?:pwsh|powershell)\s+(?:-\S+\s+)*(?:-(?:File|f)\s+)?(\S+\.ps1)/i,
  /(?:^|\s)(\.{1,2}\/\S+\.(?:sh|bash|zsh|ps1))/,
  /(?:^|\s)(\.{1,2}\/[\w./-]+)(?:\s|$)/,
];

function splitSegments(line) {
  return line.split(/&&|\|\||[;|]/).map((s) => s.trim()).filter(Boolean);
}

// Strips leading `VAR=value` assignments, reporting whether CI=true was among them.
function stripEnvPrefix(segment) {
  let rest = segment;
  let ci = false;
  for (;;) {
    const m = rest.match(/^([A-Za-z_][\w]*)=(\S*)\s+/);
    if (!m) break;
    if (m[1] === 'CI' && /^["']?true["']?$/i.test(m[2])) ci = true;
    rest = rest.slice(m[0].length);
  }
  return { rest, ci };
}

function detectSegmentManager(segment) {
  if (/^yarn\b/.test(segment)) return 'yarn';
  if (/^bunx?\b/.test(segment)) return 'bun';
  if (/^(?:pnpm|pnpx)\b/.test(segment)) return 'pnpm';
  if (/^(?:npm|npx)\b/.test(segment)) return 'npm';
  return null;
}

function directoryOverride(segment, currentDir) {
  const npmPrefix = segment.match(/--prefix(?:=|\s+)(\S+)/);
  if (npmPrefix) return normalizeDir(npmPrefix[1], currentDir);
  const pnpmDir = segment.match(/(?:--dir|-C)(?:=|\s+)(\S+)/);
  if (pnpmDir) return normalizeDir(pnpmDir[1], currentDir);
  return currentDir;
}

function findScriptReference(segment, currentDir) {
  for (const pattern of SCRIPT_INVOCATION_PATTERNS) {
    const m = segment.match(pattern);
    if (!m) continue;
    const target = normalizeDir(m[1], currentDir);
    if (target && isFile(target)) return target;
  }
  return null;
}

// Walks one shell line, carrying `cd` and CI state forward across segments.
function analyzeShellLine(line, state, context, sink) {
  for (const rawSegment of splitSegments(line)) {
    const { rest: segment, ci: inlineCi } = stripEnvPrefix(rawSegment);
    if (!segment) continue;

    if (/^export\s+CI=["']?true["']?/i.test(segment)) {
      state.ci = true;
      continue;
    }

    const cd = segment.match(/^cd\s+(\S+)/);
    if (cd) {
      const target = normalizeDir(cd[1], state.dir);
      if (target) state.dir = target;
      continue;
    }

    const script = findScriptReference(segment, state.dir);
    if (script) sink.references.push({ file: script, dir: state.dir });

    const manager = detectSegmentManager(segment);
    if (!manager) continue;

    let subcommand = null;
    if (manager === 'npm' || manager === 'pnpm') {
      const normalized = segment.replace(/^npx\b/, 'npm exec').replace(/^pnpx\b/, 'pnpm dlx');
      const m = normalized.match(/^(?:npm|pnpm)\s+((?:-{1,2}[\w-]+(?:=\S+)?\s+)*)([a-zA-Z][\w-]*)?/);
      subcommand = m && m[2] ? m[2].toLowerCase() : null;
    }

    sink.usages.push({
      source: context.source,
      file: context.file,
      line: context.line,
      dir: directoryOverride(segment, state.dir) || state.dir,
      manager,
      subcommand,
      global: GLOBAL_FLAG.test(segment),
      ci: state.ci || inlineCi,
      text: rawSegment,
    });
  }
}

// ---------------------------------------------------------------------------
// Checkouts of other repositories
//
// Their contents are not part of this repository, so they cannot be verified
// here and are reported as unscanned instead.
// ---------------------------------------------------------------------------

const CHECKOUT_USES = /uses:\s*["']?[\w.-]+\/checkout@/;

function isCurrentRepository(value) {
  if (value == null) return true;
  const raw = value.replace(/\s+#.*$/, '').trim().replace(/^["']|["']$/g, '');
  if (!raw) return true;
  if (/\$\{\{\s*github\.repository\s*\}\}/.test(raw)) return true;
  if (raw.includes('${{')) return false; // unresolvable expression
  const current = process.env.GITHUB_REPOSITORY;
  return current ? raw.toLowerCase() === current.toLowerCase() : false;
}

function collectExternalCheckouts(rel, lines, stepStart) {
  const external = [];
  let current = null;
  const flush = () => {
    if (current && current.isCheckout && !isCurrentRepository(current.repository)) {
      external.push({
        file: rel,
        line: current.line,
        repository: current.repository.replace(/\s+#.*$/, '').trim().replace(/^["']|["']$/g, ''),
        path: current.path ? current.path.replace(/\s+#.*$/, '').trim().replace(/^["']|["']$/g, '') : null,
      });
    }
    current = null;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (current && line.trim() && indentOf(line) <= current.indent && !stepStart.test(line)) flush();
    if (stepStart.test(line)) {
      flush();
      current = { indent: indentOf(line), isCheckout: false, path: null, repository: null, line: i + 1 };
    }
    if (!current) continue;

    if (CHECKOUT_USES.test(line)) {
      current.isCheckout = true;
      current.line = i + 1;
    }
    const p = line.match(/^\s*path:\s*(.+?)\s*$/);
    if (p) current.path = p[1];
    const r = line.match(/^\s*repository:\s*(.+?)\s*$/);
    if (r) current.repository = r[1];
  }
  flush();

  return external;
}

// ---------------------------------------------------------------------------
// File scanners
// ---------------------------------------------------------------------------

const indentOf = (line) => line.match(/^\s*/)[0].length;

// Linear pass that tracks job-level `env: CI: true` and per-step context.
function scanYamlFile(rel, text, source, sink) {
  const lines = text.split(/\r?\n/);
  const stepStart = /^(\s*)-\s+(?:name|uses|run|id|if|env|with|shell|working-directory|continue-on-error|timeout-minutes):/;

  sink.externalCheckouts.push(...collectExternalCheckouts(rel, lines, stepStart));

  let jobCi = false;
  let step = null;
  let runState = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (/^ {2}[A-Za-z_][\w-]*:\s*$/.test(line)) jobCi = false; // new job block

    if (step && line.trim() && indentOf(line) <= step.indent && !stepStart.test(line)) {
      step = null;
      runState = null;
    }

    if (stepStart.test(line)) {
      step = { indent: indentOf(line), dir: '.', ci: jobCi };
      runState = null;
    }

    if (/^\s*CI:\s*["']?true["']?\s*(#.*)?$/.test(line)) {
      if (step) step.ci = true;
      else jobCi = true;
      continue;
    }

    const workingDirectory = line.match(/^\s*-?\s*working-directory:\s*(.+?)\s*$/);
    if (workingDirectory && step) {
      const resolved = normalizeDir(workingDirectory[1].replace(/\s+#.*$/, ''));
      if (resolved) step.dir = resolved;
      continue;
    }

    const localAction = line.match(/^\s*-?\s*uses:\s*["']?(\.{1,2}\/[^\s"'#]+)/);
    if (localAction) {
      const target = normalizeDir(localAction[1]);
      for (const candidate of ['action.yml', 'action.yaml']) {
        if (target && isFile(joinDir(target, candidate))) {
          sink.references.push({ file: joinDir(target, candidate), dir: target });
        }
      }
      continue;
    }

    if (/^\s*-?\s*run:\s*/.test(line)) {
      runState = { dir: step ? step.dir : '.', ci: step ? step.ci : jobCi };
      const inline = line.replace(/^\s*-?\s*run:\s*/, '').replace(/^[|>][-+]?\s*$/, '');
      if (inline.trim()) analyzeShellLine(inline, runState, { source, file: rel, line: i + 1 }, sink);
      continue;
    }

    if (runState && line.trim() && !/^\s*[A-Za-z_-]+:\s/.test(line)) {
      analyzeShellLine(line, runState, { source, file: rel, line: i + 1 }, sink);
    }
  }
}

function scanDockerfile(rel, text, sink) {
  const baseDir = dirOf(rel);
  const rawLines = text.split(/\r?\n/);

  // Merge backslash line continuations into logical lines while keeping the
  // starting line number for annotations.
  const logical = [];
  let buffer = '';
  let startLine = 0;
  for (let i = 0; i < rawLines.length; i++) {
    const line = rawLines[i];
    if (buffer === '') startLine = i + 1;
    if (/\\\s*$/.test(line)) {
      buffer += line.replace(/\\\s*$/, ' ');
    } else {
      logical.push({ text: buffer + line, line: startLine });
      buffer = '';
    }
  }
  if (buffer) logical.push({ text: buffer, line: startLine });

  const state = { dir: baseDir, ci: false };
  const meta = { file: rel, npmLockCopied: false, pnpmLockCopied: false, usesNpm: false, usesPnpm: false };

  for (const { text: line, line: lineNo } of logical) {
    if (/^\s*(?:ENV|ARG)\s+CI[=\s]+["']?true["']?/i.test(line)) {
      state.ci = true;
      continue;
    }
    const workdir = line.match(/^\s*WORKDIR\s+(\S+)/i);
    if (workdir) {
      const resolved = normalizeDir(workdir[1].replace(/^\//, ''), baseDir);
      if (resolved) state.dir = resolved;
      continue;
    }
    if (/^\s*COPY\b/i.test(line)) {
      if (/(package-lock\.json|npm-shrinkwrap\.json|package\*\.json|\s\.\s+\.)/i.test(line)) meta.npmLockCopied = true;
      if (/(pnpm-lock\.yaml|\s\.\s+\.)/i.test(line)) meta.pnpmLockCopied = true;
      continue;
    }
    if (!/^\s*RUN\b/i.test(line)) continue;

    const before = sink.usages.length;
    analyzeShellLine(line.replace(/^\s*RUN\s+/i, ''), state, { source: 'dockerfile', file: rel, line: lineNo }, sink);
    for (const usage of sink.usages.slice(before)) {
      if (usage.manager === 'npm') meta.usesNpm = true;
      if (usage.manager === 'pnpm') meta.usesPnpm = true;
    }
  }

  sink.dockerMeta.set(baseDir, meta);
}

function scanScript(rel, text, baseDir, sink) {
  const state = { dir: baseDir, ci: false };
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#')) continue;
    analyzeShellLine(line, state, { source: 'script', file: rel, line: i + 1 }, sink);
  }
}

// Scans CI entry points, then follows the scripts and local actions they invoke.
function discover(files) {
  const sink = { usages: [], references: [], dockerMeta: new Map(), externalCheckouts: [] };
  const scanned = new Set();
  const queue = [];

  for (const rel of files) {
    if (isWorkflowFile(rel)) queue.push({ file: rel, kind: 'workflow', dir: '.' });
    else if (isActionFile(rel)) queue.push({ file: rel, kind: 'action', dir: '.' });
    else if (isDockerfile(rel)) queue.push({ file: rel, kind: 'dockerfile', dir: dirOf(rel) });
  }

  while (queue.length) {
    const item = queue.shift();
    if (scanned.has(item.file)) continue;
    scanned.add(item.file);

    const text = readText(item.file);
    if (text == null) continue;

    const before = sink.references.length;
    if (item.kind === 'dockerfile') scanDockerfile(item.file, text, sink);
    else if (item.kind === 'script') scanScript(item.file, text, item.dir, sink);
    else scanYamlFile(item.file, text, item.kind, sink);

    for (const reference of sink.references.slice(before)) {
      if (scanned.has(reference.file)) continue;
      const kind = isActionFile(reference.file) ? 'action'
        : isDockerfile(reference.file) ? 'dockerfile'
          : 'script';
      queue.push({ file: reference.file, kind, dir: reference.dir });
    }
  }

  return sink;
}

// ---------------------------------------------------------------------------
// Project model + verification
// ---------------------------------------------------------------------------

function getProject(projects, dir) {
  if (!projects.has(dir)) {
    projects.set(dir, {
      dir,
      evidence: new Set(),
      manager: null,
      hasPackageJson: false,
      isWorkspaceMember: false,
      workspaceRoot: null,
      violations: [], // { title, message, file, line }
      warnings: [], // { title, message, file, line }
    });
  }
  return projects.get(dir);
}

// Nearest ancestor (inclusive) that actually looks like a project root.
function nearestProjectDir(startDir, projectDirs) {
  if (projectDirs.has(startDir)) return startDir;
  for (const anc of ancestors(startDir)) {
    if (projectDirs.has(anc)) return anc;
  }
  return null;
}

function addViolation(project, v) {
  project.violations.push(v);
}

function addWarning(project, w) {
  project.warnings.push(w);
}

function detectPackageManager(project, pkg) {
  const dir = project.dir;
  const engines = (pkg && pkg.engines) || {};
  const declared = typeof (pkg && pkg.packageManager) === 'string'
    ? pkg.packageManager.split('@')[0]
    : '';

  const pnpmSignal =
    exists(joinDir(dir, 'pnpm-lock.yaml')) ||
    exists(joinDir(dir, 'pnpm-workspace.yaml')) ||
    declared === 'pnpm' ||
    engines.pnpm != null;
  const npmSignal =
    exists(joinDir(dir, 'package-lock.json')) ||
    exists(joinDir(dir, 'npm-shrinkwrap.json')) ||
    declared === 'npm' ||
    (engines.npm != null && String(engines.npm).toLowerCase() !== 'disallow');
  const yarnSignal = exists(joinDir(dir, 'yarn.lock')) || declared === 'yarn';
  const bunSignal = exists(joinDir(dir, 'bun.lockb')) || exists(joinDir(dir, 'bun.lock')) || declared === 'bun';

  if (pnpmSignal) return 'pnpm';
  if (yarnSignal) return 'yarn';
  if (bunSignal) return 'bun';
  if (npmSignal) return 'npm';
  return null;
}

function checkNpmrc(project, requirements) {
  const dir = project.dir;
  const rel = joinDir(dir, '.npmrc');
  const text = readText(rel);
  if (text == null) {
    addViolation(project, {
      title: 'Missing .npmrc',
      message: `Missing .npmrc in "${dir}". It must sit next to package.json with the required supply-chain settings.`,
      file: joinDir(dir, 'package.json'),
    });
    return;
  }
  const config = parseNpmrc(text);
  for (const [key, requirement] of Object.entries(requirements)) {
    const actual = config[key];
    if (meetsRequirement(actual, requirement)) continue;
    addViolation(project, {
      title: `.npmrc "${key}"`,
      message: actual == null
        ? `.npmrc in "${dir}" is missing "${key}=${describeRequirement(requirement)}".`
        : `.npmrc in "${dir}" has "${key}=${actual}" but requires "${key}=${describeRequirement(requirement)}".`,
      file: rel,
      line: lineOfMatch(text, new RegExp('^\\s*' + key.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&') + '\\s*=', 'i')),
    });
  }
}

function checkLockfile(project, managerPolicy, label) {
  if (managerPolicy.lockfiles.some((name) => exists(joinDir(project.dir, name)))) return;
  addViolation(project, {
    title: `Missing ${label} lock-file`,
    message: `"${project.dir}" must commit ${managerPolicy.lockfiles.join(' or ')}.`,
    file: joinDir(project.dir, 'package.json'),
  });
}

function checkNpmProject(project, pkg, pkgText, policy) {
  const engines = (pkg && pkg.engines) || {};
  checkLockfile(project, policy.npm, 'npm');

  if (!guaranteesMinimum(engines.npm, policy.npm.engineMin)) {
    addViolation(project, {
      title: 'engines.npm',
      message: `package.json in "${project.dir}" must guarantee npm >=${policy.npm.engineMin} (found ${engines.npm == null ? 'nothing' : `"${engines.npm}"`}).`,
      file: joinDir(project.dir, 'package.json'),
      line: lineOfMatch(pkgText, /"npm"\s*:/),
    });
  }

  checkNpmrc(project, policy.npm.npmrc);
}

function checkPnpmProject(project, pkg, pkgText, policy) {
  const dir = project.dir;
  const engines = (pkg && pkg.engines) || {};
  checkLockfile(project, policy.pnpm, 'pnpm');

  if (String(engines.npm).toLowerCase() !== policy.pnpm.engineNpm) {
    addViolation(project, {
      title: 'engines.npm',
      message: `package.json in "${dir}" must set engines.npm to "${policy.pnpm.engineNpm}" when using pnpm to prevent npm from running with an unsafe default configuration (found ${engines.npm == null ? 'nothing' : `"${engines.npm}"`}).`,
      file: joinDir(dir, 'package.json'),
      line: lineOfMatch(pkgText, /"npm"\s*:/),
    });
  }
  if (!guaranteesMinimum(engines.pnpm, policy.pnpm.engineMin)) {
    addViolation(project, {
      title: 'engines.pnpm',
      message: `package.json in "${dir}" must guarantee pnpm >=${policy.pnpm.engineMin} (found ${engines.pnpm == null ? 'nothing' : `"${engines.pnpm}"`}).`,
      file: joinDir(dir, 'package.json'),
      line: lineOfMatch(pkgText, /"pnpm"\s*:/),
    });
  }

  checkNpmrc(project, policy.pnpm.npmrc);

  const wsRel = joinDir(dir, 'pnpm-workspace.yaml');
  const wsText = readText(wsRel);
  if (wsText == null) {
    addViolation(project, {
      title: 'Missing pnpm-workspace.yaml',
      message: `Missing pnpm-workspace.yaml in "${dir}" with the required supply-chain settings.`,
      file: joinDir(dir, 'package.json'),
    });
    return;
  }

  const workspace = parseTopLevelYamlScalars(wsText);
  for (const [key, requirement] of Object.entries(policy.pnpm.workspace)) {
    const actual = workspace[key];
    if (meetsRequirement(actual, requirement)) continue;
    addViolation(project, {
      title: `pnpm-workspace.yaml "${key}"`,
      message: actual == null
        ? `pnpm-workspace.yaml in "${dir}" is missing "${key}: ${describeRequirement(requirement)}".`
        : `pnpm-workspace.yaml in "${dir}" has "${key}: ${actual}" but requires "${key}: ${describeRequirement(requirement)}".`,
      file: wsRel,
      line: lineOfMatch(wsText, new RegExp('^\\s*' + key + '\\s*:')),
    });
  }
}

function checkLockfileConflicts(project) {
  const dir = project.dir;
  for (const [name, manager] of [['yarn.lock', 'yarn'], ['bun.lockb', 'bun'], ['bun.lock', 'bun']]) {
    if (!exists(joinDir(dir, name))) continue;
    addViolation(project, {
      title: `Disallowed package manager (${manager})`,
      message: `${manager} is not permitted (${name} present in "${dir}"). Use pnpm (preferred) or npm.`,
      file: joinDir(dir, name),
    });
  }
  if (project.manager === 'pnpm' && exists(joinDir(dir, 'package-lock.json'))) {
    addViolation(project, {
      title: 'npm used where pnpm is configured',
      message: `"${dir}" is a pnpm project but a package-lock.json is present. Remove it; npm must not be used where pnpm is configured.`,
      file: joinDir(dir, 'package-lock.json'),
    });
  }
}

function checkCommandUsages(project, usages, policy) {
  for (const u of usages) {
    const where = `${u.source} (${u.file})`;

    if (policy.disallowedManagers.includes(u.manager)) {
      addViolation(project, {
        title: `Disallowed package manager (${u.manager})`,
        message: `${where} runs "${u.text}". Only pnpm (preferred) or npm are permitted.`,
        file: u.file,
        line: u.line,
      });
      continue;
    }

    if (u.global) {
      addWarning(project, {
        title: 'Global install not recommended',
        message: `${where} runs a global install ("${u.text}"). Global tool installs bypass the lock-file and the project's .npmrc, so they are not recommended. Prefer a pinned devDependency invoked via "${u.manager === 'pnpm' ? 'pnpm exec' : 'npx --no-install'}", or a SHA-pinned action.`,
        file: u.file,
        line: u.line,
      });
      continue;
    }

    if (project.manager === 'pnpm' && u.manager === 'npm' && INSTALLING_SUBCOMMANDS.has(u.subcommand)) {
      addViolation(project, {
        title: 'npm used where pnpm is configured',
        message: `${where} runs "${u.text}" in a pnpm project ("${u.dir}"). Use pnpm instead.`,
        file: u.file,
        line: u.line,
      });
      continue;
    }

    if (u.manager === 'npm' && (u.subcommand === 'install' || u.subcommand === 'i')) {
      addViolation(project, {
        title: 'Use "npm ci"',
        message: `${where} runs "${u.text}". Use "npm ci" in CI environments and container build flows.`,
        file: u.file,
        line: u.line,
      });
    }

    if (u.manager === 'pnpm' && INSTALLING_SUBCOMMANDS.has(u.subcommand) && !u.ci) {
      addViolation(project, {
        title: 'Missing CI=true for pnpm',
        message: `${where} runs "${u.text}" without CI=true. Set "env: CI: true" for pnpm in CI environments and container build flows.`,
        file: u.file,
        line: u.line,
      });
    }
  }
}

function checkDockerLockfileCopy(project, dockerMeta) {
  const meta = dockerMeta.get(project.dir);
  if (!meta) return;
  if (meta.usesNpm && project.manager !== 'pnpm' && !meta.npmLockCopied) {
    addViolation(project, {
      title: 'Lock-file not added to container build',
      message: `${meta.file} installs with npm but does not COPY package-lock.json into the image. Lock-files must be added to container builds.`,
      file: meta.file,
    });
  }
  if (meta.usesPnpm && !meta.pnpmLockCopied) {
    addViolation(project, {
      title: 'Lock-file not added to container build',
      message: `${meta.file} installs with pnpm but does not COPY pnpm-lock.yaml into the image. Lock-files must be added to container builds.`,
      file: meta.file,
    });
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const notes = [];
  const policy = buildPolicy(readReleaseAgeDays(notes));
  const failOnViolation = getInput('fail-on-violation', 'true').toLowerCase() !== 'false';

  const roots = getInput('paths', '.').split(/[\s,]+/).map((r) => normalizeDir(r)).filter(Boolean);
  const files = collectFiles(roots.length ? roots : ['.']);

  const projects = new Map();
  const workspaceRoots = new Set();

  // 1. File-based discovery.
  for (const rel of files) {
    const name = posix.basename(rel);
    if (!PROJECT_MARKERS.has(name)) continue;
    const project = getProject(projects, dirOf(rel));
    project.evidence.add(name);
    if (name === 'package.json') project.hasPackageJson = true;
    if (name === 'pnpm-workspace.yaml') workspaceRoots.add(dirOf(rel));
  }

  // Detect npm/pnpm workspace roots (so members are not falsely flagged).
  for (const project of projects.values()) {
    if (!project.hasPackageJson) continue;
    const { value } = parseJsonSafe(readText(joinDir(project.dir, 'package.json')) || '');
    if (value && value.workspaces) workspaceRoots.add(project.dir);
  }

  // 2-4. Workflows, composite actions, Dockerfiles and the scripts they invoke.
  const { usages, dockerMeta, externalCheckouts } = discover(files);

  // Attach every command to its nearest real project. Commands with no project
  // above them (e.g. a global tool install) are hygiene-only and must never
  // produce "missing package.json" style errors.
  const projectDirs = new Set(projects.keys());
  const usagesByDir = new Map();
  const orphanUsages = [];

  for (const u of usages) {
    const owner = nearestProjectDir(u.dir, projectDirs);
    if (!owner) {
      orphanUsages.push(u);
      continue;
    }
    const project = getProject(projects, owner);
    project.evidence.add(`${u.source}:${posix.basename(u.file)}`);
    if (!usagesByDir.has(owner)) usagesByDir.set(owner, []);
    usagesByDir.get(owner).push(u);
  }

  // Resolve workspace membership.
  for (const project of projects.values()) {
    for (const anc of ancestors(project.dir)) {
      if (!workspaceRoots.has(anc)) continue;
      project.isWorkspaceMember = true;
      project.workspaceRoot = anc;
      break;
    }
  }

  // Verify each project.
  for (const project of projects.values()) {
    let pkg = null;
    let pkgText = null;

    if (project.hasPackageJson) {
      pkgText = readText(joinDir(project.dir, 'package.json'));
      const parsed = parseJsonSafe(pkgText || '');
      if (parsed.error) {
        addViolation(project, {
          title: 'Invalid package.json',
          message: `package.json in "${project.dir}" is not valid JSON: ${parsed.error}`,
          file: joinDir(project.dir, 'package.json'),
        });
      }
      pkg = parsed.value;
    }

    project.manager = detectPackageManager(project, pkg);

    // Command hygiene applies to members too.
    checkCommandUsages(project, usagesByDir.get(project.dir) || [], policy);

    // Config lives at the workspace root, so members are not checked for it.
    if (project.isWorkspaceMember) continue;

    checkLockfileConflicts(project);
    checkDockerLockfileCopy(project, dockerMeta);

    if (project.manager === 'pnpm') {
      checkPnpmProject(project, pkg, pkgText, policy);
    } else if (project.manager === 'npm') {
      checkNpmProject(project, pkg, pkgText, policy);
    } else if (project.manager === 'yarn' || project.manager === 'bun') {
      addViolation(project, {
        title: `Disallowed package manager (${project.manager})`,
        message: `"${project.dir}" is configured for ${project.manager}. Use pnpm (preferred) or npm.`,
        file: joinDir(project.dir, 'package.json'),
      });
    } else if (project.hasPackageJson) {
      addViolation(project, {
        title: 'No package manager configured',
        message: `"${project.dir}" has a package.json but no lock-file or engines configuration. Configure pnpm (preferred) or npm per the guideline.`,
        file: joinDir(project.dir, 'package.json'),
      });
    }
  }

  for (const u of orphanUsages) {
    const bucket = getProject(projects, u.dir);
    bucket.evidence.add(`${u.source}:${posix.basename(u.file)}`);
    checkCommandUsages(bucket, [u], policy);
  }

  report(projects, policy, notes, externalCheckouts, failOnViolation);
}

function statusOf(project) {
  if (project.violations.length) return 'non-compliant';
  if (project.isWorkspaceMember) return 'workspace member';
  return 'compliant';
}

function locationOf(entry) {
  if (!entry.file) return '';
  return entry.line ? `${entry.file}:${entry.line}` : entry.file;
}

function externalCheckoutSummary(externalCheckouts) {
  if (!externalCheckouts.length) return [];
  return [
    '',
    '### Repositories not scanned',
    '',
    '| Repository | Checked out at | Referenced from |',
    '| --- | --- | --- |',
    ...externalCheckouts.map((c) => `| \`${c.repository}\` | \`${c.path || '.'}\` | \`${c.file}:${c.line}\` |`),
  ];
}

function report(projects, policy, notes, externalCheckouts, failOnViolation) {
  const all = [...projects.values()].sort((a, b) => a.dir.localeCompare(b.dir));
  const nonCompliant = all.filter((p) => p.violations.length > 0);
  const totalViolations = all.reduce((n, p) => n + p.violations.length, 0);
  const totalWarnings = all.reduce((n, p) => n + p.warnings.length, 0);
  const policyLine = `npm >=${policy.npm.engineMin}, pnpm >=${policy.pnpm.engineMin}, minimum release age ${policy.releaseAgeDays} day(s)`;

  console.log('Node.js supply-chain compliance');
  console.log('===============================');
  console.log(`Policy: ${policyLine}`);
  for (const note of notes) {
    console.log(`Note: ${note}`);
    annotate('warning', note, { title: 'Supply-chain policy input' });
  }

  for (const checkout of externalCheckouts) {
    const at = checkout.path ? ` at "${checkout.path}"` : '';
    const message = `"${checkout.repository}" is checked out${at} but is a different repository, so it was not scanned. Run this check in that repository as well.`;
    console.log(`Not scanned: ${checkout.repository} (${checkout.file}:${checkout.line})`);
    annotate('warning', message, {
      file: checkout.file,
      line: checkout.line,
      title: 'External repository not scanned',
    });
  }
  console.log('');

  if (all.length === 0) {
    console.log('No Node.js projects discovered in the repository.');
    annotate('notice', 'No Node.js projects discovered in the repository.', { title: 'Node.js supply chain' });
    writeSummary([
      '## Node.js supply-chain compliance',
      '',
      'No Node.js projects discovered in the repository.',
      ...externalCheckoutSummary(externalCheckouts),
    ].join('\n'));
    setOutput('compliant', 'true');
    setOutput('project-count', '0');
    setOutput('violation-count', '0');
    setOutput('warning-count', '0');
    return;
  }

  const label = { compliant: 'PASS', 'non-compliant': 'FAIL', 'workspace member': 'SKIP' };
  console.log(`Discovered ${all.length} Node.js project(s):`);
  console.log('');
  for (const p of all) {
    const note = p.isWorkspaceMember ? ` (member of workspace "${p.workspaceRoot}")` : '';
    console.log(`  ${label[statusOf(p)]}  ${p.dir}  [${p.manager || 'unknown'}]${note}`);
    console.log(`        discovered via: ${[...p.evidence].sort().join(', ') || 'command usage'}`);
    for (const v of p.violations) console.log(`        error    ${locationOf(v)} - ${v.message}`);
    for (const w of p.warnings) console.log(`        warning  ${locationOf(w)} - ${w.message}`);
    console.log('');
  }

  for (const p of all) {
    for (const w of p.warnings) {
      annotate('warning', w.message, { file: w.file, line: w.line, title: w.title });
    }
  }

  // Granular annotations plus one summary annotation per non-compliant project.
  for (const p of nonCompliant) {
    for (const v of p.violations) {
      annotate('error', v.message, { file: v.file, line: v.line, title: v.title });
    }
    const titles = [...new Set(p.violations.map((v) => v.title))].join('; ');
    annotate('error', `${p.violations.length} supply-chain violation(s): ${titles}.`, {
      file: joinDir(p.dir, 'package.json'),
      title: `Non-compliant Node.js project: ${p.dir}`,
    });
  }

  const md = [
    '## Node.js supply-chain compliance',
    '',
    nonCompliant.length === 0
      ? `All **${all.length}** Node.js project(s) in the repository are compliant.`
      : `**${nonCompliant.length}** of **${all.length}** Node.js project(s) are non-compliant (${totalViolations} violation(s), ${totalWarnings} warning(s)).`,
    '',
    `Policy: ${policyLine}.`,
    '',
    '| Project | Manager | Status | Discovered via | Violations | Warnings |',
    '| --- | --- | --- | --- | --- | --- |',
    ...all.map((p) => `| \`${p.dir}\` | ${p.manager || 'unknown'} | ${statusOf(p)} | ${[...p.evidence].sort().join('<br>') || 'command usage'} | ${p.violations.length} | ${p.warnings.length} |`),
  ];

  if (nonCompliant.length) {
    md.push('', '### Violations', '');
    for (const p of nonCompliant) {
      md.push(`<details open><summary><code>${p.dir}</code> - ${p.violations.length} violation(s)</summary>`, '');
      md.push('| Requirement | Location | Detail |', '| --- | --- | --- |');
      for (const v of p.violations) md.push(`| ${v.title} | \`${locationOf(v)}\` | ${v.message} |`);
      md.push('', '</details>', '');
    }
  }

  if (totalWarnings) {
    md.push('', '### Warnings', '', '| Project | Location | Detail |', '| --- | --- | --- |');
    for (const p of all) {
      for (const w of p.warnings) md.push(`| \`${p.dir}\` | \`${locationOf(w)}\` | ${w.message} |`);
    }
  }

  if (externalCheckouts.length) {
    md.push(...externalCheckoutSummary(externalCheckouts));
  }

  writeSummary(md.join('\n'));

  if (nonCompliant.length === 0) {
    console.log(`All ${all.length} Node.js project(s) in the repository are compliant.`);
    annotate('notice', `All ${all.length} Node.js project(s) in the repository are compliant.`, { title: 'Node.js supply chain' });
  } else {
    console.log(`${nonCompliant.length} of ${all.length} Node.js project(s) are non-compliant.`);
  }

  setOutput('compliant', nonCompliant.length === 0 ? 'true' : 'false');
  setOutput('project-count', String(all.length));
  setOutput('violation-count', String(totalViolations));
  setOutput('warning-count', String(totalWarnings));

  if (nonCompliant.length && failOnViolation) process.exitCode = 1;
}

try {
  main();
} catch (err) {
  annotate('error', `verify-node-supply-chain failed: ${err && err.stack ? err.stack : err}`, {
    title: 'verify-node-supply-chain crashed',
  });
  process.exitCode = 1;
}
