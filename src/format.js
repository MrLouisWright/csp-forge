const useColor = (stream) => !('NO_COLOR' in process.env) && Boolean(process.env.FORCE_COLOR || stream?.isTTY);
const palette = (color) => {
  const c = (code) => (s) => (color ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  return { red: c(31), yellow: c(33), green: c(32), dim: c(2), bold: c(1), cyan: c(36) };
};
const issue = (p, x, lines) => {
  const tag = x.severity === 'error' ? p.red('✖ error') : p.yellow('⚠ warn ');
  lines.push(`  ${tag} ${p.bold(x.title || x.message)} ${p.dim('[' + x.id + ']')}`);
  if (x.title && x.message) lines.push(`          ${x.message}`);
  else if (x.file) lines.push(`          ${p.dim('in ' + x.file)}`);
  if (x.fix) lines.push(...x.fix.split('\n').map((l, i) => `          ${i ? '' : p.cyan('fix: ')}${p.dim(l)}`));
};

/** Pretty output for --check results. */
export function pretty(results, { color = useColor(process.stdout) } = {}) {
  const p = palette(color);
  const lines = [];
  for (const r of results) {
    lines.push('', p.bold(r.target) + p.dim(` checked against ${r.files} scanned file(s)`));
    if (!r.findings.length) lines.push(p.green('  ✔ policy covers everything the site uses and is not overly loose'));
    for (const x of r.findings) issue(p, x, lines);
  }
  const e = results.reduce((s, r) => s + r.findings.filter((x) => x.severity === 'error').length, 0);
  const w = results.reduce((s, r) => s + r.findings.filter((x) => x.severity === 'warn').length, 0);
  lines.push('', `${results.length} policy(ies) checked: ${e ? p.red(e + ' error(s)') : p.green('0 errors')}, ${w ? p.yellow(w + ' warning(s)') : '0 warnings'}`);
  return lines.join('\n');
}

/** Human summary of a generation run (written to stderr). */
export function summary(scan, { color = useColor(process.stderr) } = {}) {
  const p = palette(color);
  const lines = [p.bold(`csp-forge: scanned ${scan.files.length} file(s)`) + p.dim(` — ${scan.inline.scripts} inline script(s), ${scan.inline.styles} inline style(s), ${scan.inline.styleAttrs} style attribute(s), ${scan.inline.handlers} event handler(s)`)];
  const seen = new Set();
  for (const w of scan.warnings) {
    const k = w.id + w.message;
    if (seen.has(k)) continue;
    seen.add(k);
    issue(p, { ...w, title: w.message, message: w.file ? p.dim('in ' + w.file) : '' }, lines);
  }
  const rev = new Map();
  for (const r of scan.review) if (!rev.has(r.directive + r.source)) rev.set(r.directive + r.source, r);
  if (rev.size) {
    lines.push(`  ${p.yellow('⚠ review')} ${p.bold(`${rev.size} source(s) detected heuristically in JS — please review`)} ${p.dim('[js-detected]')}`);
    for (const r of rev.values()) lines.push(`          ${r.directive} ${p.cyan(r.source)} ${p.dim(`(${r.how} in ${r.file}: ${r.url.slice(0, 80)})`)}`);
    lines.push(`          ${p.cyan('fix: ')}${p.dim('Drop false positives with "ignore": ["https://unused.example/*"] in .csp-forgerc.json')}`);
  }
  return lines.join('\n');
}
