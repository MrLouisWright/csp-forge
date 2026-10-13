export function toSarif(results, version = '1.0.0') {
  const rules = new Map();
  const out = [];
  for (const r of results) for (const f of r.findings) {
    if (!rules.has(f.id)) rules.set(f.id, { id: f.id, name: f.id, shortDescription: { text: f.title }, help: { text: f.fix || '' },
      defaultConfiguration: { level: f.severity === 'error' ? 'error' : 'warning' } });
    out.push({ ruleId: f.id, level: f.severity === 'error' ? 'error' : 'warning',
      message: { text: `${r.target}: ${f.title}. ${f.message}\nFix: ${f.fix || ''}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: r.target } } }],
      partialFingerprints: { 'cspForge/v1': `${r.target}|${f.id}|${f.title}` } });
  }
  return { version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{ tool: { driver: { name: 'csp-forge', version, informationUri: 'https://github.com/MrLouisWright/csp-forge', rules: [...rules.values()] } }, results: out }] };
}
