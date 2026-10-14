import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { formatReportingEndpoints, reportingEndpointsHeader, normalizeReporting, render, generate } from '../src/index.js';

const fx = (n) => fileURLToPath(new URL(`./fixtures/${n}`, import.meta.url));

test('reporting endpoints header and directives', async () => {
  const norm = normalizeReporting({ reportTo: { name: 'csp-endpoint', url: 'https://example.com/csp' }, reportUri: '/legacy' });
  assert.equal(norm.reportToName, 'csp-endpoint');
  assert.equal(formatReportingEndpoints(norm.endpoints), 'csp-endpoint="https://example.com/csp"');
  assert.equal(reportingEndpointsHeader({ reportTo: { name: 'csp', url: 'https://r.example/csp' } }), 'csp="https://r.example/csp"');

  const { directives } = await generate({
    dir: fx('clean'),
    config: { reportUri: '/csp-report', reportTo: { name: 'csp-endpoint', url: 'https://example.com/csp' } },
  });
  assert.deepEqual(directives['report-uri'], ['/csp-report']);
  assert.deepEqual(directives['report-to'], ['csp-endpoint']);

  const nginx = render(directives, 'nginx', { reporting: { reportTo: { name: 'csp-endpoint', url: 'https://example.com/csp' } } });
  assert.match(nginx, /add_header Content-Security-Policy/);
  assert.match(nginx, /add_header Reporting-Endpoints/);
  assert.match(render(directives, 'reporting-endpoints', { reporting: { reportTo: { name: 'csp-endpoint', url: 'https://example.com/csp' } } }), /^Reporting-Endpoints: csp-endpoint=/);
});
