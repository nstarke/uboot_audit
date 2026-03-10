const { listBinaryEntries } = require('./shared');

module.exports = function registerRootRoute(app, deps) {
  const { testsDir, scriptsDir, fsp, verboseRequestLog, verboseResponseLog } = deps;
  const agentTestsDir = deps.path.join(testsDir, 'agent');

  async function listAgentTestEntries(dir) {
    const entries = await fsp.readdir(dir, { withFileTypes: true }).catch(() => []);
    const tests = entries.map((entry) => {
      if (entry.isFile() && entry.name.endsWith('.sh')) {
        return [{
          name: entry.name,
          url: `/tests/agent/${encodeURIComponent(entry.name)}`
        }];
      }
      return [];
    });

    return tests.flat().sort((a, b) => a.name.localeCompare(b.name));
  }

  async function listScriptEntries(dir) {
    const entries = await fsp.readdir(dir, { withFileTypes: true }).catch(() => []);
    return entries
      .filter((entry) => entry.isFile())
      .map((entry) => ({
        name: entry.name,
        url: `/scripts/${encodeURIComponent(entry.name)}`
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  app.get('/', async (req, res) => {
    verboseRequestLog(req);
    const binaryEntries = await listBinaryEntries(deps.assetsDir, fsp, deps.releaseStateFile);
    const testEntries = await listAgentTestEntries(agentTestsDir);
    const scriptEntries = await listScriptEntries(scriptsDir);

    const assetItems = binaryEntries.length
      ? binaryEntries.map(({ fileName, url }) => `      <li><a href="${escapeHtml(url)}">${escapeHtml(fileName)}</a></li>`).join('\n')
      : '      <li><em>No binaries downloaded.</em></li>';

    const testItems = testEntries.length
      ? testEntries.map(({ name, url }) => `      <li><a href="${escapeHtml(url)}">tests/agent/${escapeHtml(name)}</a></li>`).join('\n')
      : '      <li><em>No agent test shell scripts found.</em></li>';

    const scriptItems = scriptEntries.length
      ? scriptEntries.map(({ name, url }) => `      <li><a href="${escapeHtml(url)}">scripts/${escapeHtml(name)}</a></li>`).join('\n')
      : '      <li><em>No command scripts found.</em></li>';

    const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Release Binaries and Test Scripts</title>
  </head>
  <body>
    <h1>Release Binaries</h1>
    <p>Serving files from: ${escapeHtml(deps.assetsDir)}</p>
    <ul>
${assetItems}
    </ul>

    <h1>Test Scripts</h1>
    <p>Serving agent scripts from: ${escapeHtml(agentTestsDir)}</p>
    <ul>
${testItems}
    </ul>

    <h1>Command Scripts</h1>
    <p>Serving command scripts from: ${escapeHtml(scriptsDir)}</p>
    <ul>
${scriptItems}
    </ul>
  </body>
</html>
`;

    res.type('text/html').send(html);
    verboseResponseLog(req, 200, Buffer.byteLength(html));
  });
};