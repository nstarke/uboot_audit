const { listBinaryEntries } = require('./shared');

module.exports = function registerRootRoute(app, deps) {
  const { testsDir, fsp, verboseRequestLog, verboseResponseLog } = deps;

  app.get('/', async (req, res) => {
    verboseRequestLog(req);
    const binaryEntries = await listBinaryEntries(deps.assetsDir, fsp, deps.releaseStateFile);
    const testEntries = (await fsp.readdir(testsDir).catch(() => []))
      .filter((name) => name.endsWith('.sh'))
      .sort((a, b) => a.localeCompare(b))
      .map((name) => `/tests/${encodeURIComponent(name)}`);

    const body = {
      tests: testEntries,
      binaries: binaryEntries.map(({ isa, url }) => ({ isa, url }))
    };
    const json = JSON.stringify(body);
    res.json(body);
    verboseResponseLog(req, 200, Buffer.byteLength(json));
  });
};