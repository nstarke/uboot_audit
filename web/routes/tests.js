const { isSafeSinglePathSegment } = require('./shared');

module.exports = function registerTestsRoute(app, deps) {
  const { testsDir, fsp, isWithinRoot, verboseRequestLog, verboseResponseLog } = deps;
  const agentTestsDir = deps.path.join(testsDir, 'agent');

  app.get('/tests/agent/:name', async (req, res) => {
    verboseRequestLog(req);
    const requestedPath = req.params.name;
    if (!isSafeSinglePathSegment(requestedPath) || !requestedPath.endsWith('.sh')) {
      res.status(400).type('text').send('invalid path\n');
      verboseResponseLog(req, 400, 13);
      return;
    }
    const candidate = deps.path.resolve(agentTestsDir, requestedPath);
    if (!isWithinRoot(candidate, agentTestsDir)) {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
      return;
    }
    try {
      const stat = await fsp.stat(candidate);
      if (!stat.isFile()) {
        throw new Error('not a file');
      }
      res.sendFile(candidate);
    } catch {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
    }
  });

  app.get('/tests/*', (req, res) => {
    verboseRequestLog(req);
    res.status(404).type('text').send('not found\n');
    verboseResponseLog(req, 404, 10);
  });
};