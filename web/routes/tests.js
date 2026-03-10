const { isSafeSinglePathSegment } = require('./shared');

module.exports = function registerTestsRoute(app, deps) {
  const { testsDir, fsp, isWithinRoot, verboseRequestLog, verboseResponseLog } = deps;

  app.get('/tests/:name', async (req, res) => {
    verboseRequestLog(req);
    if (!isSafeSinglePathSegment(req.params.name)) {
      res.status(400).type('text').send('invalid path\n');
      verboseResponseLog(req, 400, 13);
      return;
    }
    const candidate = deps.path.resolve(testsDir, req.params.name);
    if (!isWithinRoot(candidate, testsDir)) {
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
};