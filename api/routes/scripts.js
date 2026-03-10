const { isSafeSinglePathSegment } = require('./shared');

module.exports = function registerScriptsRoute(app, deps) {
  const { scriptsDir, fsp, isWithinRoot, verboseRequestLog, verboseResponseLog } = deps;

  app.get('/scripts/:name', async (req, res) => {
    verboseRequestLog(req);
    const requestedPath = req.params.name;
    if (!isSafeSinglePathSegment(requestedPath)) {
      res.status(400).type('text').send('invalid path\n');
      verboseResponseLog(req, 400, 13);
      return;
    }

    const candidate = deps.path.resolve(scriptsDir, requestedPath);
    if (!isWithinRoot(candidate, scriptsDir)) {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
      return;
    }

    try {
      const stat = await fsp.stat(candidate);
      if (!stat.isFile()) {
        throw new Error('not a file');
      }
      res.type('text/plain').sendFile(candidate);
    } catch {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
    }
  });
};