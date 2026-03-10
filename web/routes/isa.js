const { listBinaryEntries, isSafeSinglePathSegment } = require('./shared');

module.exports = function registerIsaRoute(app, deps) {
  const { assetsDir, fsp, isWithinRoot, mime, verboseRequestLog, verboseResponseLog } = deps;

  app.get('/isa/:isa', async (req, res) => {
    verboseRequestLog(req);
    if (!isSafeSinglePathSegment(req.params.isa)) {
      res.status(400).type('text').send('invalid path\n');
      verboseResponseLog(req, 400, 13);
      return;
    }
    const binaryEntries = await listBinaryEntries(assetsDir, fsp, deps.releaseStateFile);
    const match = binaryEntries.find((entry) => entry.isa === req.params.isa);
    if (!match) {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
      return;
    }

    const candidate = deps.path.resolve(assetsDir, match.fileName);
    if (!isWithinRoot(candidate, assetsDir)) {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
      return;
    }

    res.type(mime.lookup(candidate) || 'application/octet-stream');
    res.sendFile(candidate);
  });
};