module.exports = function registerAssetRoute(app, deps) {
  const { assetsDir, fsp, isWithinRoot, mime, verboseRequestLog, verboseResponseLog } = deps;

  app.get('/:name', async (req, res) => {
    verboseRequestLog(req);
    const candidate = deps.path.resolve(assetsDir, req.params.name);
    if (!isWithinRoot(candidate, assetsDir)) {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
      return;
    }
    try {
      const stat = await fsp.stat(candidate);
      if (!stat.isFile()) {
        throw new Error('not a file');
      }
      res.type(mime.lookup(candidate) || 'application/octet-stream');
      res.sendFile(candidate);
    } catch {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
    }
  });
};