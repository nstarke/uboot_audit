function listBinaryEntries(assetsDir, fsp, releaseStateFile) {
  return fsp.readdir(assetsDir, { withFileTypes: true }).catch(() => []).then((entries) => entries
    .filter((entry) => entry.isFile()
      && entry.name !== releaseStateFile
      && entry.name !== '.release_state.json'
      && !entry.name.startsWith('.release_state'))
    .map((entry) => {
      const isa = entry.name.startsWith('embedded_linux_audit-')
        ? entry.name.slice('embedded_linux_audit-'.length)
        : entry.name;
      return {
        isa,
        fileName: entry.name,
        url: `/isa/${encodeURIComponent(isa)}`
      };
    })
    .sort((a, b) => a.isa.localeCompare(b.isa)));
}

function isSafeSinglePathSegment(value) {
  if (typeof value !== 'string' || !value) {
    return false;
  }

  if (value.includes('/') || value.includes('\\')) {
    return false;
  }

  if (value === '.' || value === '..' || value.includes('..')) {
    return false;
  }

  return true;
}

module.exports = {
  listBinaryEntries,
  isSafeSinglePathSegment
};