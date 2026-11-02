/* Public save-receipt checks. Secret values are never copied into projections. */
(() => {
  const strip = value => String(value || '').replace(/^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g, '');
  const validName = profile => profile && typeof profile.name === 'string'
    && profile.name.length > 0 && Array.from(profile.name).length <= 100;

  const verify = (tool, kind, profile, submitted) => {
    if (!validName(profile) || profile.name !== strip(submitted.get('name'))) return false;
    const text = name => strip(submitted.get(name));
    const number = (name, fallback) => Number(submitted.has(name) ? submitted.get(name) : fallback);

    if (tool === 'snmp' && kind === 'credentials') {
      if (profile.version !== text('version').toLowerCase()) return false;
      if (profile.version === 'v3') {
        return profile.username === text('username')
          && profile.security_level === text('security_level').toLowerCase()
          && profile.auth_protocol === text('auth_protocol').toLowerCase()
          && profile.priv_protocol === text('priv_protocol').toLowerCase()
          && profile.context_name === text('context_name');
      }
      return profile.version === 'v2c' && profile.has_community === true;
    }

    if (kind === 'hosts' || kind === 'servers') {
      if (typeof profile.host !== 'string' || profile.host !== text('host')
        || !Number.isInteger(profile.port)
        || profile.port !== number('port', kind === 'hosts' ? 161 : 1812)) return false;
      return kind !== 'hosts' || (profile.credential_name === text('credential_name')
        && profile.timeout === number('timeout', 2)
        && profile.retries === number('retries', 1));
    }

    if (tool === 'radius' && kind === 'credentials') {
      return typeof profile.username === 'string' && profile.username === text('username');
    }

    // Each successful non-comment line produces one entry. Semantic validation
    // remains authoritative on the server; these checks bind its public count.
    const source = submitted.get(kind === 'oids' ? 'source' : 'attributes') || '';
    const lines = String(source).split(/\r\n|[\n\r\v\f\u001c-\u001e\u0085\u2028\u2029]/)
      .map(strip).filter(line => line && !line.startsWith(kind === 'oids' ? '#' : '# '));
    return Number.isInteger(profile.count) && profile.count === lines.length
      && profile.count > 0 && profile.count <= 50;
  };

  window.TwnNetworkProfileReceipt = Object.freeze({strip, validName, verify});
})();
