// JavaScript MISP connectivity
const https = require('node:https');

class MISP {
  constructor(url, apiKey, insecure = false) {
    this.url = url;
    this.apiKey = apiKey;

    this.agent = new https.Agent({
      keepAlive: true,
      maxSockets: 4,
    });

    this.url = new URL(this.url);
    this.options = {
      agent: this.agent,
      host: this.url.host,
      hostname: this.url.hostname,
      headers: {
        Authorization: this.apiKey,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      json: true,
    };

    if (this.url.port) {
      this.options.port = this.url.port;
    }

    // The following additional options from tls.connect() are also accepted:
    // ca, cert, ciphers, clientCertEngine, crl, dhparam, ecdhCurve, honorCipherOrder,
    // key, passphrase, pfx, rejectUnauthorized, secureOptions, secureProtocol,
    // servername, sessionIdContext, highWaterMark.
    //
    // Support all the CA things?
    // Or let users pass in an agent?
    if (insecure) { this.options.rejectUnauthorized = false; }
  }

  // Internal helper to do a request to MISP
  async doRequest(method, path, resolve, reject, jsonBody = undefined) {
    const opts = {
      ...this.options,
      method,
      path,
    };

    const req = https.request(opts, (res) => {
      if (res.statusCode < 200 || res.statusCode > 299) {
        reject(res);
      } else {
        let rawData = '';
        res.on('data', (chunk) => { rawData += chunk; });
        res.on('end', () => {
          resolve(JSON.parse(rawData));
        });
        res.on('error', reject);
      }
    });
    req.on('error', reject);
    req.on('close', () => { /* nothing? */ });

    if (jsonBody !== undefined) {
      req.end(JSON.stringify(jsonBody));
    } else {
      req.end();
    }
  }

  // Search body according to API
  async attributesRestSearch(searchBody, limit = undefined) {
    return new Promise((resolve, reject) => {
      this.doRequest(
        'POST',
        '/attributes/restSearch',
        (data) => {
          const attributes = data?.response?.Attribute;
          if (attributes === undefined) {
            reject(data);
          } else {
            resolve(attributes);
          }
        },
        reject,
        {
          ...searchBody,
          ...(searchBody.limit === undefined && limit !== undefined && { limit }),
        },
      );
    });
  }

  async addSightingValues(values) {
    return new Promise((resolve, reject) => {
      this.doRequest(
        'POST',
        '/sightings/add',
        (data) => {
          console.log('SIGHTINGS RESPONSE', data);
          resolve(data);
        },
        reject,
        {
          values,
        },
      );
    });
  }

  // Report a sighting to the MISP instance given an Attribute UUID or ID.
  async addSightingAttribute(attributeId) {
    return new Promise((resolve, reject) => {
      this.doRequest(
        'POST',
        `/sightings/add/${attributeId}`,
        (data) => {
          if (data?.Sighting !== undefined) {
            resolve(data.Sigthing);
          } else {
            reject(data);
          }
        },
        reject,
      );
    });
  }
}

module.exports = { MISP };
