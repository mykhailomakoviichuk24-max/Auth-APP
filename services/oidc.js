// OpenID Connect (Завдання 6): Authorization Code Flow + PKCE + state + nonce.
const { Issuer } = require('openid-client');
const config = require('../config');

let clientPromise = null;

function isConfigured() {
  return !!(config.oidc.clientId && config.oidc.clientSecret);
}

function getClient() {
  if (!isConfigured()) return null;
  if (!clientPromise) {
    clientPromise = Issuer.discover(config.oidc.issuer)
      .then(
        (issuer) =>
          new issuer.Client({
            client_id: config.oidc.clientId,
            client_secret: config.oidc.clientSecret,
            redirect_uris: [config.oidc.redirectUri],
            response_types: ['code'],
          })
      )
      .catch((err) => {
        clientPromise = null; // дозволити повторну спробу
        throw err;
      });
  }
  return clientPromise;
}

module.exports = { isConfigured, getClient };
