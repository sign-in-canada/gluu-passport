const { JWK: { createKeyStore, asKey } } = require('node-jose');
const { Issuer } = require('openid-client');
const path = require('path');
const fs = require('fs/promises');
const { logger } = require('./logging');
const keyStore = new createKeyStore();
const keyVaultPath = '/run/keyvault/keys/';

async function addKeytoKeyStore(file) {

  const privateKeyPath = path.resolve(keyVaultPath, file);
  const fileSymLinkInfo = await fs.lstat(privateKeyPath);

  if (fileSymLinkInfo.isFile()) {
    const fileNameRegExp = /(.*?)_(.*?)_(.*?)\.pem/
    const matches = file.match(fileNameRegExp)

    if (matches.length === 4) { // file naming: keydId_use_alg.pem
      try {
        const privateKey = await fs.readFile(privateKeyPath, 'utf8');
        const opts = {
          kid: `${matches[1]}_${matches[2]}_${matches[3]}`,
          use: matches[2],
          alg: matches[3].toUpperCase()
        };

        // Create the key and add it to the keystore
        const jwkKey = await asKey(privateKey.toString(), 'pem', opts);
        await keyStore.add(jwkKey);
        logger.log('info', `added key`)

      } catch (err) {
        const msg = 'Private key was not successfully added to the keystore.'
        logger.log('error', `${msg} key: ${file}, error: ${err}`)
      }
    }
  }
}

async function getPrivateKeys() {
  try {
    const file = await fs.readdir(keyVaultPath);
    return file;
  } catch (error) {
    logger.log('error', `failed to get private keys: ${error}`)
  }
}

/**
 * get keystore after creating and adding private keys
 * @returns keystore
 */
async function getKeystore() {
  logger.log('verbose', 'Importing private keys into the keystore')
  const privateKeys = await getPrivateKeys();
  return Promise.all(privateKeys.map(async privateKey => {
    await addKeytoKeyStore(privateKey);
  }));
}

const clients = []

/**
 * Get issuer object
 * @param {*} providerOptions
 * @returns Issuer
 */
async function getIssuer(providerOptions) {
  try {
    return await Issuer.discover(providerOptions.issuer)
  } catch (e) {
    logger.log('debug', e.message)
    logger.log('debug', `Failed to fetch config from ${providerOptions.issuer}/.well-known/openid-configuration OpenID Connect Discovery endpoint, Going for manual setup`)
    return new Issuer(providerOptions)
  }
}

/**
 *  initialize openid-client passport strategy
 * @param {*} provider
 * @returns issuer.client
 */
async function getClient(provider) {
  const { options } = provider
  let client = clients.find(c => c.id === provider.id)
  if (client) {
    return client.client
  }

  const issuer = await getIssuer(options)
  if (options.token_endpoint_auth_method && options.token_endpoint_auth_method === 'private_key_jwt' && options.use_request_object && options.use_request_object.toString() === 'true') {
    // getKeystore with private keys
    const keyStoreKeys = keyStore.all();
    if (keyStoreKeys.length === 0) await getKeystore();
    client = new issuer.Client(options, keyStore.toJSON(true))
  } else {
    client = new issuer.Client(options)
  }
  logger.log('info', `openid-client config: ${JSON.stringify(client)}`)
  clients.push({ id: provider.id, client })
  return client
}

module.exports = {
  getClient
}
