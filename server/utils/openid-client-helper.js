const jose = require('jose')
const { JWK: { generateSync, asKey }, JWKS: { KeyStore } } = require('jose_v2')
const { Issuer } = require('openid-client')
const path = require('path')
const fs = require('fs');
const util = require('util');
const fileUtils = require('../utils/file-utils')
const { logger } = require('./logging')
const clientJWKSFilePath = path.join(`${process.cwd()}/server`, 'jwks')
const secretKey = require('./misc').secretKey()
let ks = new KeyStore()
const keysPath = '/run/keyvault/keys/'

/**
 * generate jwks and store it in file. file name will be like [provider.id].json
 * @param {*} provider
 * @returns undefined
 */
async function generateJWKS(provider) {
  const keyType = generateSync('RSA')
  const keyStore = new KeyStore(keyType)
  const fileName = path.join(fileUtils.makeDir(clientJWKSFilePath), provider.id + '.json')
  if (!fs.existsSync(fileName)) {
    await fileUtils.writeDataToFile(fileName, JSON.stringify(keyStore.toJWKS(true)))
  }
}

async function readDirectoryAsync(path) {
  return new Promise((resolve, reject) => {
    fs.readdir(path, (err, files) => {
      if (err) return reject(err);
      resolve(files);
    });
  });
}

async function addKeytoKeyStore(file) {

  const akeyPath = path.resolve(keysPath, file)
  if (fs.lstatSync(akeyPath).isFile()) {
    const fileNameRegExp = /(.*?)_(.*?)_(.*?)\.pem/
    const matches = file.match(fileNameRegExp)

    if (matches.length === 4) { // file naming: keydId_use_alg.pem
      try {
        const readFileAsync = util.promisify(fs.readFile);
        const privateKey = await readFileAsync(akeyPath, 'utf8');

        const keyObj = {
          key: privateKey,
          passphrase: secretKey
        }

        const opts = {
          kid: `${matches[1]}_${matches[2]}_${matches[3]}`,
          use: matches[2],
          alg: matches[3].toUpperCase()
        }

        // Create the key and add it to the keystore
        const key = asKey(keyObj, opts)
        ks.add(key)
        logger.log('info', `added key`)

      } catch (err) {
        const msg = 'Private key was not successfully added to the keystore.'
        logger.log('error', `${msg} key: ${file}, error: ${err}`)
      }
    }
  }
}

/**
 * get keystore after creating and adding private keys
 * @returns keystore
 */
async function getKeystore() {
  logger.log('verbose', 'Importing private keys into the keystore')
  const files = await readDirectoryAsync(keysPath);
  return Promise.all(files.map(async file => {
    await addKeytoKeyStore(file);
    logger.log('info', `====== KS return value ${JSON.stringify(file, null, 4)} =======`)
  })
  );
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
    if (ks.size === 0) await getKeystore();
    client = new issuer.Client(options, ks.toJWKS(true))
  } else {
    client = new issuer.Client(options)
  }
  logger.log('info', `openid-client config: ${JSON.stringify(client)}`)
  clients.push({ id: provider.id, client })
  return client
}

module.exports = {
  getClient,
  generateJWKS
}
