const { SecretClient } = require("@azure/keyvault-secrets");
const { DefaultAzureCredential } = require("@azure/identity");
const credential = new DefaultAzureCredential();
const keyvaultClient = new SecretClient('https://kv-sic-dev-00.vault.azure.net', credential);


module.exports = {
  passportFile: '/etc/gluu/conf/passport-config.json',
  saltFile: '/etc/gluu/conf/salt',
  timerInterval: 2 * 60 * 1000, // 2 minutes in milliseconds
  rateLimitWindowMs: 24 * 60 * 60 * 1000, // 24 hrs in milliseconds
  rateLimitMaxRequestAllow: 100000,
  appInsightsKey: (async function() {
    return await keyvaultClient.getSecret('InstrumentationKey');
  })() ,
  // redisPassword: await keyvaultClient.getSecret('RedisPW'),
  cookieMaxAge: null,
  cookiePath: '/passport',
  cookieSameSite: 'none',
  cookieSecure: true,
  HTTP_PROXY: process.env.HTTP_PROXY,
  HTTPS_PROXY: process.env.HTTPS_PROXY,
  NO_PROXY: process.env.NO_PROXY
}
