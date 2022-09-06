const expressSession = require('express-session')
let RedisStore = require("connect-redis")(expressSession)
const config = require('config')
const { secretKey } = require('./misc')

const { createClient } = require("redis")
let redisClient = createClient(`rediss://:${config.redisPassword}@sic-dev1.redis.cache.windows.net:6380`)

const expressSessionConfig = {
  cookie: {
    maxAge: config.get('cookieMaxAge'),
    path: config.get('cookiePath'),
    sameSite: config.get('cookieSameSite'),
    secure: config.get('cookieSecure')
  },
  store: new RedisStore({ client: redisClient }),
  secret: secretKey(),
  resave: false,
  saveUninitialized: false
}

const session = expressSession(expressSessionConfig)

module.exports = {
  session
}
