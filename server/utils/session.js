const expressSession = require('express-session')
const MemoryStore = require('memorystore')(expressSession)
const config = require('config')
const { secretKey } = require('./utils/misc')

const expressSessionConfig = {
  cookie: {
    maxAge: 86400000,
    sameSite: config.get('cookieSameSite'),
    secure: config.get('cookieSecure')
  },
  store: new MemoryStore({
    checkPeriod: 86400000 // prune expired entries every 24h
  }),
  secret: secretKey(),
  resave: false,
  saveUninitialized: false
}

const session = expressSession(expressSessionConfig)

module.exports = {
  session
}
