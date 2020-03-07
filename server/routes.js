const
        router = require('express').Router(),
        passport = require('passport'),
        uuid = require('uuid'),
        fs = require('fs'),
        R = require('ramda'),
        idpInitiated = require('./idp-initiated'),
        misc = require('./utils/misc'),
        logger = require("./utils/logging")
        url = require('url')

// CATS SAML Authentication Responses use the HTTP POST binding
router.post('/auth/saml/:provider/callback',
        validateProvider,
        authenticateRequestCallback,
        processIdpInitiated,
    callbackResponse)

// CATS SAML Logout Requests and Responses use the HTTP Redirect binding
router.get('/auth/saml/:provider/callback',
        validateProvider,
    processLogout)

router.get('/auth/:provider/callback',
        validateProvider,
        authenticateRequestCallback,
    callbackResponse)

router.get('/auth/:provider/:token',
        validateProvider,
    validateToken,
    authenticateRequest)

router.get('/auth/:provider/:token/saml/:samlissuer',
        validateProvider,
    validateToken,
        authenticateRequest)

router.get('/auth/:provider/:token/id/:mfapai',
        validateProvider,
    validateToken,
        authenticateRequest)

// SP-initiated logout
router.get('/logout/request', (req, res, next) => {
        if (!(req.user && req.user.provider)) {
                res.status(400).send('No Session')
        } else {
                const provider = req.user.provider
                const strategy = passport._strategy(provider)
                if (strategy.name === 'saml' && strategy._saml.options.logoutUrl && !req.user.logoutRequest) {
                        const relayState = req.query && req.query.post_logout_redirect_uri
                        if (relayState) {
                                req.query.RelayState = relayState
                        }
                        // Restore the SAML Subject for the logout request
                        req.user = req.session.samlSubject
                        logger.log2('debug', 'SAML Logout of subject ' + JSON.stringify(req.user))
                        strategy.logout(req, (err, uri) => {
                                req.logout()
                                res.redirect(uri)
                        }
                        )
                } else {
                        res.send("Success")
                }
        }
}
)

// Propagate SP Logout Response
router.get('/logout/response/:status?', (req, res, next) => {
        const status = req.params.status || 'Success'
        if (!(req.user && req.user.provider)) {
                res.status(400).send('No Session')
        } else {
                const provider = req.user.provider
                const strategy = passport._strategy(provider)
                if (req.user.logoutRequest) {
                        logger.log2('verbose', 'Sending SAML logout response to provider ' + provider)
                        req.samlLogoutRequest = req.user.logoutRequest
                        req.samlLogoutRequest.status = 'urn:oasis:names:tc:SAML:2.0:status:' + status
                        strategy._saml.getLogoutResponseUrl(req, {}, (err, url) => {
                                if (err) {
                                        handleError(req, res, err.message)
                                } else {
                                        res.redirect(url)
                                }
                        })
                } else {
                        res.status(400).send("No logout request to respond to!")
                }
        }
}
)

router.get('/casa/:provider/:token',
        (req, res, next) => {
                req.failureUrl = '/casa/rest/pl/account-linking/idp-linking'
                next()
        },
        validateProvider,
    validateToken,
    authenticateRequestCasa)

//Token generation
router.get('/token',
        function (req, res, next) {
                logger.log2('verbose', 'Issuing token')
                let     t = misc.getJWT({ jwt: uuid() }, 120)   //2 min expiration
                res.status(200).send({ token_: t})
        }
)

//Metadata
router.get('/auth/meta/idp/:idp',
    function (req, res) {

        let idp = req.params.idp
        logger.log2('verbose', `Metadata request for IDP ${idp}`)

        fs.readFile(`${__dirname}/idp-metadata/${idp}.xml`,
                        (e, data) => {
                                        if (e) {
                                                res.status(500).send(`An error occurred: ${e}`)
                                        } else {
                                                res.status(200).set('Content-Type', 'text/xml').send(String(data))
                                        }
                                })
    })

//Supporting functions

function abortIfProfileMissing(req, res, user) {
        if (!user) {
                handleError(req, res, 'No user profile was found')
        } else if (R.keys(user).length == 0) {
                handleError(req, res, 'User profile is empty')
        }
}

function validateProvider(req, res, next) {

        let provider = req.params.provider,     //provider is non empty here
                providerConfData = R.find(R.propEq('id', provider), global.providers)

        if (providerConfData) {
                //Attach some info for later use
                req.passportAuthenticateParams = providerConfData.passportAuthnParams
                next()
        } else {
                handleError(req, res, `${provider} is not recognized as external identity provider`)
        }

}

function authenticateRequest(req, res, next) {
        logger.log2('verbose', `Authenticating request against ${req.params.provider}`)
        passport.authenticate(req.params.provider, req.passportAuthenticateParams)(req, res, next)
}

function authenticateRequestCasa(req, res, next) {

        let provider = req.params.provider

        res.cookie('casa-' + provider, 'marker cookie', {
                        httpOnly: true,
                        maxAge: 120000, //2min expiration
                        secure: true
                })

        logger.log2('verbose', `Proceeding with linking procedure for provider ${provider}`)
        authenticateRequest(req, res, next)

}

function authenticateRequestCallback(req, res, next) {

        logger.log2('verbose', `Authenticating request against ${req.params.provider}`)
        passport.authenticate(
                        req.params.provider, { failureRedirect: global.basicConfig.failureRedirectUrl, failureFlash: true }
                )(req, res, next)

}

function validateToken(req, res, next) {

        let t = req.params.token
        try {
                logger.log2('verbose', 'Validating token')
                misc.verifyJWT(t)
                next()
        } catch (err) {
                let msg = 'Token did not pass validation.'
                logger.log2('error', `${msg} token: ${t}, error: ${err}`)
                handleError(req, res, msg)
        }

}

function processIdpInitiated(req, res, next) {
        let user = req.user,
                relayState = req.body.RelayState

        logger.log2('debug', `RelayState value: ${relayState}`)
        logger.log2('debug', `SAML reponse in body:\n${req.body.SAMLResponse}`)

        abortIfProfileMissing(req, res, user)
        idpInitiated.process(user, relayState, global.iiconfig, res, next)
}

function callbackResponse(req, res) {

        let postUrl, user = req.user

        abortIfProfileMissing(req, res, user)

        let provider = user.provider,
                sub = user.uid
    logger.log2('info', `User ${sub} authenticated with provider ${provider}`)

        if (req.cookies['casa-' + provider]) {
                postUrl = '/casa/rest/pl/account-linking/idp-linking/' + provider
        } else {
                postUrl = global.config.postProfileEndpoint
        }

        //Apply transformation to user object and restore original provider value
        user = misc.arrify(user)
        user.provider = provider

    let now = new Date().getTime(),
        jwt = misc.getRpJWT({
                                iss: postUrl,
                                sub: sub,
                                aud: global.basicConfig.clientId,
                                jti: uuid(),
                                exp: now / 1000 + 30,
                                iat: now,
                                data: user
                })

    logger.log2('debug', `Sending user data ${jwt} to: ${postUrl}`)

    res.set('content-type', 'text/html;charset=UTF-8')
    return res.status(200).send(`
                <html xmlns="http://www.w3.org/1999/xhtml">
                <script src="https://ajax.googleapis.com/ajax/libs/jquery/2.2.4/jquery.js"></script>
                <script type="text/javascript">
                        function getLanguage() {
                                $.ajax({
                                        url: '${global.basicConfig.languageAPI}',
                                        type: 'GET',
                                        contentType: 'application/json',
                                        xhrFields: {
                                                withCredentials: true
                                        },
                                        success: function (data) {
                                                 document.forms[0].elements[1].value = data.lang.substring(0, 2) + "_CA";
                                                 document.forms[0].submit();
                                                 },
                                        error: function (jqXHR, textStatus, errorThrown) { console.log(errorThrown); document.forms[0].submit() }
                                });
                        }
                </script>
                        <body onload="getLanguage()">
                                <noscript>
                                        <p>
                                                <b>Note:</b> your browser does not support JavaScript, please press the Continue
                                                button to proceed.
                                        </p>
                                        <p>
                                                <b>Remarque:</b> votre navigateur ne prend pas en charge JavaScript, veuillez appuyer sur le bouton Continuer
                                                pour continuer.
                                        </p>
                                </noscript>
                                <img style='display:block;margin-left:auto;margin-right:auto;padding:10% 0;' src='/oxauth/ext/resources/assets/icon_flag_rotation_080x080.gif'>
                                <form action="${postUrl}" method="post">
                                        <div>
                                                <input type="hidden" name="user" value="${jwt}"/>
                                                <input id="ui_locale" type="hidden" name="ui_locale"/>
                                                <noscript>
                                                        <input type="submit" value="Continue / Continuer"/>
                                                </noscript>
                                        </div>
                                </form>
                        </body>
                </html> `
        )

}

function processLogout(req, res) {

        function validateCallback(err, profile, loggedOut) {
                logger.log2('debug', 'logout callback ' + JSON.stringify(err) + ' ' + JSON.stringify(profile) + ' ' + loggedOut)

                if (err) {
                        logger.log2('error', err.stack)
                        res.status(400).send('Invalid SAML request') // TODO: Redirect to logout error UI page
                } else if (profile) { // Logout Request
                        req.user.logoutRequest = profile
                        const redirectUri = encodeURIComponent('https://' + req.hostname + '/passport/logout/response')
                        res.redirect('/oxauth/restv1/end_session?post_logout_redirect_uri=' + redirectUri)
                } else { // Logout Response
                        res.send("Success")
                }
        }

        const provider = req.params.provider
        logger.log2('verbose', 'received logout from provider ' + provider)
        const strategy = passport._strategy(provider)


        var originalQuery = url.parse(req.url).query
        strategy._saml.validateRedirect(req.query, originalQuery, validateCallback)
}

function handleError(req, res, msg) {

        if (R.isNil(req)) {
                res.status(500).send(msg)
        } else {
                let failureUrl = R.defaultTo(global.basicConfig.failureRedirectUrl, req.failureUrl)
                res.redirect(`${failureUrl}?failure=${msg}`)
        }

}

module.exports = router
