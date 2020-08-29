const saltFile = './test/testdata/salt'
const timerInterval = 60000

const passportFile = {
	configurationEndpoint:
        'https://chris.gluuthree.org/identity/restv1/passport/config',

	failureRedirectUrl:
        'https://chris.gluuthree.org/oxauth/auth/passport/passportlogin.htm',

	logLevel: 'debug',

	consoleLogOnly: false,

	clientId: '1502.d49baf9f-b19b-40de-a990-33d08e7f9e77',

	keyPath: './test/testdata/passport-rp.pem',

	keyId: '36658e03-34ea-4745-ad43-959916c96def_sig_rs512',

	keyAlg: 'RS512'
}


module.exports = {
	saltFile,
	passportFile,
	timerInterval,
}