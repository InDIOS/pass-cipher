import PassCipher = require('.');
// import { HexBase64BinaryEncoding } from 'crypto';

let config = {
	cipher: {
		algorithm: /*'aes-256-cbc-hmac-sha256'*/'aes192',
		encoded: 'hex'
	},
	saltSize: 128,
	testPassword: 'lokol'
};
const encrypt = new PassCipher({
	saltSize: config.saltSize,
	algorithm: config.cipher.algorithm,
	// encoded: <HexBase64BinaryEncoding>config.cipher.encoded
});

let salt = encrypt.randomSalt(config.saltSize);
encrypt.cipher(config.testPassword, salt).then(encrypted => {
	console.log(`Test Passwords: ${config.testPassword}`);
	console.log(`Cipher Algorithm: ${encrypt.config.algorithm}`);
	console.log(`Cipher Encoded: ${encrypt.config.encoded}`);
	console.log(`Generate Salt Size: ${encrypt.config.saltSize}`);
	// console.log(`Cipher Error: ${err}`);
	console.log(`Generated Salt: ${salt}`);
	console.log(`Generated Hash: ${encrypted}`);
	console.log(`Salt Size: ${salt.length}`);
	console.log(`Hash Size: ${(encrypted).length}`);
	encrypt.compare(config.testPassword, encrypted, salt, (err: Error, isMatch: boolean) => {
		console.log(`Compare Error: ${err}`);
		console.log(`Match Password: ${isMatch}`);
	});
}).catch(err => console.log(`Cipher Error: ${err}`));