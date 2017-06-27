import {
	createCipher, createDecipher,
	randomBytes
} from 'crypto';
import { CipherOptions, CallBack } from "./types";


const defaultOptions: CipherOptions = {
	saltSize: 128,
	encoded: 'hex',
	algorithm: 'aes-256-cbc-hmac-sha256'
};

class PassCipher {

	options: CipherOptions;

	constructor(options?: CipherOptions) {
		this.options = { ...defaultOptions, ...(options || {}) };
	}

	get config() {
		return this.options;
	}

	randomSalt(size?: number) {
		return randomBytes(size || defaultOptions.saltSize).toString(this.options.encoded);
	}

	cipher(passphrase: string): Promise<string>;
	cipher(passphrase: string, cb: CallBack): void;
	cipher(passphrase: string, salt: string): Promise<string>;
	cipher(passphrase: string, salt: string, cb: CallBack): void;
	cipher(passphrase: string, salt?: string | CallBack, cb?: CallBack) {
		if (!passphrase) {
			const err = new Error('The passphrase must by provided.');
			return result<null>(err, null, cb);
		}
		try {
			salt = typeof salt === 'function' ? this.randomSalt() : salt;
			return result<string>(null, this.cipherSync(passphrase, salt), cb);
		} catch (err) {
			return result<null>(err, null, cb);
		}
	}

	cipherSync(passphrase: string, salt?: string) {
		if (!passphrase) {
			throw new Error('The passphrase must by provided.');
		}
		let cipher = createCipher(this.options.algorithm, passphrase);
		salt = salt || this.randomSalt();
		let encrypted = cipher.update(salt, 'utf8', this.options.encoded);
		encrypted += cipher.final(this.options.encoded);
		return encrypted;
	}

	compareSync(testPassprhase: string, encrypted: string, salt: string) {
		if (!testPassprhase || !encrypted || !salt) {
			throw new Error('The testPassprhase, encrypted and salt must by provided.');
		}
		let decipher = createDecipher(this.options.algorithm, testPassprhase);
		let decrypted = decipher.update(encrypted, this.options.encoded, 'utf8');
		decrypted += decipher.final('utf8');
		return decrypted === salt;
	}

	compare(testPassprhase: string, encrypted: string, salt: string): Promise<boolean>;
	compare(testPassprhase: string, encrypted: string, salt: string, cb: CallBack): void;
	compare(testPassprhase: string, encrypted: string, salt: string, cb?: CallBack) {
		if (!testPassprhase || !encrypted || !salt) {
			const err = new Error('The testPassprhase, encrypted and salt must by provided.');
			return result<null>(err, null, cb);
		}
		try {
			return result<boolean>(null, this.compareSync(testPassprhase, encrypted, salt), cb);
		} catch (err) {
			return result<null>(err, null, cb);
		}
	}
}

function result<V>(err: Error, value: V, cb: CallBack) {
	if (cb) {
		if (err) {
			cb(err, null);
		} else {
			cb(null, value);
		}
		return;
	} else {
		return err ? Promise.reject(err) : Promise.resolve(value);
	}
}

export = PassCipher;