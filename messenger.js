"use strict";

/** ******* Imports ********/

const {
	/* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
	bufferToString,
	genRandomSalt,
	generateEG, // async
	computeDH, // async
	verifyWithECDSA, // async
	HMACtoAESKey, // async
	HMACtoHMACKey, // async
	HKDF, // async
	encryptWithGCM, // async
	decryptWithGCM,
	cryptoKeyToJSON, // async
	govEncryptionDataStr,
	signWithECDSA,
} = require("./lib");

/** ******* Implementation ********/

class MessengerClient {
	constructor(certAuthorityPublicKey, govPublicKey) {
		// the certificate authority DSA public key is used to
		// verify the authenticity and integrity of certificates
		// of other users (see handout and receiveCertificate)

		// you can store data as needed in these objects.
		// Feel free to modify their structure as you see fit.
		this.caPublicKey = certAuthorityPublicKey;
		this.govPublicKey = govPublicKey;
		this.conns = {}; // data for each active connection
		this.certs = {}; // certificates of other users
		this.EGKeyPair = {}; // keypair from generateCertificate
	}

	/**
	 * Generate a certificate to be stored with the certificate authority.
	 * The certificate must contain the field "username".
	 *
	 * Arguments:
	 *   username: string
	 *
	 * Return Type: certificate object/dictionary
	 */
	async generateCertificate(username) {
		this.EGKeyPair = await generateEG();
		const certificate = {
			username: username,
			pubKey: this.EGKeyPair.pub,
		};
		return certificate;
	}

	/**
	 * Receive and store another user's certificate.
	 *
	 * Arguments:
	 *   certificate: certificate object/dictionary
	 *   signature: ArrayBuffer
	 *
	 * Return Type: void
	 */
	async receiveCertificate(certificate, signature) {
		// The signature will be on the output of stringifying the certificate
		// rather than on the certificate directly.
		const certString = JSON.stringify(certificate);
		const verified = await verifyWithECDSA(
			this.caPublicKey,
			certString,
			signature
		);

		if (!verified) {
			throw new Error("Certificate invalid!");
		}

		this.certs[certificate.username] = certificate;
	}

	/**
	 * Generate the message to be sent to another user.
	 *
	 * Arguments:
	 *   name: string
	 *   plaintext: string
	 *
	 * Return Type: Tuple of [dictionary, ArrayBuffer]
	 */
	async sendMessage(name, plaintext) {
		/* See section 3.1 https://signal.org/docs/specifications/doubleratchet/ */
		// DH(dh_pair, dh_pub)
		// EG key pair used to derive initial root key
		if (!this.conns[name]) {
			// stores the ratchet key pair, the public key of the other user, and the root key
			this.conns[name] = {
				rootKey: null,
				ratchetSec: this.EGKeyPair.sec,
				ratchetPub: this.EGKeyPair.pub,
				pubKey: this.certs[name].pubKey,
				n: 0, // message number
				msgKeySkipped: {}, // store n: msgKey for skipped messages
			};
		} else {
			let keyPair = await generateEG();
			this.conns[name].ratchetSec = keyPair.sec; // update ratchet key pair
			this.conns[name].ratchetPub = keyPair.pub; // update ratchet key pair
		}
		let {rootKey, ratchetSec, ratchetPub, pubKey, n, msgKeySkipped} =
			this.conns[name];
		let dh_out = await computeDH(ratchetSec, pubKey);
		if (!rootKey) {
			rootKey = dh_out;
		}
		// KDF_RK(rk, dh_out)
		// HKDF with SHA, rk = HKDF salt, dh_out = HKDF input key material
		let chainKey;
		[rootKey, chainKey] = await HKDF(dh_out, rootKey, "constant 1");

		// KDF_CK(ck)
		// HMAC with SHA, ck = HMAC key
		let msgKey = await HMACtoAESKey(chainKey, "constant 2");
		let msgKeyBuf = await HMACtoAESKey(chainKey, "constant 2", true);
		chainKey = await HMACtoHMACKey(chainKey, "constant 3");

		/* Government backdoor: ElGamal with AES-GCM under gov public key */
		let ivGov = genRandomSalt(16);
		let vGov = ratchetPub;
		let govKey = await computeDH(ratchetSec, this.govPublicKey); // Elgamal (see pg. 455)
		govKey = await HMACtoAESKey(govKey, govEncryptionDataStr);
		let cGov = await encryptWithGCM(govKey, msgKeyBuf, ivGov);

		// ENCRYPT(mk, plaintext, AD), disregard AD
		// AES-GCM
		const receiverIV = genRandomSalt(16);

		const header = {
			receiverIV: receiverIV,
			cGov: cGov,
			vGov: vGov,
			ivGov: ivGov,
			pubKey: ratchetPub,
			n: n,
		};

		const ciphertext = await encryptWithGCM(
			msgKey,
			plaintext,
			receiverIV,
			JSON.stringify(header)
		); // use header as AD

		// update sendChain
		n += 1;
		this.conns[name] = {rootKey, ratchetSec, ratchetPub, pubKey, sendChain};

		return [header, ciphertext];
	}

	/**
	 * Decrypt a message received from another user.
	 *
	 * Arguments:
	 *   name: string
	 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
	 *
	 * Return Type: string
	 */
	async receiveMessage(name, [header, ciphertext]) {
		// derive msgKey
		if (!this.conns[name]) {
			this.conns[name] = {
				rootKey: null,
				ratchetPub: null,
				ratchetSec: null,
				pubKey: this.certs[name].pubKey,
				recvChain: {key: null, n: 0},
			};
		} else {
			this.conns[name].pubKey = header.pubKey; // update ratchet pubKey
		}
		let privKey = !this.conns[name].ratchetSec
			? this.EGKeyPair.sec
			: this.conns[name].ratchetSec;
		let dh_out = await computeDH(privKey, this.conns[name].pubKey);
		let {rootKey, ratchetSec, ratchetPub, pubKey, recvChain} = this.conns[name];
		if (!rootKey) {
			rootKey = dh_out;
		}

		let chainKey;
		[rootKey, chainKey] = await HKDF(dh_out, rootKey, "constant 1");
		let msgKey = await HMACtoAESKey(chainKey, "constant 2");
		chainKey = await HMACtoHMACKey(chainKey, "constant 3");
		this.conns[name] = {rootKey, ratchetSec, ratchetPub, pubKey};

		// DECRYPT
		// throw an error if GCM detects tampering
		let plaintext;
		try {
			plaintext = await decryptWithGCM(
				msgKey,
				ciphertext,
				header.receiverIV,
				JSON.stringify(header)
			);
		} catch (e) {
			throw new Error("tampering detected!");
		}

		plaintext = bufferToString(plaintext);
		// console.log(plaintext);
		return plaintext;
	}
}

module.exports = {
	MessengerClient,
};
