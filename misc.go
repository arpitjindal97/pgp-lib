package main

import (
	"golang.org/x/crypto/openpgp/packet"
)

type Entity struct {
	Identities  []Identity
	Fingerprint string
	Algorithm   string
}

type Identity struct {
	Name    string
	Comment string
	Email   string
}

type Key struct {
	Fingerprint string
	Keyblock    string
	Keytype     string
	Passphrase  string
}

type Account struct {
	Email       string
	Fingerprint string
}

func KeyAlgoString(algo packet.PublicKeyAlgorithm) string {

	switch algo {
	case packet.PubKeyAlgoRSA:
		return "RSA"
	case packet.PubKeyAlgoRSAEncryptOnly:
		return "RSAEncryptOnly"
	case packet.PubKeyAlgoRSASignOnly:
		return "RSASignOnly"
	case packet.PubKeyAlgoElGamal:
		return "ElGamal"
	case packet.PubKeyAlgoDSA:
		return "DSA"
	case packet.PubKeyAlgoECDH:
		return "ECDH"
	case packet.PubKeyAlgoECDSA:
		return "ECDSA"
	default:
		return "Unknown"
	}
}
