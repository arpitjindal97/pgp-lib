package main

import (
	"bytes"
	"encoding/hex"
	"golang.org/x/crypto/openpgp"
	"io/ioutil"
	"strings"
)

func AddPrivateKey(path string, passphrase string) string {

	file, _ := ioutil.ReadFile(path)

	reader := bytes.NewReader(file)

	entityList, err := openpgp.ReadArmoredKeyRing(reader)

	if err != nil {
		return "Invalid Key file"
	}

	entity := entityList[0]
	entity.PrivateKey.Decrypt([]byte(passphrase))

	//w, err := armor.Encode(os.Stdout, openpgp.PrivateKeyType, nil)
	//defer w.Close()
	//entityList[0].SerializePrivate(w, nil)

	fingerprint := hex.EncodeToString(entity.PrimaryKey.Fingerprint[:])
	fingerprint = strings.ToUpper(fingerprint)

	if entity.PrivateKey.Encrypted {
		return "Error while decrypting keys"
	}
	if database.ExistsKey(fingerprint) {
		return "Already Exists"
	}
	database.InsertKey(fingerprint, string(file), "private", passphrase)

	return "Done"
}

func AddPublicKey(path string) string {

	file, _ := ioutil.ReadFile(path)

	reader := bytes.NewReader(file)

	entityList, err := openpgp.ReadArmoredKeyRing(reader)
	if err != nil {
		return "Invalid Key file"
	}
	entity := entityList[0]

	fingerprint := hex.EncodeToString(entity.PrimaryKey.Fingerprint[:])
	fingerprint = strings.ToUpper(fingerprint)

	if database.ExistsKey(fingerprint) {
		return "Already Exists"
	}
	database.InsertKey(fingerprint, string(file), "public", "")

	return "Done"
}
