package main

import (
	database "./database"
	"bytes"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"io/ioutil"
	"log"
	"os"
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

	if database.ExistsKey(fingerprint) {
		return "Already Exists"
	}
	database.InsertKey(fingerprint, string(file), "public", "")

	return "Done"
}
func main() {
	database.CreateDatabase()
	resp := AddPublicKey("/home/arpit/Desktop/gpg-dev/public_arpit.key")
	log.Printf("Response : %s\n", resp)
}

func main1() {
	var e *openpgp.Entity
	e, err := openpgp.NewEntity("itis", "test", "itis@itis3.com", nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Add more identities here if you wish

	// Sign all the identities
	for _, id := range e.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, nil)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	w, err := armor.Encode(os.Stdout, openpgp.PublicKeyType, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer w.Close()

	e.Serialize(w)

	finger := string(e.PrimaryKey.Fingerprint[:])
	fmt.Println(e.PrimaryKey.Fingerprint)
	log.Println(finger)
}
