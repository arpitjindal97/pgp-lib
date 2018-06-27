package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
)

var database Database

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

func GetKeyList(keytype string) []Entity {
	keys := database.ListKeys(keytype)

	myEntity := []Entity{}

	for _, key := range keys {
		//log.Printf("Key at %d is: %q", i, key)

		reader := bytes.NewReader([]byte(key.Keyblock))
		entityList, _ := openpgp.ReadArmoredKeyRing(reader)
		entity := entityList[0]

		fingerprint := hex.EncodeToString(entity.PrimaryKey.Fingerprint[:])
		fingerprint = strings.ToUpper(fingerprint)
		myIdentity := []Identity{}
		bits, _ := entity.PrimaryKey.BitLength()
		keyBits := strconv.FormatUint(uint64(bits), 10) + " bits"

		algo := KeyAlgoString(entity.PrimaryKey.PubKeyAlgo) + ", " + keyBits

		for _, iden := range entity.Identities {
			if len(iden.Signatures) != 0 {

				sig := iden.Signatures[len(iden.Signatures)-1]
				if sig.RevocationReasonText != "" {
					continue
				}
			}
			myIdentity = append(myIdentity, Identity{iden.UserId.Name, iden.UserId.Comment, iden.UserId.Email})
		}
		myEntity = append(myEntity, Entity{myIdentity, fingerprint, algo})

	}
	return myEntity

}

func GetKeyListEmail(email, keytype string) []Entity {
	entityList := GetKeyList(keytype)
	for i := 0; i < len(entityList); i++ {
		var containsEmail = false
		for _, iden := range entityList[i].Identities {
			if iden.Email == email {
				containsEmail = true
				break
			}
		}
		if !containsEmail {
			entityList = append(entityList[:i], entityList[(i+1):]...)
			i = i - 1
		}
	}
	return entityList

}

func main() {
	database := Database{}

	database.CreateDatabase()
	resp := AddPublicKey("/home/arpit/Desktop/gpg-dev/public_arpit.key")
	log.Printf("Response : %s\n", resp)
	entityList := GetKeyListEmail("arpitjindal97@gmail.com", "public")
	log.Printf("Entity : %q\n", entityList)
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
