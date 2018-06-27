package main

import (
	"bytes"
	"encoding/hex"
	"golang.org/x/crypto/openpgp"
	"strconv"
	"strings"
)

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
