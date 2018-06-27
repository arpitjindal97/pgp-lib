package main

import (
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"log"
	"os"
)

var database Database

func main() {
	database := Database{}

	database.CreateDatabase()

	resp := AddPrivateKey("/home/arpit/Desktop/gpg-dev/private_arpit.key", "hiddenpass")
	log.Printf("Response : %s\n", resp)

	entityList := GetKeyListEmail("arpitjindal97@gmail.com", "private")
	log.Printf("Entity : %q\n", entityList)

	resp = AddAccount("arpitjindal97@gmail.com", "")
	log.Printf("AddAccount Response : %s\n", resp)

	EditAccount("arpitjindal97@gmail.com", "6AE70B2D3ADCD2C6723706A08DE39E0CFDAB3322")

	resp = DeleteKey("6AE70B2D3ADCD2C6723706A08DE39E0CFDAB3322", "private")
	log.Printf("Delete Response : %s\n", resp)

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
