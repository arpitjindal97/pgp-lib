package main

func DeleteKey(fingerprint, keytype string) string {
	if keytype == "private" {
		account := database.GetAccountByFingerprint(fingerprint)
		if account.Email != "" {
			return "This key is being used by " + account.Email
		}
	}
	database.DeleteKey(fingerprint)
	return "Done"
}
