package main

func AddAccount(email, fingerprint string) string {

	if database.GetAccount(email).Email == "" {
		database.AddAccount(email, fingerprint)
		return "Done"
	}
	return "Account already exists"
}

func EditAccount(email, fingerprint string) {
	database.UpdateAccount(email, fingerprint)
}

func DeleteAccount(email string) {
	database.DeleteAccount(email)
}
