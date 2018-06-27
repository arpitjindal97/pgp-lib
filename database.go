package main

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"log"
)

type Database struct {
}

func (*Database) CreateDatabase() {

	db, err := sql.Open("sqlite3", "./foo.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	sqlStmt := `
	create table account (
		email text not null primary key,
		fingerprint text not null
	);
	delete from account;

	create table keys (
		fingerprint text not null primary key,
		keyblock text not null,
		keytype text not null,
		passphrase text
	);
	delete from keys;
	`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		return
	}
}

func (*Database) InsertKey(fingerprint, keyblock, keytype, passphrase string) {
	db, err := sql.Open("sqlite3", "./foo.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("insert into keys values(?,?,?,?)")
	defer stmt.Close()

	stmt.Exec(fingerprint, keyblock, keytype, passphrase)

	tx.Commit()

}

func (*Database) ExistsKey(fingerprint string) bool {
	db, err := sql.Open("sqlite3", "./foo.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	sqlStmt := `
	select fingerprint from keys where fingerprint = ?
	`
	stmt, _ := db.Prepare(sqlStmt)
	defer stmt.Close()

	var result string
	err = stmt.QueryRow(fingerprint).Scan(&result)
	if err != nil {
		return false
	}
	return true
}

func (*Database) GetKey(fingerprint string) string {
	db, err := sql.Open("sqlite3", "./foo.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	sqlStmt := `
	select keyblock from keys where fingerprint = ?
	`
	stmt, _ := db.Prepare(sqlStmt)
	defer stmt.Close()

	var result string
	err = stmt.QueryRow(fingerprint).Scan(&result)
	if err != nil {
		return ""
	}
	return result
}

func (*Database) ListKeys(keytype string) []Key {

	db, err := sql.Open("sqlite3", "./foo.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	stmt, _ := db.Prepare("select fingerprint,keyblock,keytype,passphrase from keys where keytype = ?")
	defer stmt.Close()
	rows, err := stmt.Query(keytype)

	var key []Key
	if err != nil {
		log.Fatal(err)
		return key
	}

	for rows.Next() {
		var fingerprint, keyblock, keytype, passphrase string
		_ = rows.Scan(&fingerprint, &keyblock, &keytype, &passphrase)
		new_key := Key{fingerprint, keyblock, keytype, passphrase}

		key = append(key, new_key)

	}
	return key
}

func (*Database) DeleteKey(fingerprint string) {
	db, err := sql.Open("sqlite3", "./foo.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("delete from keys where fingerprint = ?")
	defer stmt.Close()

	stmt.Exec(fingerprint)

	tx.Commit()
}

func (*Database) GetAccount(email string) Account {
	db, err := sql.Open("sqlite3", "./foo.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	stmt, _ := db.Prepare("select fingerprint from account where email = ?")
	defer stmt.Close()
	var fingerprint string
	err = stmt.QueryRow(email).Scan(&fingerprint)
	if err != nil {
		return Account{"", ""}
	}
	return Account{email, fingerprint}

}

func (*Database) GetAccountByFingerprint(fingerprint string) Account {
	db, err := sql.Open("sqlite3", "./foo.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	stmt, _ := db.Prepare("select email from account where fingerprint = ?")
	defer stmt.Close()
	var email string
	err = stmt.QueryRow(fingerprint).Scan(&email)
	if err != nil {
		return Account{"", ""}
	}
	return Account{email, fingerprint}

}

func (*Database) AddAccount(email, fingerprint string) {
	db, err := sql.Open("sqlite3", "./foo.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("insert into account values(?,?)")
	defer stmt.Close()

	stmt.Exec(email, fingerprint)

	tx.Commit()
}

func (*Database) DeleteAccount(email string) {
	db, err := sql.Open("sqlite3", "./foo.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("delete from account where email = ?")
	defer stmt.Close()

	stmt.Exec(email)

	tx.Commit()
}

func (*Database) UpdateAccount(email, fingerprint string) {
	database.DeleteAccount(email)
	database.AddAccount(email, fingerprint)
}
