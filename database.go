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
	create table identity (
		email text not null primary key,
		name text not null,
		fingerprint text not null
	);
	delete from identity;

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
	stmt, err := db.Prepare(sqlStmt)
	if err != nil {
		log.Fatal(err)
		return true
	}
	defer stmt.Close()

	var result string
	err = stmt.QueryRow(fingerprint).Scan(&result)
	if err != nil {
		return false
	}
	return true
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
