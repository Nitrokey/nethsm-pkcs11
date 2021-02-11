package main

/*
#include "pkcs11go.h"
*/
import "C"
import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/niclabs/dtc/v3/config"
	"github.com/spf13/viper"
	"log"
	"sync"
)

// Sqlite3DB is a wrapper over a sql.Sqlite3DB object, complying with storage
// interface.
type Sqlite3DB struct {
	sync.Mutex
	*sql.DB
	MaxHandle int
}

// Returns the defined sqlite3 configuration.
func GetSqlite3Config() (*config.Sqlite3Config, error) {
	var conf config.Sqlite3Config
	err := viper.UnmarshalKey("dtc.sqlite3", &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}

func (db *Sqlite3DB) Init(slots []*config.SlotsConfig) error {
	if err := db.createTablesIfNotExist(); err != nil {
		return fmt.Errorf("create tables: %v", err)
	}
	if err := db.insertTokens(slots); err != nil {
		return fmt.Errorf("insert first token: %v", err)
	}
	return nil
}

func (db *Sqlite3DB) SaveToken(token *Token) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	// Preparing statements
	tokenStmt, err := tx.Prepare(InsertTokenQuery)
	if err != nil {
		return err
	}
	objectStmt, err := tx.Prepare(InsertCryptoObjectQuery)
	if err != nil {
		return err
	}
	attrStmt, err := tx.Prepare(InsertAttributeQuery)
	if err != nil {
		return err
	}
	// Cleaning old CryptoObjects
	cleanObjectStmt, err := tx.Prepare(CleanCryptoObjectQuery)
	if err != nil {
		return err
	}
	if _, err := cleanObjectStmt.Exec(token.Label); err != nil {
		return err
	}
	// Cleaning old attributes
	cleanAttrsStmt, err := tx.Prepare(CleanAttributesQuery)
	if err != nil {
		return err
	}
	if _, err := cleanAttrsStmt.Exec(token.Label); err != nil {
		return err
	}
	// Saving the token
	if _, err := tokenStmt.Exec(token.Label, token.Pin, token.SoPin); err != nil {
		return err
	}
	// Saving the CryptoObjects
	for _, object := range token.Objects {
		if object.Handle == 0 {
			actualHandle, err := db.GetMaxHandle()
			if err != nil {
				return err
			}
			object.Handle = actualHandle + 1
		}
		if _, err := objectStmt.Exec(token.Label, object.Handle); err != nil {
			return err
		}
		// Saving the attributes
		for _, attr := range object.Attributes {
			if _, err := attrStmt.Exec(token.Label, object.Handle, attr.Type, attr.Value); err != nil {
				return err
			}
		}
	}
	// Committing
	return tx.Commit()
}

func (db *Sqlite3DB) GetToken(label string) (token *Token, err error) {
	// Retrieve token
	tokenStmt, err := db.Prepare(GetTokenQuery)
	if err != nil {
		return
	}
	var pin, soPin string
	err = tokenStmt.QueryRow(label).Scan(&pin, &soPin)
	if err != nil {
		return
	}
	token = &Token{
		Label:   label,
		Pin:     pin,
		SoPin:   soPin,
		Objects: make(CryptoObjects, 0),
	}

	attrsStmt, err := db.Prepare(GetCryptoObjectAttrsQuery)
	if err != nil {
		return
	}
	rows, err := attrsStmt.Query(label)
	if err != nil {
		return
	}
	defer rows.Close()
	var aHandle int
	var aType sql.NullInt64
	var aValue []byte
	objects := make(map[int]*CryptoObject)
	for rows.Next() {
		err = rows.Scan(&aHandle, &aType, &aValue)
		if err != nil {
			return
		}
		object, ok := objects[aHandle]
		if !ok {
			object = &CryptoObject{
				Handle:     C.CK_OBJECT_HANDLE(aHandle),
				Attributes: make(Attributes),
			}
			objects[aHandle] = object
		}
		if aType.Valid && aValue != nil {
			object.Attributes[uint32(aType.Int64)] = &Attribute{
				Type:  uint32(aType.Int64),
				Value: aValue,
			}
		}
	}
	for _, object := range objects {
		token.Objects = append(token.Objects, object)
	}
	return
}

func (db *Sqlite3DB) GetMaxHandle() (C.CK_ULONG, error) {
	db.Lock()
	defer db.Unlock()
	err := db.updateMaxHandle()
	if err != nil {
		log.Printf("cannot get max handle")
		return 0, err
	}
	return C.CK_ULONG(db.MaxHandle), nil
}

func (db *Sqlite3DB) Close() error {
	return db.Close()
}

func GetDatabase(path string) (Storage, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	return &Sqlite3DB{
		DB: db,
	}, nil
}

func (db *Sqlite3DB) createTablesIfNotExist() error {
	for _, stmt := range CreateStmts {
		_, err := db.Exec(stmt)
		if err != nil {
			return fmt.Errorf("in stmt %s: %v", stmt, err)
		}
	}
	return nil
}

func (db *Sqlite3DB) insertTokens(slots []*config.SlotsConfig) error {
	stmt, err := db.Prepare(InsertTokenQuery)
	if err != nil {
		return err
	}
	if len(slots) == 0 {
		slots = []*config.SlotsConfig{{}}
	}
	for _, token := range slots {
		if len(token.Label) == 0 {
			token.Label = "TCBHSM"
		}
		if len(token.Pin) == 0 {
			token.Pin = "1234" // Default PIN
		}
		_, err = stmt.Exec(token.Label, token.Pin, token.Pin)
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *Sqlite3DB) updateMaxHandle() error {
	rows, err := db.Query(GetMaxHandleQuery)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		var maxHandle sql.NullInt64
		if err := rows.Scan(&maxHandle); err != nil {
			return err
		}
		if maxHandle.Valid {
			db.MaxHandle = int(maxHandle.Int64)
		} else {
			db.MaxHandle = 0
		}
	} else {
		return rows.Err()
	}
	return nil
}
