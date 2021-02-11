package main

/*
#include "pkcs11go.h"
*/
import "C"
import (
	"fmt"
	"github.com/niclabs/dtc/v3/config"
)

type Storage interface {
	// Executes the logic necessary to initialize the storage.
	Init(slots []*config.SlotsConfig) error

	// Saves a token into the storage, or returns an error.
	SaveToken(*Token) error

	// Retrieves a token from the storage or returns an error.
	GetToken(string) (*Token, error)

	// Returns the biggest number of a handle in the storage.
	GetMaxHandle() (C.CK_ULONG, error)

	// Finalizes the use of the storage. The storage is not usable
	// If this method is called.
	Close() error
}

// NewDatabase retrieves a new database of the type dbType. Right now it only works with Sqlite type.
func NewDatabase(dbType string) (Storage, error) {
	switch dbType {
	case "sqlite3":
		sqliteConfig, err := GetSqlite3Config()
		if err != nil {
			return nil, fmt.Errorf("sqlite3 config not defined")
		}
		return GetDatabase(sqliteConfig.Path)
	default:
		return nil, NewError("NewDatabase", fmt.Sprintf("storage option not found: '%s'", dbType), 0)
	}
}
