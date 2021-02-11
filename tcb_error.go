package main

/*
#include "pkcs11go.h"
*/
import "C"
import "fmt"

// TCBError represents an error from the library.
// It contains the method where the error occured, a description of the error
// and the Criptoki return value related to the error.
type TcbError struct {
	Who         string
	Description string
	Code        C.CK_RV
}

// NewError returns a new error. with the provided parameters.
func NewError(who, description string, code C.CK_RV) TcbError {
	if code == C.CK_RV(0) {
		code = C.CKR_GENERAL_ERROR
	}
	return TcbError{
		Who:         who,
		Description: description,
		Code:        code,
	}
}

func (err TcbError) Error() string {
	return fmt.Sprintf("%s: %s", err.Who, err.Description)
}
