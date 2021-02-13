package core

/*
#include "pkcs11go.h"
*/
import "C"
import (
	"fmt"
	"net/http"
)

// P11Error represents an error from the library.
// It contains the method where the error occured, a description of the error
// and the Cryptoki return value related to the error.
type P11Error struct {
	Who         string
	Description string
	Code        C.CK_RV
}

// NewError returns a new error. with the provided parameters.
func NewError(who, description string, code C.CK_RV) P11Error {
	if code == C.CK_RV(0) {
		code = C.CKR_GENERAL_ERROR
	}
	return P11Error{
		Who:         who,
		Description: description,
		Code:        code,
	}
}

// NewAPIError returns a new error. with the provided parameters.
func NewAPIError(who, f string, r *http.Response, err error) P11Error {
	desc := fmt.Sprintf("Error when calling '%v': %v\n%v\n", who, f, err)
	desc += fmt.Sprintf("HTTP request: %+v\n", r.Request)
	desc += fmt.Sprintf("HTTP response: %+v\n", r)
	if r.StatusCode == 401 {
		return NewError(who, desc, C.CKR_PIN_INCORRECT)
	}
	return NewError(who, desc, C.CKR_DEVICE_ERROR)
}

func (err P11Error) Error() string {
	return fmt.Sprintf("%s: %s", err.Who, err.Description)
}
