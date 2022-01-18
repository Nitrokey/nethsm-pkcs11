package module

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
	Code        CK_RV
}

// NewError returns a new error. with the provided parameters.
func NewError(who, description string, code CK_RV) P11Error {
	if code == CK_RV(0) {
		code = CKR_GENERAL_ERROR
	}
	return P11Error{
		Who:         who,
		Description: description,
		Code:        code,
	}
}

// NewAPIError returns a new error. with the provided parameters.
func NewAPIError(who, f string, r *http.Response, err error) P11Error {
	desc := fmt.Sprintf("%v\n%v\n", f, err)
	desc += fmt.Sprintf("HTTP request: %+v\n", r.Request)
	desc += fmt.Sprintf("HTTP response: %+v\n", r)
	if r.StatusCode == 401 {
		return NewError(who, desc, CKR_PIN_INCORRECT)
	} else if r.StatusCode == 404 {
		return NewError(who, desc, CKR_ARGUMENTS_BAD)
	}
	return NewError(who, desc, CKR_GENERAL_ERROR)
}

func (err P11Error) Error() string {
	return fmt.Sprintf("%s: %s", err.Who, err.Description)
}
