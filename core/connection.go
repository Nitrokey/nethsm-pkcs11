package core

import (
	"fmt"

	"p11nethsm/config"
	"p11nethsm/network"
	"p11nethsm/network/zmq"
)

// Creates a new connection of type "connType". Currently only zmq is implemented.
func NewConnection(connType string) (conn network.Connection, err error) {
	switch connType {
	case "zmq":
		zmqConfig, err1 := config.GetZMQConfig()
		if err1 != nil {
			err = err1
			return
		}
		conn, err1 = zmq.New(zmqConfig)
		if err1 != nil {
			err = err1
			return
		}
		return conn, nil
	default:
		err = NewError("NewConnection", fmt.Sprintf("network option not found: '%s'", connType), 0)
		return
	}
}
