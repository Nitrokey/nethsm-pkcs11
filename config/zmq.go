package config

import (
	"github.com/spf13/viper"
)

// ZMQConfig represents a ZMQ network configuration.
// The configuration must have an asymmetric key pair, because the connections are only
// done in ZMQ CURVE Auth mode (Ironhouse mode as of the ZMQ security tutorial)
type ZMQConfig struct {
	PublicKey  string        // PublicKey used in ZMQ Curve Auth
	PrivateKey string        // PrivateKey used in ZMQ Curve Auth
	Nodes      []*NodeConfig // A list with the nodes configuration.
	Timeout    uint16        // The max time the system waits for an answer when sends a message to the nodes.
}

// NodeConfig represents the basic connection data the server requires to connect to a node: its public key (for ZMQ CURVE Auth), its IP and the port where it is listening its message.
type NodeConfig struct {
	PublicKey string
	Host      string
	Port      uint16
}

// GetZMQConfig returns the ZMQ Configuration defined in the config file.
func GetZMQConfig() (*ZMQConfig, error) {
	var conf ZMQConfig
	err := viper.UnmarshalKey("dtc.zmq", &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
