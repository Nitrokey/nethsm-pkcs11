package config

import (
	"github.com/spf13/viper"
)

// ZMQConfig defines the global configuration file.
type Config struct {
	DTC      DTCConfig      // DTC related configuration
	Criptoki CriptokiConfig // Criptoki related configuration
}

// DTCConfig manages the configuration related with this implementation, as the messaging type, nodes number and threshold.
type DTCConfig struct {
	MessagingType string // Type of messaging system. Currently only "zmq" is implemented.
	NodesNumber   uint16 // Number of nodes configured
	Threshold     uint16 // Minimum number of nodes that need to sign to validate a signature.
}

// CriptokiConfig represents the configuration specific to Criptoki API.
type CriptokiConfig struct {
	ManufacturerID  string         // String that will be shown as Manufacturer ID
	Model           string         // String that will be shown as Model
	Description     string         // String that will be shown as Description
	SerialNumber    string         // String that will be shown as Serial Number
	MinPinLength    uint8          // String that will be used as Min Pin SignatureLength
	MaxPinLength    uint8          // String that will be used as Max Pin SignatureLength
	MaxSessionCount uint16         // String that will be used as Max Session Count
	DatabaseType    string         // Type of database used for saving criptoki info. Right now only is usable "sqlite3".
	Slots           []*SlotsConfig // List of slots open.
}

// SlotsConfig defines the slots the HSM has.
type SlotsConfig struct {
	Label string // ID of the Token inserted on this slot. It must exist on the HSM.
	Pin   string // Password to configure in Token
}

// GetConfig returns the configuration extracted from the common config file.
func GetConfig() (*Config, error) {
	var conf Config
	err := viper.UnmarshalKey("dtc.general", &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
