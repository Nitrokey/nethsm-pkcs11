package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	Cryptoki CryptokiConfig // Cryptoki related configuration
}

// CryptokiConfig represents the configuration specific to Cryptoki API.
type CryptokiConfig struct {
	SerialNumber    string         // String that will be shown as Serial Number
	MinPinLength    uint8          // String that will be used as Min Pin SignatureLength
	MaxPinLength    uint8          // String that will be used as Max Pin SignatureLength
	MaxSessionCount uint16         // String that will be used as Max Session Count
	DatabaseType    string         // Type of database used for saving cryptoki info. Right now only is usable "sqlite3".
	Slots           []*SlotsConfig // List of slots open.
}

// SlotsConfig defines the slots the HSM has.
type SlotsConfig struct {
	Description string
	Label       string // ID of the Token inserted on this slot. It must exist on the HSM.
	URL         string
	User        string
	Password    string // Password to configure in Token
	Pin         string
}

// GetConfig returns the configuration extracted from the common config file.
func GetConfig() (*Config, error) {
	var conf Config
	err := viper.Unmarshal(&conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
