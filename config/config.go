package config

import (
	"fmt"

	"github.com/spf13/viper"
)

var conf Config

func init() {
	viper.SetConfigName("p11nethsm.conf")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("$PWD")
	viper.AddConfigPath("$HOME/.nitrokey")
	viper.AddConfigPath("/etc/nitrokey")
	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("Failed to read config file: %v", err))
	}
	sub := viper.Sub("p11nethsm")
	if sub == nil {
		panic(fmt.Errorf("Failed to parse config: no p11nethsm entry"))
	}
	if err := sub.UnmarshalExact(&conf); err != nil {
		panic(fmt.Errorf("Failed to parse config: %v", err))
	}
}

// CryptokiConfig represents the configuration specific to Cryptoki API.
type Config struct {
	LogFile         string
	MaxSessionCount uint16 // String that will be used as Max Session Count
	Debug           bool
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
	CertSHA256  string
	Sparse      bool
}

// GetConfig returns the configuration extracted from the common config file.
func Get() *Config {
	return &conf
}
