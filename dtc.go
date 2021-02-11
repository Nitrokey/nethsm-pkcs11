package main

import "C"
import (
	"fmt"
	"sync"

	"github.com/niclabs/dtc/v3/config"
	"github.com/niclabs/dtc/v3/network"
	"github.com/spf13/viper"
)

func init() {
	viper.SetConfigName("dtc-config")
	viper.AddConfigPath("./")
	viper.AddConfigPath("$HOME/.dtc")
	viper.AddConfigPath("/etc/dtc/")
	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("config file problem %v", err))
	}
}

// DTC represents the Distributed Threshold Criptography library. It manages on its own the nodes, and exposes a simple API to use it.
type DTC struct {
	sync.Mutex
	Connection network.Connection // The messenger DTC uses to communicate with the nodes.
	Threshold  uint16             // The threshold defined in the model.
	Nodes      uint16             // The total number of nodes used.
}

// NewDTC creates a new and ready DTC struct. It connects automatically to its nodes.
func NewDTC(config config.DTCConfig) (*DTC, error) {
	connection, err := NewConnection(config.MessagingType)
	if err != nil {
		return nil, err
	}
	dtc := &DTC{
		Threshold:  config.Threshold,
		Nodes:      config.NodesNumber,
		Connection: connection,
	}
	if err = connection.Open(); err != nil {
		return nil, err
	}
	return dtc, nil
}
