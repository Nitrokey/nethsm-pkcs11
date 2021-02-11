package main

import (
	"github.com/niclabs/tcrsa"
	"log"
)

// RSACreateKey creates a new key and saves its shares distributed among all the nodes.
func (dtc *DTC) RSACreateKey(keyID string, bitSize int, exponent int) (*tcrsa.KeyMeta, error) {
	dtc.Lock()
	defer dtc.Unlock()
	log.Printf("Creating new key with bitsize=%d, threshold=%d and nodes=%d", bitSize, dtc.Threshold, dtc.Nodes)
	keyShares, keyMeta, err := tcrsa.NewKey(bitSize, dtc.Threshold, dtc.Nodes, &tcrsa.KeyMetaArgs{E:exponent})
	if err != nil {
		return nil, err
	}
	log.Printf("Sending key shares with keyid=%s", keyID)
	if err := dtc.Connection.SendRSAKeyShares(keyID, keyShares, keyMeta); err != nil {
		return nil, err
	}
	log.Printf("Acking key shares related to keyid=%s", keyID)
	if err := dtc.Connection.AckRSAKeyShares(); err != nil {
		return nil, err
	}
	return keyMeta, nil
}

// RSASignData with a key name a byte hash, sending it to all the keyshare holders.
func (dtc *DTC) RSASignData(keyName string, meta *tcrsa.KeyMeta, data []byte) ([]byte, error) {
	dtc.Lock()
	defer dtc.Unlock()
	log.Printf("Signing data with key of id=%s", keyName)
	if err := dtc.Connection.AskForRSASigShares(keyName, data); err != nil {
		return nil, err
	}
	// We get the sig shares
	sigShareList, err := dtc.Connection.GetRSASigShares(int(meta.K))
	if err != nil {
		return nil, err
	}

	// We verify them
	for _, sigShare := range sigShareList {
		if err := sigShare.Verify(data, meta); err != nil {
			return nil, err
		}
	}
	// Finally We merge and return them
	return sigShareList.Join(data, meta)
}

// RSADeleteKey an old key deleting the key shares from all the nodes.
func (dtc *DTC) RSADeleteKey(keyID string) error {
	dtc.Lock()
	defer dtc.Unlock()
	log.Printf("Deleting key shares with keyid=%s", keyID)
	if err := dtc.Connection.AskForRSAKeyDeletion(keyID); err != nil {
		return err
	}
	log.Printf("Acking key shares deletion related to keyid=%s", keyID)
	return dtc.Connection.AckRSAKeyDeletion()
}
