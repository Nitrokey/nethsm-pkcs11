package main

import (
	"crypto/ecdsa"
	"github.com/niclabs/tcecdsa"
	"log"
)

// ECDSACreateKey creates a new key and saves its shares distributed among all the nodes.
func (dtc *DTC) ECDSACreateKey(keyID string, curveName string) (*tcecdsa.KeyMeta, *ecdsa.PublicKey, error) {
	dtc.Lock()
	defer dtc.Unlock()
	log.Printf("Creating new key with curveName=%s, threshold=%d and nodes=%d", curveName, dtc.Threshold, dtc.Nodes)
	keyShares, keyMeta, err := tcecdsa.NewKey(uint8(dtc.Nodes), uint8(dtc.Threshold), curveName, nil)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("Sending key shares with keyid=%s", keyID)
	if err := dtc.Connection.SendECDSAKeyShares(keyID, keyShares, keyMeta); err != nil {
		return nil, nil, err
	}
	log.Printf("Receiving keyInit messages from keyid=%s", keyID)
	keyInitMessageList, err := dtc.Connection.GetECDSAKeyInitMessageList()
	if err != nil {
		return nil, nil, err
	}
	pk, err := keyMeta.GetPublicKey(keyInitMessageList)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("Sending keyInit messages for keyid=%s", keyID)
	if err := dtc.Connection.SendECDSAKeyInitMessageList(keyID, keyInitMessageList); err != nil {
		return nil, nil, err
	}
	log.Printf("Acking keyInit message reception for keyid=%s", keyID)
	if err := dtc.Connection.AckECDSAKeyInitReception(); err != nil {
		return nil, nil, err
	}
	return keyMeta, pk, nil
}

// ECDSASignData with a key name a byte hash, sending it to all the keyshare holders.
func (dtc *DTC) ECDSASignData(keyID string, meta *tcecdsa.KeyMeta, data []byte) ([]byte, error) {
	dtc.Lock()
	defer dtc.Unlock()
	log.Printf("Sending Round 1 messages...")
	if err := dtc.Connection.AskForECDSARound1MessageList(keyID, data); err != nil {
		return nil, err
	}
	log.Printf("Receiving Round 1 responses...")
	nodeIDs, round1List, err := dtc.Connection.GetECDSARound1MessageList(int(meta.Paillier.K))
	if err != nil {
		return nil, err
	}

	//Round 2
	log.Printf("Sending Round 2 messages...")
	if err := dtc.Connection.AskForECDSARound2MessageList(nodeIDs, round1List); err != nil {
		return nil, err
	}
	log.Printf("Receiving Round 2 responses...")
	round2List, err := dtc.Connection.GetECDSARound2MessageList(int(meta.Paillier.K))
	if err != nil {
		return nil, err
	}

	// Round 3
	log.Printf("Sending Round 3 messages...")
	if err := dtc.Connection.AskForECDSARound3MessageList(nodeIDs, round2List); err != nil {
		return nil, err
	}
	log.Printf("Receiving Round 3 responses...")
	round3List, err := dtc.Connection.GetECDSARound3MessageList(int(meta.Paillier.K))
	if err != nil {
		return nil, err
	}

	// GetSignature
	log.Printf("Sending Round 4 (getSignature) messages...")
	if err := dtc.Connection.AskForECDSASignature(nodeIDs, round3List); err != nil {
		return nil, err
	}
	log.Printf("Receiving Round 4 (getSignature) responses...")
	r, s, err := dtc.Connection.GetECDSASignature(int(meta.Paillier.K))
	if err != nil {
		return nil, err
	}
	// https://www.oasis-open.org/committees/download.php/50389/CKM_ECDSA_FIPS_186_4_v03.pdf section 2.3.1
	// >>> The signature octets correspond to the concatenation of the ECDSA values r and s,
	// >>> both represented as an octet string of equal length of at most nLen with the most
	// >>> significant byte first. If r and s have different octet length, the shorter of both
	// >>> must be padded with leading zero octets such that both have the same octet length.
	// >>> Loosely spoken, the first half of the signature is r and the second half is s.
	// >>> For signatures created by a token, the resulting signature is always of length 2nLen.
	rBytes, sBytes := r.Bytes(), s.Bytes()
	sigSize := 2 * int((meta.Curve().Params().BitSize + 7) / 8)
	if len(rBytes) > sigSize/2 || len(sBytes) > sigSize/2 {
		return nil, NewError("DTC.ECDSASignData", "R and S length should be the same as the signature Size", 0)
	}
	sig := make([]byte, sigSize)
	copy(sig[sigSize/2-len(rBytes):sigSize/2], rBytes)
	copy(sig[sigSize-len(rBytes):sigSize], sBytes)
	return sig, nil
}

// ECDSADeleteKey deletes the key shares of the key with id = keyID from all the nodes.
func (dtc *DTC) ECDSADeleteKey(keyID string) error {
	dtc.Lock()
	defer dtc.Unlock()
	log.Printf("Deleting key shares with keyid=%s", keyID)
	if err := dtc.Connection.AskForECDSAKeyDeletion(keyID); err != nil {
		return err
	}
	log.Printf("Acking key shares deletion related to keyid=%s", keyID)
	return dtc.Connection.AckECDSAKeyDeletion()
}
