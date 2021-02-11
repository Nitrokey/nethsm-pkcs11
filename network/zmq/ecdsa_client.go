package zmq

import (
	"fmt"
	"log"
	"math/big"

	"github.com/niclabs/dtcnode/v3/message"
	"github.com/niclabs/tcecdsa"
)

func (client *Client) SendECDSAKeyShares(keyID string, keys []*tcecdsa.KeyShare, meta *tcecdsa.KeyMeta) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if len(client.nodes) != client.numNodes {
		return fmt.Errorf("all %d nodes are needed to send key shares, but only %d are connected", client.numNodes, len(client.nodes))
	}
	if len(keys) != client.numNodes {
		return fmt.Errorf("number of keys (%d) is not equal to number of nodes (%d)", len(keys), client.numNodes)
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot send key shares in a currentMessage state different to None")
	}
	i := 0
	for id, node := range client.nodes {
		log.Printf("Sending key share to node in %s:%d", node.host, node.port)
		msg, err := node.sendECDSAKeyShare(keyID, keys[i], meta)
		if err != nil {
			// I must send key shares to all nodes! No resiliency here.
			return fmt.Errorf("error with node %s: %s", id, err)
		}
		client.pendingMessages[msg.ID] = msg
		i++
	}
	client.currentMessage = message.SendECDSAKeyShare
	return nil
}

func (client *Client) GetECDSAKeyInitMessageList() (tcecdsa.KeyInitMessageList, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.SendECDSAKeyShare {
		return nil, fmt.Errorf("cannot ask for KeyInitMessages in a currentMessage state different to SendECDSAKeyShare")
	}
	if len(client.nodes) != client.numNodes {
		return nil, fmt.Errorf("all %d nodes are needed to send key shares, but only %d are connected", client.numNodes, len(client.nodes))
	}
	list := make(tcecdsa.KeyInitMessageList, 0)
	if err := doForNTimeout(client.channel, len(client.nodes), client.timeout, client.doMessage(func(msg *message.Message) error {
		keyInitMsg, err := message.DecodeECDSAKeyInitMessage(msg.Data[0])
		if err != nil {
			return fmt.Errorf("corrupt key: %v\n", msg)
		} else {
			list = append(list, keyInitMsg)
			return nil
		}
	})); err != nil {
		return nil, err
	}
	return list, nil
}

func (client *Client) SendECDSAKeyInitMessageList(keyID string, messages tcecdsa.KeyInitMessageList) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if len(messages) != len(client.nodes) {
		return fmt.Errorf("number of initKeyMessages is not equal to number of nodes")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot send keyInitMessageList in a currentMessage state different to None")
	}
	for i, node := range client.nodes {
		log.Printf("Sending init key params to node in %s:%d", node.host, node.port)
		msg, err := node.ecdsaInitKeys(keyID, messages)
		if err != nil {
			// I must init key shares of all nodes! No resiliency here.
			return fmt.Errorf("error with node %s: %s", i, err)
		}
		client.pendingMessages[msg.ID] = msg
	}
	client.currentMessage = message.ECDSAInitKeys
	return nil
}

func (client *Client) AckECDSAKeyInitReception() error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if !client.running {
		return fmt.Errorf("connection not running")
	}
	if client.currentMessage != message.ECDSAInitKeys {
		return fmt.Errorf("cannot ack KeyShareMessageList in a currentMessage state different to ECDSAInitKeys")
	}
	log.Printf("timeout will be %s", client.timeout)
	return doForNTimeout(client.channel, len(client.nodes), client.timeout, client.ackOnly)
}

func (client *Client) AskForECDSARound1MessageList(keyID string, msgToSign []byte) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot ask for Round1Message in a currentMessage state different to None")
	}
	for _, node := range client.nodes {
		log.Printf("Asking for sig share to node in %s:%d", node.host, node.port)
		msg, err := node.ecdsaRound1(keyID, msgToSign)
		if err != nil {
			log.Printf("error sending Round1Message with node %s: %s", node.ID(), err)
			// I can lose some nodes in round 1
			continue
		}
		client.pendingMessages[msg.ID] = msg
	}
	client.currentMessage = message.ECDSARound1
	return nil
}

func (client *Client) GetECDSARound1MessageList(k int) ([]string, tcecdsa.Round1MessageList, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if k <= 0 {
		return nil, nil, fmt.Errorf("k must be greater than 0")
	}
	if k > len(client.pendingMessages) {
		return nil, nil, fmt.Errorf("not enough nodes acked the last step. needed=%d, had=%d", k, len(client.pendingMessages))
	}
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.ECDSARound1 {
		return nil, nil, fmt.Errorf("cannot get Round1MessageList in a currentMessage state different to ECDSARound1")
	}
	list := make(tcecdsa.Round1MessageList, 0)
	msgIDs := make([]string, 0)
	err := doForNTimeout(client.channel, k, client.timeout, client.doMessage(func(msg *message.Message) error {
		keyInitMsg, err := message.DecodeECDSARound1Message(msg.Data[0])
		if err != nil {
			return fmt.Errorf("corrupt key: %v\n", msg)
		} else {
			list = append(list, keyInitMsg)
			msgIDs = append(msgIDs, msg.ResponseOf)
			return nil
		}
	}))
	if (err != nil && err != TimeoutError) || (len(msgIDs) < k || len(list) < k) {
		return nil, nil, err
	}
	if len(list) != len(msgIDs) {
		return nil, nil, fmt.Errorf("list and msgIDs length should be the same")
	}
	return msgIDs[:k], list[:k], nil
}

func (client *Client) AskForECDSARound2MessageList(nodeIDs []string, messages tcecdsa.Round1MessageList) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if len(messages) != len(nodeIDs) {
		return fmt.Errorf("number of Round1Messages is not equal to number of node IDs")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot send Round1MessageList in a currentMessage state different to None")
	}
	for _, nodeID := range nodeIDs {
		node, ok := client.nodes[nodeID]
		if !ok {
			e := fmt.Sprintf("node with nodeID %s not found. Available nodes:", nodeID)
			for k, _ := range client.nodes {
				e += k + ","
			}
			return fmt.Errorf(e)
		}
		log.Printf("Sending Round1MessageList to node in %s:%d", node.host, node.port)
		msg, err := node.ecdsaRound2(messages)
		if err != nil {
			return fmt.Errorf("error with node %s: %s", nodeID, err)
		}
		client.pendingMessages[msg.ID] = msg
	}
	client.currentMessage = message.ECDSARound2
	return nil
}

func (client *Client) GetECDSARound2MessageList(k int) (tcecdsa.Round2MessageList, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if k <= 0 {
		return nil, fmt.Errorf("k must be greater than 0")
	}
	if k > len(client.pendingMessages) {
		return nil, fmt.Errorf("not enough nodes acked the last step. needed=%d, had=%d", k, len(client.pendingMessages))
	}
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.ECDSARound2 {
		return nil, fmt.Errorf("cannot get Round2MessageList in a currentMessage state different to ECDSARound1")
	}
	list := make(tcecdsa.Round2MessageList, 0)
	if err := doForNTimeout(client.channel, k, client.timeout, client.doMessage(func(msg *message.Message) error {
		keyInitMsg, err := message.DecodeECDSARound2Message(msg.Data[0])
		if err != nil {
			return fmt.Errorf("corrupt key: %v\n", msg)
		} else {
			list = append(list, keyInitMsg)
			return nil
		}
	})); err != nil {
		return nil, err
	}
	if len(list) != k {
		return nil, fmt.Errorf("list length should be k, but it is not")
	}
	return list, nil
}

func (client *Client) AskForECDSARound3MessageList(nodeIDs []string, messages tcecdsa.Round2MessageList) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if len(messages) != len(nodeIDs) {
		return fmt.Errorf("number of Round2Messages is not equal to number of node IDs")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot send Round2MessageList in a currentMessage state different to None")
	}
	for _, nodeID := range nodeIDs {
		node, ok := client.nodes[nodeID]
		if !ok {
			return fmt.Errorf("node with nodeID %s not found", nodeID)
		}
		log.Printf("Sending Round2MessageList to node in %s:%d", node.host, node.port)
		msg, err := node.ecdsaRound3(messages)
		if err != nil {
			return fmt.Errorf("error with node %s: %s", nodeID, err)
		}
		client.pendingMessages[msg.ID] = msg
	}
	client.currentMessage = message.ECDSARound3
	return nil
}

func (client *Client) GetECDSARound3MessageList(k int) (tcecdsa.Round3MessageList, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if k <= 0 {
		return nil, fmt.Errorf("k must be greater than 0")
	}
	if k > len(client.pendingMessages) {
		return nil, fmt.Errorf("not enough nodes acked the last step. needed=%d, had=%d", k, len(client.pendingMessages))
	}
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.ECDSARound3 {
		return nil, fmt.Errorf("cannot get Round3MessageList in a currentMessage state different to ECDSARound1")
	}
	list := make(tcecdsa.Round3MessageList, 0)
	if err := doForNTimeout(client.channel, k, client.timeout, client.doMessage(func(msg *message.Message) error {
		keyInitMsg, err := message.DecodeECDSARound3Message(msg.Data[0])
		if err != nil {
			return fmt.Errorf("corrupt key: %v\n", msg)
		} else {
			list = append(list, keyInitMsg)
			return nil
		}
	})); err != nil {
		return nil, err
	}
	if len(list) != k {
		return nil, fmt.Errorf("list length should be k, but it is not")
	}
	return list, nil
}

func (client *Client) AskForECDSASignature(nodeIDs []string, messages tcecdsa.Round3MessageList) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if len(messages) != len(nodeIDs) {
		return fmt.Errorf("number of Round3Messages is not equal to number of node IDs")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot send Round3MessageList in a currentMessage state different to None")
	}
	for _, nodeID := range nodeIDs {
		node, ok := client.nodes[nodeID]
		if !ok {
			return fmt.Errorf("node with nodeID %s not found", nodeID)
		}
		log.Printf("Sending Round3MessageList to node in %s:%d", node.host, node.port)
		msg, err := node.ecdsaGetSignature(messages)
		if err != nil {
			return fmt.Errorf("error with node %s: %s", nodeID, err)
		}
		client.pendingMessages[msg.ID] = msg
	}
	client.currentMessage = message.ECDSAGetSignature
	return nil
}

func (client *Client) GetECDSASignature(k int) (*big.Int, *big.Int, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if k <= 0 {
		return nil, nil, fmt.Errorf("k must be greater than 0")
	}
	if k > len(client.pendingMessages) {
		return nil, nil, fmt.Errorf("not enough nodes acked the last step. needed=%d, had=%d", k, len(client.pendingMessages))
	}
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.ECDSAGetSignature {
		return nil, nil, fmt.Errorf("cannot get signature in a currentMessage state different to ECDSARound1")
	}
	rList := make([]*big.Int, 0)
	sList := make([]*big.Int, 0)
	if err := doForNTimeout(client.channel, k, client.timeout, client.doMessage(func(msg *message.Message) error {
		r, s, err := message.DecodeECDSASignature(msg.Data[0])
		if err != nil {
			return fmt.Errorf("corrupt key: %v", msg)
		}
		rList = append(rList, r)
		sList = append(sList, s)
		return nil
	})); err != nil {
		return nil, nil, err
	}
	if len(rList) != k || len(sList) != k {
		return nil, nil, fmt.Errorf("rList and sList length should be k, but they are not")
	}

	r := rList[0]
	s := sList[0]

	for _, ri := range rList {
		if ri.Cmp(r) != 0 {
			return nil, nil, fmt.Errorf("nodes returned different signatures")
		}
	}
	for _, si := range sList {
		if si.Cmp(s) != 0 {
			return nil, nil, fmt.Errorf("nodes returned different signatures")
		}
	}
	return r, s, nil
}

func (client *Client) AskForECDSAKeyDeletion(keyID string) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot ask for key deletion in a currentMessage state different to None")
	}
	for _, node := range client.nodes {
		log.Printf("Asking for key deletion to node in %s:%d", node.host, node.port)
		msg, err := node.deleteECDSAKeyShare(keyID)
		if err != nil {
			log.Printf("error with node %s: %s", keyID, err)
			// I can allow to lose some nodes (they will have some key metadata but that is ok)
			continue
		}
		client.pendingMessages[msg.ID] = msg
	}
	client.currentMessage = message.DeleteECDSAKeyShare
	return nil
}

func (client *Client) AckECDSAKeyDeletion() error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if !client.running {
		return fmt.Errorf("connection not running")
	}
	if client.currentMessage != message.DeleteECDSAKeyShare {
		return fmt.Errorf("cannot ack for key deletion in a currentMessage state different to ECDSAInitKeys")
	}
	log.Printf("timeout will be %s", client.timeout)
	return doForNTimeout(client.channel, len(client.nodes), client.timeout, client.ackOnly)
}
