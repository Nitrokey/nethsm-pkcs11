package zmq

import (
	"github.com/niclabs/dtcnode/v3/message"
	"github.com/niclabs/tcecdsa"
)

func (node *Node) sendECDSAKeyShare(id string, key *tcecdsa.KeyShare, meta *tcecdsa.KeyMeta) (*message.Message, error) {
	keyBinary, err := message.EncodeECDSAKeyShare(key)
	if err != nil {
		return nil, err
	}
	metaBinary, err := message.EncodeECDSAKeyMeta(meta)
	if err != nil {
		return nil, err
	}
	msg, err := message.NewMessage(message.SendECDSAKeyShare, node.ID(), []byte(id), keyBinary, metaBinary)
	if err != nil {
		return nil, err
	}
	_, err = node.sendMessage(msg.GetBytesLists()...)
	if err != nil {
		return nil, err
	}
	return msg, nil

}

func (node *Node) ecdsaInitKeys(id string, initKeyMessages tcecdsa.KeyInitMessageList) (msg *message.Message, err error) {
	initKeyMsgsBin, err := message.EncodeECDSAKeyInitMessageList(initKeyMessages)
	if err != nil {
		return nil, err
	}
	msg, err = message.NewMessage(message.ECDSAInitKeys, node.ID(), []byte(id), initKeyMsgsBin)
	if err != nil {
		return nil, err
	}
	if _, err := node.sendMessage(msg.GetBytesLists()...); err != nil {
		return nil, err
	}
	return msg, nil
}

func (node *Node) ecdsaRound1(id string, doc []byte) (msg *message.Message, err error) {
	msg, err = message.NewMessage(message.ECDSARound1, node.ID(), []byte(id), doc)
	if err != nil {
		return nil, err
	}
	if _, err := node.sendMessage(msg.GetBytesLists()...); err != nil {
		return nil, err
	}
	return msg, nil
}

func (node *Node) ecdsaRound2(messages tcecdsa.Round1MessageList) (msg *message.Message, err error) {
	msgsBin, err := message.EncodeECDSARound1MessageList(messages)
	if err != nil {
		return nil, err
	}
	msg, err = message.NewMessage(message.ECDSARound2, node.ID(), msgsBin)
	if err != nil {
		return nil, err
	}
	if _, err := node.sendMessage(msg.GetBytesLists()...); err != nil {
		return nil, err
	}
	return msg, nil
}

func (node *Node) ecdsaRound3(messages tcecdsa.Round2MessageList) (msg *message.Message, err error) {
	msgsBin, err := message.EncodeECDSARound2MessageList(messages)
	if err != nil {
		return nil, err
	}
	msg, err = message.NewMessage(message.ECDSARound3, node.ID(), msgsBin)
	if err != nil {
		return nil, err
	}
	if _, err := node.sendMessage(msg.GetBytesLists()...); err != nil {
		return nil, err
	}
	return msg, nil
}

func (node *Node) ecdsaGetSignature(messages tcecdsa.Round3MessageList) (msg *message.Message, err error) {
	msgsBin, err := message.EncodeECDSARound3MessageList(messages)
	if err != nil {
		return nil, err
	}
	msg, err = message.NewMessage(message.ECDSAGetSignature, node.ID(), msgsBin)
	if err != nil {
		return nil, err
	}
	if _, err := node.sendMessage(msg.GetBytesLists()...); err != nil {
		return nil, err
	}
	return msg, nil
}

func (node *Node) deleteECDSAKeyShare(id string) (*message.Message, error) {
	msg, err := message.NewMessage(message.DeleteECDSAKeyShare, node.ID(), []byte(id))
	if err != nil {
		return nil, err
	}
	_, err = node.sendMessage(msg.GetBytesLists()...)
	if err != nil {
		return nil, err
	}
	return msg, nil
}
