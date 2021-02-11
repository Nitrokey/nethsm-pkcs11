package zmq

import (
	"fmt"
	"log"
	"net"

	"github.com/niclabs/dtc/v3/config"
	"github.com/niclabs/dtcnode/v3/message"
	"github.com/pebbe/zmq4"
)

// NodeState represents a code for the state of the node
type NodeState int

// Node represents a remote machine connection. It has all the data required to connect to a node, and a pointer to use the respective Client struct.
type Node struct {
	id     string        // Internal Node ID
	host   *net.IPAddr   // Host of remote node
	port   uint16        // Port of remote node SUB
	pubKey string        // Public key of remote node used in ZMQ CURVE Auth
	socket *zmq4.Socket  // ZMQ4 Socket
	client *Client       // The server that manages this Node subroutine.
	quit   chan struct{} // Signal to stop polling messages
	Err    error         // The last error this node had.
}

func newNode(client *Client, config *config.NodeConfig) (*Node, error) {
	var nodeIP *net.IPAddr
	nodeIP, err := net.ResolveIPAddr("ip", config.Host)
	if err != nil {
		return nil, err
	}
	id, err := message.GetRandomHexString(8)
	if err != nil {
		return nil, err
	}
	return &Node{
		id:     id,
		host:   nodeIP,
		port:   config.Port,
		pubKey: config.PublicKey,
		client: client,
		quit:   make(chan struct{}, 1),
	}, nil
}

// ID Returns node ID
func (node *Node) ID() string {
	return node.id
}

// ClientID returns Client ID
func (node *Node) ClientID() string {
	return node.client.ID
}

func (node *Node) getConnString() string {
	return fmt.Sprintf("%s://%s:%d", TchsmProtocol, node.host, node.port)
}

func (node *Node) disconnect() error {
	return node.socket.Disconnect(node.getConnString())
}

func (node *Node) connect() error {
	// Create and name socket
	s, err := node.client.ctx.NewSocket(zmq4.REQ)
	if err != nil {
		node.Err = err
		return err
	}
	node.socket = s
	if err := node.socket.SetIdentity(node.ClientID()); err != nil {
		node.Err = err
		return err
	}

	if err = node.socket.ClientAuthCurve(node.pubKey, node.client.pubKey, node.client.privKey); err != nil {
		node.Err = err
		return err
	}

	// connect
	log.Printf("connecting to %s socket in %s", node.ID(), node.getConnString())
	if err = node.socket.Connect(node.getConnString()); err != nil {
		node.Err = err
		return err
	}
	if err := node.socket.SetRcvtimeo(node.client.timeout); err != nil {
		node.Err = err
		return err
	}
	if err := node.socket.SetSndtimeo(node.client.timeout); err != nil {
		node.Err = err
		return err
	}
	return nil
}

func (node *Node) listen() {
	go func() {
		for {
			select {
			case <-node.quit:
				log.Printf("stopping listening of messages")
				return
			default:
				rawMsg, err := node.socket.RecvMessageBytes(0)
				if err != nil {
					continue
				}
				msg, err := message.FromBytes(rawMsg)
				if err != nil {
					log.Printf("Cannot parse message: %s\n", err)
					return
				}
				node.client.channel <- msg
			}
		}
	}()
}

func (node *Node) stopReceiving() {
	node.quit <- struct{}{}
}

func (node *Node) sendMessage(parts ...interface{}) (int, error) {
	i, err := node.socket.SendMessage(parts...)
	if n := zmq4.AsErrno(err); n == zmq4.EFSM {
		err = node.connect() // Reconnecting (FSM was wating a reply that never came)
		if err != nil {      // Error reconnecting
			return -1, err
		}
		return node.socket.SendMessage(parts...) // if fails, nothing to do
	}
	return i, err
}
