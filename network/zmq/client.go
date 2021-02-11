package zmq

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/niclabs/dtc/v3/config"
	"github.com/niclabs/dtcnode/v3/message"
	"github.com/pebbe/zmq4"
)

// The domain of the ZMQ connection. This value must be the same in the server, or it will not work.
const TchsmDomain = "tchsm"

// The protocol used for the ZMQ connection. TCP is the best for this usage cases.
const TchsmProtocol = "tcp"

// This error represents a timeout situation
var TimeoutError = fmt.Errorf("timeout")

// This error represents a forcing break on the waiting routine
var BreakError = fmt.Errorf("force break")

// Client Structure represents a connection to a set of Nodes via ZMQ
// Messaging Protocol.
type Client struct {
	ID              string                      // Connection ID
	running         bool                        // true if it is running
	privKey         string                      // Private Key of node
	pubKey          string                      // Public Key of node
	timeout         time.Duration               // SignatureLength of timeout in seconds
	nodes           map[string]*Node            // Map of connected nodes of type ZMQ
	ctx             *zmq4.Context               // ZMQ Context
	pendingMessages map[string]*message.Message // A map with requests without response. ResponseOf know what message I'm expecting.
	channel         chan *message.Message       // The channel where all the responses from router are sent.
	mutex           sync.Mutex                  // A mutex to operate the pendingMessages map.
	currentMessage  message.Type                // A label which indicates the operation the connection is doing right now. It avoids inconsistent states (i.e. ask for a type of resource and then collect another one).
	numNodes        int                         // Number of nodes based on configuration
}

// New returns a new ZMQ connection based in the configuration provided.
func New(config *config.ZMQConfig) (client *Client, err error) {
	context, err := zmq4.NewContext()
	if err != nil {
		return
	}
	if config.Timeout == 0 {
		config.Timeout = 10
	}
	clientID, err := message.GetRandomHexString(8)
	if err != nil {
		return nil, err
	}
	client = &Client{
		ID:              clientID,
		privKey:         config.PrivateKey,
		pubKey:          config.PublicKey,
		timeout:         time.Duration(config.Timeout) * time.Second,
		ctx:             context,
		channel:         make(chan *message.Message),
		pendingMessages: make(map[string]*message.Message),
		nodes:           make(map[string]*Node, 0),
		numNodes:        len(config.Nodes),
	}
	for i := 0; i < len(config.Nodes); i++ {
		newNode, err := newNode(client, config.Nodes[i])
		if err != nil {
			log.Printf("Node number %d has a bad configuration: %s", i+1, err)
			continue
		}
		client.nodes[newNode.ID()] = newNode
	}
	return
}

func (client *Client) Open() (err error) {
	if client.running {
		return nil
	}
	if client.nodes == nil {
		return fmt.Errorf("not initialized. Use 'New' to create a new struct")
	}
	_ = zmq4.AuthStart()
	// Now we connect to the clients
	for _, node := range client.nodes {
		if err = node.connect(); err != nil {
			zmq4.AuthStop()
			return
		}
		node.listen()
	}
	client.running = true
	return
}

func (client *Client) Close() error {
	if !client.running {
		return nil
	}
	// Try to disconnect from peers
	for _, node := range client.nodes {
		err := node.disconnect()
		node.stopReceiving()
		if err != nil {
			return err
		}
	}
	client.running = false
	zmq4.AuthStop()
	return nil
}

func (client *Client) getPubKeys() []string {
	pubKeys := make([]string, 0)
	for _, node := range client.nodes {
		pubKeys = append(pubKeys, node.pubKey)
	}
	return pubKeys
}

func (client *Client) getIPs() ([]string, error) {
	ips := make([]string, 0)
	for _, node := range client.nodes {
		ips = append(ips, node.host.String())
	}
	return ips, nil
}

func (client *Client) getNodeByID(id string) *Node {
	for _, node := range client.nodes {
		if node.ID() == id {
			return node
		}
	}
	return nil
}

// ackOnly just marks the messages as received, executing no function.
// This name is only for convenience.
func (client *Client) ackOnly(msg *message.Message) error {
	return client.doMessage(nil)(msg)
}

// doMessage defines a function that is executed when receiving a message.
// It checks preliminarily the message received and then executes fn.
// It returns an error from the preliminary check or an error from fn.
func (client *Client) doMessage(fn func(msg *message.Message) error) func(msg *message.Message) error {
	return func(msg *message.Message) error {
		log.Printf("message %s received from node %s\n", msg.ID, msg.From)
		if pending, exists := client.pendingMessages[msg.ID]; exists {
			delete(client.pendingMessages, msg.ID)
			if err := msg.ResponseOK(pending); err != nil {
				log.Printf("error with message from node %s: %v\n", msg.From, err)
				return err
			}
			if fn != nil {
				return fn(msg)
			}
		} else {
			log.Printf("unexpected message, ignoring (id: %s, type: %s, from: %s, responseOf: %s)", msg.ID, msg.Type.String(), msg.From, msg.ResponseOf)
			return fmt.Errorf("unexpected message")
		}
		return nil
	}
}
