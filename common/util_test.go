package common

import (
	"testing"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/stretchr/testify/assert"
)

func TestGetList(t *testing.T) {

	nodes, err := GetList("../test/enode.txt")
	if err != nil {
		t.Fatalf("GetList returned an error: %v", err)
	}

	println(len(nodes))
}

func TestDiscv4Generator(t *testing.T) {
	// Replace with your test data and assertions
	packetType := "ping"
	count := 1
	nodeList := []*enode.Node{
		// Replace with mock nodes or load from test file
		enode.MustParse("enode://ba85011c70bcc5c04d8607d3a0ed29aa6179c092cbdda10d5d32684fb33ed01bd94f588ca8f91ac48318087dcb02eaf36773a7a453f0eedd6742af668097b29c@10.0.1.16:30303?discport=30304"),
	}

	err := discv4Generator(packetType, count, nodeList)
	assert.NoError(t, err, "Discv4Generator should not return error")
	// Add additional assertions as needed
}
