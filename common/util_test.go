package common

import (
	"testing"
)

func TestGetList(t *testing.T) {

	nodes, err := GetList("../test/enode.txt")
	if err != nil {
		t.Fatalf("GetList returned an error: %v", err)
	}

	println(len(nodes))
}
