package common

import (
	"testing"
)

func TestGetList(t *testing.T) {
	// 调用 GetList 函数，读取 "../test/1.txt" 文件
	nodes, err := GetList("../test/enode.txt")
	if err != nil {
		t.Fatalf("GetList returned an error: %v", err)
	}

	println(len(nodes))
}
