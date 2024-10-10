// Copyright 2024 Fudong and Hosen
// This file is part of the D2PFuzz library.
//
// The D2PFuzz library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The D2PFuzz library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the D2PFuzz library. If not, see <http://www.gnu.org/licenses/>.

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

const (
	SequenceLength = 100
)

// Config 结构体
type Config struct {
	ProtocolFlag string `json:"protocolFlag"`
	TargetFlag   string `json:"targetFlag"`
	EngineFlag   bool   `json:"engineFlag"`
	ChainEnvFlag string `json:"chainFlag"`
}

const configFileName = "config.json"

// ReadConfig 读取配置文件
func ReadConfig() (*Config, error) {
	config := &Config{}
	data, err := ioutil.ReadFile(configFileName)
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %v", err)
	}
	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal config data: %v", err)
	}
	return config, nil
}

// WriteConfig
func WriteConfig(config *Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal config data: %v", err)
	}
	err = ioutil.WriteFile("./fuzzer"+configFileName, data, 0644)
	if err != nil {
		return fmt.Errorf("could not write config file: %v", err)
	}
	return nil
}
