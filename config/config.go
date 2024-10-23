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
	"os"
	"path/filepath"
)

const (
	SequenceLength = 100
)

type Config struct {
	ProtocolFlag string `json:"protocolFlag"`
	TargetFlag   string `json:"targetFlag"`
	EngineFlag   bool   `json:"engineFlag"`
	ChainEnvFlag string `json:"chainFlag"`
}

// getConfigFilePath returns the correct path to the config file depending on where the program is run
func getConfigFilePath() (string, error) {
	// Get current working directory
	workingDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("could not get current working directory: %v", err)
	}

	// Assuming `main.go` and `fuzzer.go` are in different directories, handle both cases
	if filepath.Base(workingDir) == "fuzzer" {
		// If running from the fuzzer directory, assume the config.json is in the parent directory
		return filepath.Abs("../config.json")
	} else {
		// Otherwise assume the config.json is in the current directory
		return filepath.Abs("./config.json")
	}
}

// ReadConfig reads the configuration from the config file
func ReadConfig() (*Config, error) {
	config := &Config{}
	configFileName, err := getConfigFilePath()
	if err != nil {
		return nil, fmt.Errorf("could not get config file path: %v", err)
	}

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

// WriteConfig writes the configuration to the config file
func WriteConfig(config *Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal config data: %v", err)
	}
	configFileName, err := getConfigFilePath()
	if err != nil {
		return fmt.Errorf("could not get config file path: %v", err)
	}
	err = ioutil.WriteFile(configFileName, data, 0644)
	if err != nil {
		return fmt.Errorf("could not write config file: %v", err)
	}
	return nil
}
