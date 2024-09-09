package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// Config 结构体
type Config struct {
	ProtocolFlag string `json:"protocolFlag"`
	TargetFlag   string `json:"targetFlag"`
	EngineFlag   string `json:"engineFlag"`
}

// Config 文件名
const ConfigFileName = "fuzz_config.json"

// ReadConfig 读取配置文件
func ReadConfig() (*Config, error) {
	config := &Config{}
	data, err := ioutil.ReadFile(ConfigFileName)
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %v", err)
	}
	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal config data: %v", err)
	}
	return config, nil
}

// WriteConfig 写入配置文件
func WriteConfig(config *Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal config data: %v", err)
	}
	err = ioutil.WriteFile(ConfigFileName, data, 0644)
	if err != nil {
		return fmt.Errorf("could not write config file: %v", err)
	}
	return nil
}
