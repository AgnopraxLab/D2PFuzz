# D2PFuzz

D2PFuzz is a fuzzer tool for analyze the Ethernet DevP2P protocol. It is able to generate data corresponding to various sub-protocols including discv4 (e.g., Ping, Pong, etc.), discv5, rlpx, and eth according to the specification of Ethernet network communication protocols. and constructs data sequences according to the chain state and time, and adds mutation functions to them to detect the security of Ethernet network communication protocols.

## Project Structure

Introduction of some files and directories:

- `README.md`: basic information about D2PFuzz
- `generator/`: Generator tool for fuzzer
- `d2p/`: Ethereum devp2p protocol related
- `fuzzing/` : Mutation tools used in fuzz testing
- `fuzzer` : Fuzzer testing tool
- `utils/` : External Toolkit
- `test/`: Test Data

## Environment
You need to have golang and go-ethereum installed

## Install instructions

```shell
# Clone the repo to a place of your liking using
git clone git@github.com:AgnopraxLab/D2PFuzz.git
# Enter the repo
cd D2PFuzz
# Build the binary
go build
# Setting environment
./D2PFuzz setenv
# Run the fuzzer
./FuzzyVM run
```
# Setenv
