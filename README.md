# D2PFuzz

D2PFuzz is a fuzzer tool for analyze the Ethernet DevP2P protocol. It is able to generate data corresponding to various sub-protocols including discv4 (e.g., Ping, Pong, etc.), discv5, rlpx, and eth according to the specification of Ethernet network communication protocols. and constructs data sequences according to the chain state and time, and adds mutation functions to them to detect the security of Ethernet network communication protocols.

## Project Structure

Introduction of some files and directories:

- `README.md`: basic information about D2PFuzz
- `cmd/`: Executable commands
- `d2p/`: ethereum devp2p protocol
- `fuzzing/` : Mutation tools used in fuzz testing
- `utils/` : External Toolkit
- `test/`: Test Data

## Tools

### 1. Packet Generator

Run:

```
Usage:
  packet-generator [flag]

Flags:
  -p, --protocol   Specify the protocol to test
  -t, --type       Type of packet to generate (e.g., 'ping')
  -c, --count      Number of packets to generate
  -f, --file       Specify the file containing test data
  
Example:
packet-generator --protocol "discv4" --type "ping" --count 2 --file "./test.txt"
```

### 2. DevP2P Fuzzer
Updating...