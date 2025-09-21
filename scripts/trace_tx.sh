#!/bin/bash

# Transaction Tracing Script
# Used to trace detailed information of Ethereum transaction execution

# Set character encoding to UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Load RPC configuration from external file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/rpc_config.sh"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
DEFAULT_TRACER="callTracer"
DEFAULT_NODE="geth"

# Show usage information
show_usage() {
    echo -e "${BLUE}Ethereum Transaction Tracing Tool${NC}"
    echo "Usage: $0 [options] <transaction_hash>"
    echo ""
    echo "Options:"
    echo "  -t, --tracer <type>     Tracer type (default: callTracer)"
    echo "                          Available: callTracer, prestateTracer, 4byteTracer, opcodeLogger"
    echo "  -n, --node <node>       Specify node type (default: geth)"
    echo "                          Available: geth, nethermind, reth, erigon, besu"
    echo "  -e, --endpoint <URL>    Custom RPC endpoint"
    echo "  -o, --output <file>     Output result to file"
    echo "  -p, --pretty            Pretty print JSON output"
    echo "  -h, --help              Show this help information"
    echo ""
    echo "Tracer descriptions:"
    echo "  callTracer      - Trace all contract calls (recommended)"
    echo "  prestateTracer  - Trace state changes"
    echo "  4byteTracer     - Trace function call statistics"
    echo "  opcodeLogger    - Detailed opcode logs"
    echo ""
    echo "Examples:"
    echo "  $0 0x1234...                                    # Trace transaction with default settings"
    echo "  $0 -t prestateTracer 0x1234...                 # Use state tracer"
    echo "  $0 -n reth -t callTracer 0x1234...             # Use reth node for tracing"
    echo "  $0 -o trace_result.json 0x1234...              # Output to file"
    echo "  $0 -p 0x1234...                                # Pretty print output"
}

# Test RPC connection
test_rpc_connection() {
    local endpoint=$1
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$response" | grep -q '"result"'; then
        return 0
    else
        return 1
    fi
}

# Validate transaction hash
validate_tx_hash() {
    local tx_hash=$1
    if [[ ! "$tx_hash" =~ ^0x[a-fA-F0-9]{64}$ ]]; then
        echo -e "${RED}Error: Invalid transaction hash format${NC}"
        echo "Transaction hash should be a 64-character hexadecimal string starting with 0x"
        return 1
    fi
    return 0
}

# Format JSON output
format_json() {
    local json_data=$1
    local pretty=$2
    
    if [[ "$pretty" == "true" ]] && command -v jq >/dev/null 2>&1; then
        echo "$json_data" | jq '.'
    else
        echo "$json_data"
    fi
}

# Trace transaction
trace_transaction() {
    local tx_hash=$1
    local tracer=$2
    local endpoint=$3
    local output_file=$4
    local pretty=$5
    
    echo -e "${CYAN}Tracing transaction: $tx_hash${NC}"
    echo -e "${CYAN}Using tracer: $tracer${NC}"
    echo -e "${CYAN}RPC endpoint: $endpoint${NC}"
    echo ""
    
    # Prepare tracer configuration
    local tracer_config=""
    case "$tracer" in
        "callTracer")
            tracer_config='{"tracer": "callTracer"}'
            ;;
        "prestateTracer")
            tracer_config='{"tracer": "prestateTracer"}'
            ;;
        "4byteTracer")
            tracer_config='{"tracer": "4byteTracer"}'
            ;;
        "opcodeLogger")
            tracer_config='{"tracer": "opcodeLogger"}'
            ;;
        *)
            tracer_config="{\"tracer\": \"$tracer\"}"
            ;;
    esac
    
    # Execute trace request
    local trace_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"debug_traceTransaction\",\"params\":[\"$tx_hash\", $tracer_config],\"id\":1}" \
        --connect-timeout 30 --max-time 60 "$endpoint" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Error: RPC call failed${NC}"
        return 1
    fi
    
    # Check for errors in response
    if echo "$trace_response" | grep -q '"error"'; then
        echo -e "${RED}Tracing failed:${NC}"
        echo "$trace_response" | grep -o '"error":[^}]*}' | sed 's/^"error"://'
        return 1
    fi
    
    # Check if result exists
    if echo "$trace_response" | grep -q '"result"'; then
        echo -e "${GREEN}✓ Tracing successful${NC}"
        echo ""
        
        # Extract and format result
        local result=$(echo "$trace_response" | grep -o '"result":{.*}' | sed 's/^"result"://' | sed 's/}$/}/')
        if [[ -z "$result" ]]; then
            result=$(echo "$trace_response" | grep -o '"result":\[.*\]' | sed 's/^"result"://')
        fi
        
        # Format and output result
        local formatted_result=$(format_json "$result" "$pretty")
        
        if [[ -n "$output_file" ]]; then
            echo "$formatted_result" > "$output_file"
            echo -e "${GREEN}Result saved to: $output_file${NC}"
        else
            echo -e "${YELLOW}=== Trace Result ===${NC}"
            echo "$formatted_result"
        fi
        
        return 0
    else
        echo -e "${RED}Error: Abnormal response format${NC}"
        echo "$trace_response"
        return 1
    fi
}

# Main function
main() {
    local tx_hash=""
    local tracer="$DEFAULT_TRACER"
    local node="$DEFAULT_NODE"
    local endpoint=""
    local output_file=""
    local pretty="false"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--tracer)
                tracer="$2"
                shift 2
                ;;
            -n|--node)
                node="$2"
                shift 2
                ;;
            -e|--endpoint)
                endpoint="$2"
                shift 2
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -p|--pretty)
                pretty="true"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            0x*)
                tx_hash="$1"
                shift
                ;;
            *)
                echo -e "${RED}Error: Unknown parameter $1${NC}"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Check if transaction hash is provided
    if [[ -z "$tx_hash" ]]; then
        echo -e "${RED}Error: Please provide transaction hash${NC}"
        show_usage
        exit 1
    fi
    
    # Validate transaction hash
    if ! validate_tx_hash "$tx_hash"; then
        exit 1
    fi
    
    # Determine endpoint
    if [[ -z "$endpoint" ]]; then
        if [[ -n "${NODE_RPC_MAP[$node]}" ]]; then
            endpoint="${NODE_RPC_MAP[$node]}"
        else
            echo -e "${RED}Error: Unknown node type '$node'${NC}"
            echo "Available nodes: ${!NODE_RPC_MAP[@]}"
            exit 1
        fi
    fi
    
    # Test connection
    echo -e "${CYAN}Testing RPC connection...${NC}"
    if ! test_rpc_connection "$endpoint"; then
        echo -e "${RED}Error: Unable to connect to RPC endpoint $endpoint${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Connection successful${NC}"
    echo ""
    
    # Execute trace
    trace_transaction "$tx_hash" "$tracer" "$endpoint" "$output_file" "$pretty"
}

# Run main function
main "$@"