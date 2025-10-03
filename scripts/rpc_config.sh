#!/bin/bash

# RPC Configuration for Ethereum Network
# This file contains the RPC endpoint configurations used by multiple scripts
# for querying different Ethereum client nodes.

# RPC endpoint list (fixed pattern based on node count)
RPC_ENDPOINTS=(
    "http://172.16.0.11:8545"  # el-1-geth-lighthouse (geth)
    "http://172.16.0.13:8545"  # el-2-nethermind-lighthouse (nethermind)
    "http://172.16.0.14:8545"  # el-3-reth-lighthouse (reth)
    "http://172.16.0.15:8545"  # el-4-erigon-lighthouse (erigon)
    "http://172.16.0.12:8545"  # el-5-besu-lighthouse (besu)
)

# Node type to RPC endpoint mapping
declare -A NODE_RPC_MAP=(
    ["geth"]="http://172.16.0.11:8545"
    ["nethermind"]="http://172.16.0.13:8545"
    ["reth"]="http://172.16.0.14:8545"
    ["erigon"]="http://172.16.0.15:8545"
    ["besu"]="http://172.16.0.12:8545"
)

# Function to get RPC endpoint by node type
get_rpc_endpoint() {
    local node_type="$1"
    if [[ -n "${NODE_RPC_MAP[$node_type]}" ]]; then
        echo "${NODE_RPC_MAP[$node_type]}"
    else
        echo ""
    fi
}

# Function to get all available RPC endpoints
get_all_rpc_endpoints() {
    printf '%s\n' "${RPC_ENDPOINTS[@]}"
}

# Function to get node type from RPC endpoint
get_node_type_from_endpoint() {
    local endpoint="$1"
    for node_type in "${!NODE_RPC_MAP[@]}"; do
        if [[ "${NODE_RPC_MAP[$node_type]}" == "$endpoint" ]]; then
            echo "$node_type"
            return 0
        fi
    done
    echo ""
}

# Export arrays and functions for use in other scripts
export RPC_ENDPOINTS
export NODE_RPC_MAP
export -f get_rpc_endpoint
export -f get_all_rpc_endpoints
export -f get_node_type_from_endpoint