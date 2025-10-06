#!/bin/bash

# D2PFuzz Stress Testing Dedicated Script
# Specifically designed for high-load stress testing scenarios

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Project root directory
PROJECT_ROOT="../"
cd "$PROJECT_ROOT"

# Ensure executable file exists
if [ ! -f "./tx_fuzz_example" ]; then
    echo -e "${YELLOW}Compiling tx_fuzz_example...${NC}"
    go build -o tx_fuzz_example ./stress_test/tx_fuzz_example.go
    echo -e "${GREEN}Compilation completed${NC}"
fi

# Display stress test menu
show_stress_menu() {
    echo -e "${RED}=== D2PFuzz Stress Testing Suite ===${NC}"
    echo -e "${YELLOW}Warning: The following tests will generate high load, please ensure the test environment can handle it${NC}"
    echo
    echo "1. Standard Stress Test (100 TPS, 5 minutes)"
    echo "2. Extreme Stress Test (200 TPS, 10 minutes)"
    echo "3. Endurance Stress Test (50 TPS, 30 minutes)"
    echo "4. Ramp Stress Test (10->100 TPS, 15 minutes)"
    echo "5. Custom Stress Test"
    echo "6. View Stress Test Tuning Guide"
    echo "7. System Resource Check"
    echo "8. Exit"
    echo
}

# System resource check
check_system_resources() {
    echo -e "${BLUE}=== System Resource Check ===${NC}"
    echo -e "${CYAN}CPU Information:${NC}"
    lscpu | grep -E "Model name|CPU\(s\):|Thread|Core"
    echo
    echo -e "${CYAN}Memory Information:${NC}"
    free -h
    echo
    echo -e "${CYAN}Disk Space:${NC}"
    df -h | grep -E "Filesystem|/$"
    echo
    echo -e "${CYAN}Network Connections:${NC}"
    ss -tuln | head -10
    echo
}

# Standard stress test
run_standard_stress() {
    echo -e "${RED}=== Standard Stress Test ===${NC}"
    echo "Configuration: 100 TPS, 5 minutes"
    echo "Expected transactions: ~30,000"
    echo
    confirm_and_run "stress_test/stress_test_config.yaml"
}

# Extreme stress test
run_extreme_stress() {
    echo -e "${RED}=== Extreme Stress Test ===${NC}"
    echo "Configuration: 200 TPS, 10 minutes"
    echo "Expected transactions: ~120,000"
    echo -e "${YELLOW}Note: This is an extreme test that may cause system resource exhaustion${NC}"
    echo
    
    # Create extreme test configuration
    create_extreme_config
    confirm_and_run "stress_test/extreme_stress_config.yaml"
}

# Endurance stress test
run_endurance_stress() {
    echo -e "${RED}=== Endurance Stress Test ===${NC}"
    echo "Configuration: 50 TPS, 30 minutes"
    echo "Expected transactions: ~90,000"
    echo "Suitable for: Long-term stability testing"
    echo
    
    # Create endurance test configuration
    create_endurance_config
    confirm_and_run "stress_test/endurance_stress_config.yaml"
}

# Ramp stress test
run_ramp_stress() {
    echo -e "${RED}=== Ramp Stress Test ===${NC}"
    echo "Configuration: 10->100 TPS, 15 minutes"
    echo "Load pattern: Progressive growth"
    echo "Suitable for: Performance bottleneck analysis"
    echo
    
    # Create ramp test configuration
    create_ramp_config
    confirm_and_run "stress_test/ramp_stress_config.yaml"
}

# Custom stress test
run_custom_stress() {
    echo -e "${BLUE}=== Custom Stress Test ===${NC}"
    echo "Please enter test parameters:"
    
    read -p "TPS (transactions per second): " tps
    read -p "Test duration (seconds): " duration
    read -p "Load pattern (constant/ramp/burst): " load_pattern
    
    # Validate input
    if ! [[ "$tps" =~ ^[0-9]+$ ]] || ! [[ "$duration" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Error: TPS and duration must be numbers${NC}"
        return 1
    fi
    
    if [[ ! "$load_pattern" =~ ^(constant|ramp|burst)$ ]]; then
        echo -e "${RED}Error: Load pattern must be constant, ramp or burst${NC}"
        return 1
    fi
    
    echo
    echo -e "${YELLOW}Custom test configuration:${NC}"
    echo "TPS: $tps"
    echo "Duration: $duration seconds"
    echo "Load pattern: $load_pattern"
    echo "Expected transactions: ~$((tps * duration))"
    echo
    
    # Create custom configuration
    create_custom_config "$tps" "$duration" "$load_pattern"
    confirm_and_run "stress_test/custom_stress_config.yaml"
}

# Confirm and run test
confirm_and_run() {
    local config_file="$1"
    
    echo -e "${RED}Warning: About to start high-load stress test${NC}"
    echo -e "${YELLOW}Please ensure:${NC}"
    echo "1. Test environment has sufficient resources"
    echo "2. Network connection is stable"
    echo "3. Important data has been backed up"
    echo
    
    read -p "Confirm to start test? (Enter 'YES' to confirm): " confirm
    if [[ "$confirm" == "YES" ]]; then
        echo -e "${GREEN}Starting stress test...${NC}"
        echo "Configuration file: $config_file"
        echo "Start time: $(date)"
        echo
        
        # Run test
        ./tx_fuzz_example "$config_file"
        
        echo
        echo "End time: $(date)"
        echo -e "${GREEN}Stress test completed${NC}"
    else
        echo -e "${YELLOW}Test cancelled${NC}"
    fi
}

# Create extreme test configuration
create_extreme_config() {
    cat > stress_test/extreme_stress_config.yaml << 'EOF'
server:
  host: "0.0.0.0"
  port: 8080

mode: "tx_fuzzer"

tx_fuzzer:
  tx_per_second: 200
  fuzz_duration_sec: 600
  load_pattern_type: "constant"
  max_concurrent_tx: 1000
  retry_failed_tx: true
  max_retries: 5
  retry_delay_ms: 100
  gas_limit: 21000
  gas_price: 20000000000
  value_range:
    min: 1000000000000000
    max: 10000000000000000
# --- FIX: Moved fuzzing config inside tx_fuzzer ---
fuzzing:
  enabled: true
  mutation_rate: 0.3
  max_mutations_per_tx: 5

p2p:
  enabled: false

monitoring:
  enabled: true
  stats_interval_sec: 10
  export_interval_sec: 60

output:
  export_results: true
  results_file: "extreme_stress_results.json"
  log_level: "info"

accounts:
  - private_key: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
EOF
}

# Create endurance test configuration
create_endurance_config() {
    cat > stress_test/endurance_stress_config.yaml << 'EOF'
server:
  host: "0.0.0.0"
  port: 8080

mode: "tx_fuzzer"

tx_fuzzer:
  tx_per_second: 50
  fuzz_duration_sec: 1800
  load_pattern_type: "constant"
  max_concurrent_tx: 200
  retry_failed_tx: true
  max_retries: 3
  retry_delay_ms: 200
  gas_limit: 21000
  gas_price: 20000000000
  value_range:
    min: 1000000000000000
    max: 10000000000000000
  # --- FIX: Moved fuzzing config inside tx_fuzzer ---
  fuzzing:
    enabled: true
    mutation_rate: 0.2
    max_mutations_per_tx: 3

p2p:
  enabled: false

monitoring:
  enabled: true
  stats_interval_sec: 30
  export_interval_sec: 300

output:
  export_results: true
  results_file: "endurance_stress_results.json"
  log_level: "info"

accounts:
  - private_key: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
EOF
}

# Create ramp test configuration
create_ramp_config() {
    cat > stress_test/ramp_stress_config.yaml << 'EOF'
server:
  host: "0.0.0.0"
  port: 8080

mode: "tx_fuzzer"

tx_fuzz:
  tx_per_second: 100
  fuzz_duration_sec: 900
  load_pattern_type: "ramp"
  ramp_start_tps: 10
  ramp_end_tps: 100
  max_concurrent_tx: 500
  retry_failed_tx: true
  max_retries: 3
  retry_delay_ms: 150
  gas_limit: 21000
  gas_price: 20000000000
  value_range:
    min: 1000000000000000
    max: 10000000000000000
  # --- FIX: Moved fuzzing config inside tx_fuzzer ---
  fuzzing:
    enabled: true
    mutation_rate: 0.25
    max_mutations_per_tx: 4

p2p:
  enabled: false

monitoring:
  enabled: true
  stats_interval_sec: 15
  export_interval_sec: 120

output:
  export_results: true
  results_file: "ramp_stress_results.json"
  log_level: "info"

accounts:
  - private_key: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
EOF
}

# Create custom configuration
create_custom_config() {
    local tps="$1"
    local duration="$2"
    local load_pattern="$3"
    
    # Note: EOF cannot have spaces before or after
    cat > stress_test/custom_stress_config.yaml <<EOF
server:
  host: "0.0.0.0"
  port: 8080

mode: "tx_fuzzer"

tx_fuzz:
  enabled: true
  tx_per_second: $tps
  fuzz_duration_sec: $duration
  load_pattern_type: "$load_pattern"
  max_concurrent_tx: $((tps * 5))
  retry_failed_tx: true
  max_retries: 3
  retry_delay_ms: 100
  gas_limit: 21000
  gas_price: 20000000000
  value_range:
    min: 1000000000000000
    max: 10000000000000000
  # --- FIX: Moved fuzzing config inside tx_fuzzer ---
fuzzing:
  mutation_rate: 0.2
  max_mutations_per_tx: 3

p2p:
  enabled: false

monitoring:
  enabled: true
  stats_interval_sec: 10
  export_interval_sec: 60

output:
  export_results: true
  results_file: "custom_stress_results.json"
  log_level: "info"

accounts:
  - private_key: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

log:
  directory: "./logs/1000_tps"
  template: "default"
  auto_generate: true
  include_details: true
EOF
}

# Display tuning guide
show_tuning_guide() {
    if [ -f "stress_test/STRESS_TEST_TUNING_GUIDE.md" ]; then
        echo -e "${BLUE}=== Stress Test Tuning Guide ===${NC}"
        head -50 stress_test/STRESS_TEST_TUNING_GUIDE.md
        echo
        echo -e "${YELLOW}For complete guide, please check: stress_test/STRESS_TEST_TUNING_GUIDE.md${NC}"
    else
        echo -e "${RED}Tuning guide file does not exist${NC}"
    fi
}

# Main loop
main() {
    while true; do
        show_stress_menu
        read -p "Please select (1-8): " choice
        
        case $choice in
            1)
                run_standard_stress
                ;;
            2)
                run_extreme_stress
                ;;
            3)
                run_endurance_stress
                ;;
            4)
                run_ramp_stress
                ;;
            5)
                run_custom_stress
                ;;
            6)
                show_tuning_guide
                ;;
            7)
                check_system_resources
                ;;
            8)
                echo -e "${GREEN}Exit stress testing suite${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid selection, please enter 1-8${NC}"
                ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
        clear
    done
}

# Check parameters
if [ $# -eq 0 ]; then
    # Interactive mode
    clear
    echo -e "${PURPLE}D2PFuzz Stress Testing Suite${NC}"
    echo -e "${CYAN}Professional Ethereum Transaction Stress Testing Tool${NC}"
    echo
    main
else
    # Command line mode
    case $1 in
        "standard"|"1")
            run_standard_stress
            ;;
        "extreme"|"2")
            run_extreme_stress
            ;;
        "endurance"|"3")
            run_endurance_stress
            ;;
        "ramp"|"4")
            run_ramp_stress
            ;;
        "custom"|"5")
            run_custom_stress
            ;;
        "check"|"7")
            check_system_resources
            ;;
        "help"|"-h"|"--help")
            echo "D2PFuzz Stress Testing Suite"
            echo "Usage: $0 [standard|extreme|endurance|ramp|custom|check|help]"
            echo "  standard  - Standard stress test (100 TPS, 5 minutes)"
            echo "  extreme   - Extreme stress test (200 TPS, 10 minutes)"
            echo "  endurance - Endurance stress test (50 TPS, 30 minutes)"
            echo "  ramp      - Ramp stress test (10->100 TPS, 15 minutes)"
            echo "  custom    - Custom stress test"
            echo "  check     - System resource check"
            echo "  help      - Show help"
            ;;
        *)
            echo -e "${RED}Unknown parameter: $1${NC}"
            echo "Use '$0 help' to view help"
            exit 1
            ;;
    esac
fi
