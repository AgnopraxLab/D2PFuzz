#!/bin/bash

# D2PFuzz 压力测试专用脚本
# 专门用于高负载压力测试场景

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 项目根目录
PROJECT_ROOT="/home/kkk/workspaces/D2PFuzz"
cd "$PROJECT_ROOT"

# 确保可执行文件存在
if [ ! -f "./tx_fuzz_example" ]; then
    echo -e "${YELLOW}编译 tx_fuzz_example...${NC}"
    go build -o tx_fuzz_example ./stress_test/tx_fuzz_example.go
    echo -e "${GREEN}编译完成${NC}"
fi

# 显示压力测试菜单
show_stress_menu() {
    echo -e "${RED}=== D2PFuzz 压力测试套件 ===${NC}"
    echo -e "${YELLOW}警告: 以下测试将产生高负载，请确保测试环境能够承受${NC}"
    echo
    echo "1. 标准压力测试 (100 TPS, 5分钟)"
    echo "2. 极限压力测试 (200 TPS, 10分钟)"
    echo "3. 持续压力测试 (50 TPS, 30分钟)"
    echo "4. 渐进压力测试 (10->100 TPS, 15分钟)"
    echo "5. 自定义压力测试"
    echo "6. 查看压力测试调优指南"
    echo "7. 系统资源检查"
    echo "8. 退出"
    echo
}

# 系统资源检查
check_system_resources() {
    echo -e "${BLUE}=== 系统资源检查 ===${NC}"
    echo -e "${CYAN}CPU 信息:${NC}"
    lscpu | grep -E "Model name|CPU\(s\):|Thread|Core"
    echo
    echo -e "${CYAN}内存信息:${NC}"
    free -h
    echo
    echo -e "${CYAN}磁盘空间:${NC}"
    df -h | grep -E "Filesystem|/$"
    echo
    echo -e "${CYAN}网络连接:${NC}"
    ss -tuln | head -10
    echo
}

# 标准压力测试
run_standard_stress() {
    echo -e "${RED}=== 标准压力测试 ===${NC}"
    echo "配置: 100 TPS, 5分钟"
    echo "预计发送交易: ~30,000笔"
    echo
    confirm_and_run "stress_test/stress_test_config.yaml"
}

# 极限压力测试
run_extreme_stress() {
    echo -e "${RED}=== 极限压力测试 ===${NC}"
    echo "配置: 200 TPS, 10分钟"
    echo "预计发送交易: ~120,000笔"
    echo -e "${YELLOW}注意: 这是极限测试，可能导致系统资源耗尽${NC}"
    echo
    
    # 创建极限测试配置
    create_extreme_config
    confirm_and_run "stress_test/extreme_stress_config.yaml"
}

# 持续压力测试
run_endurance_stress() {
    echo -e "${RED}=== 持续压力测试 ===${NC}"
    echo "配置: 50 TPS, 30分钟"
    echo "预计发送交易: ~90,000笔"
    echo "适用于: 长期稳定性测试"
    echo
    
    # 创建持续测试配置
    create_endurance_config
    confirm_and_run "stress_test/endurance_stress_config.yaml"
}

# 渐进压力测试
run_ramp_stress() {
    echo -e "${RED}=== 渐进压力测试 ===${NC}"
    echo "配置: 10->100 TPS, 15分钟"
    echo "负载模式: 渐进式增长"
    echo "适用于: 性能瓶颈分析"
    echo
    
    # 创建渐进测试配置
    create_ramp_config
    confirm_and_run "stress_test/ramp_stress_config.yaml"
}

# 自定义压力测试
run_custom_stress() {
    echo -e "${BLUE}=== 自定义压力测试 ===${NC}"
    echo "请输入测试参数:"
    
    read -p "TPS (每秒交易数): " tps
    read -p "测试时长 (秒): " duration
    read -p "负载模式 (constant/ramp/burst): " load_pattern
    
    # 验证输入
    if ! [[ "$tps" =~ ^[0-9]+$ ]] || ! [[ "$duration" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}错误: TPS和时长必须是数字${NC}"
        return 1
    fi
    
    if [[ ! "$load_pattern" =~ ^(constant|ramp|burst)$ ]]; then
        echo -e "${RED}错误: 负载模式必须是 constant, ramp 或 burst${NC}"
        return 1
    fi
    
    echo
    echo -e "${YELLOW}自定义测试配置:${NC}"
    echo "TPS: $tps"
    echo "时长: $duration 秒"
    echo "负载模式: $load_pattern"
    echo "预计发送交易: ~$((tps * duration))笔"
    echo
    
    # 创建自定义配置
    create_custom_config "$tps" "$duration" "$load_pattern"
    confirm_and_run "stress_test/custom_stress_config.yaml"
}

# 确认并运行测试
confirm_and_run() {
    local config_file="$1"
    
    echo -e "${RED}警告: 即将开始高负载压力测试${NC}"
    echo -e "${YELLOW}请确保:${NC}"
    echo "1. 测试环境有足够的资源"
    echo "2. 网络连接稳定"
    echo "3. 已备份重要数据"
    echo
    
    read -p "确认开始测试? (输入 'YES' 确认): " confirm
    if [[ "$confirm" == "YES" ]]; then
        echo -e "${GREEN}开始压力测试...${NC}"
        echo "配置文件: $config_file"
        echo "开始时间: $(date)"
        echo
        
        # 运行测试
        ./tx_fuzz_example "$config_file"
        
        echo
        echo "结束时间: $(date)"
        echo -e "${GREEN}压力测试完成${NC}"
    else
        echo -e "${YELLOW}测试已取消${NC}"
    fi
}

# 创建极限测试配置
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

# 创建持续测试配置
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

# 创建渐进测试配置
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

# 创建自定义配置
create_custom_config() {
    local tps="$1"
    local duration="$2"
    local load_pattern="$3"
    
    # 注意这里的 EOF 前后不能有空格
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

# 显示调优指南
show_tuning_guide() {
    if [ -f "stress_test/STRESS_TEST_TUNING_GUIDE.md" ]; then
        echo -e "${BLUE}=== 压力测试调优指南 ===${NC}"
        head -50 stress_test/STRESS_TEST_TUNING_GUIDE.md
        echo
        echo -e "${YELLOW}完整指南请查看: stress_test/STRESS_TEST_TUNING_GUIDE.md${NC}"
    else
        echo -e "${RED}调优指南文件不存在${NC}"
    fi
}

# 主循环
main() {
    while true; do
        show_stress_menu
        read -p "请选择 (1-8): " choice
        
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
                echo -e "${GREEN}退出压力测试套件${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-8${NC}"
                ;;
        esac
        
        echo
        read -p "按回车键继续..."
        clear
    done
}

# 检查参数
if [ $# -eq 0 ]; then
    # 交互模式
    clear
    echo -e "${PURPLE}D2PFuzz 压力测试套件${NC}"
    echo -e "${CYAN}专业的以太坊交易压力测试工具${NC}"
    echo
    main
else
    # 命令行模式
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
            echo "D2PFuzz 压力测试套件"
            echo "用法: $0 [standard|extreme|endurance|ramp|custom|check|help]"
            echo "  standard  - 标准压力测试 (100 TPS, 5分钟)"
            echo "  extreme   - 极限压力测试 (200 TPS, 10分钟)"
            echo "  endurance - 持续压力测试 (50 TPS, 30分钟)"
            echo "  ramp      - 渐进压力测试 (10->100 TPS, 15分钟)"
            echo "  custom    - 自定义压力测试"
            echo "  check     - 系统资源检查"
            echo "  help      - 显示帮助"
            ;;
        *)
            echo -e "${RED}未知参数: $1${NC}"
            echo "使用 '$0 help' 查看帮助"
            exit 1
            ;;
    esac
fi
