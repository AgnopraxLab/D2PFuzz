#!/bin/bash

# D2PFuzz 运行示例脚本
# 提供不同场景的快速测试命令

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 项目根目录
PROJECT_ROOT="/home/kkk/workspaces/D2PFuzz"
cd "$PROJECT_ROOT"

# 确保可执行文件存在
if [ ! -f "./tx_fuzz_example" ]; then
    echo -e "${YELLOW}编译 tx_fuzz_example...${NC}"
    go build -o tx_fuzz_example ./examples/tx_fuzz_example.go
    echo -e "${GREEN}编译完成${NC}"
fi

# 显示菜单
show_menu() {
    echo -e "${BLUE}=== D2PFuzz 测试场景选择 ===${NC}"
    echo "1. 基础测试 (低TPS, 短时间)"
    echo "2. 标准测试 (默认配置)"
    echo "3. 压力测试 (高TPS, 长时间)"
    echo "4. 自定义配置文件"
    echo "5. 查看使用指南"
    echo "6. 退出"
    echo
}

# 基础测试
run_basic_test() {
    echo -e "${GREEN}运行基础测试 (5 TPS, 60秒)...${NC}"
    echo "配置: test/basic_test_config.yaml"
    echo "适用于: 功能验证、稳定性测试"
    echo
    ./tx_fuzz_example test/basic_test_config.yaml
}

# 标准测试
run_standard_test() {
    echo -e "${GREEN}运行标准测试 (10 TPS, 60秒)...${NC}"
    echo "配置: config.yaml"
    echo "适用于: 常规性能测试"
    echo
    ./tx_fuzz_example
}

# 压力测试
run_stress_test() {
    echo -e "${YELLOW}运行压力测试 (100 TPS, 300秒)...${NC}"
    echo "配置: stress_test/stress_test_config.yaml"
    echo "适用于: 极限性能测试"
    echo -e "${RED}警告: 这将产生高负载，请确保测试环境能够承受${NC}"
    echo
    read -p "确认继续? (y/N): " confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        ./tx_fuzz_example stress_test/stress_test_config.yaml
    else
        echo "取消压力测试"
    fi
}

# 自定义配置
run_custom_test() {
    echo -e "${BLUE}请输入配置文件路径:${NC}"
    read -p "配置文件路径: " config_path
    
    if [ -f "$config_path" ]; then
        echo -e "${GREEN}运行自定义配置测试...${NC}"
        ./tx_fuzz_example "$config_path"
    else
        echo -e "${RED}错误: 配置文件不存在: $config_path${NC}"
    fi
}

# 显示使用指南
show_usage_guide() {
    if [ -f "USAGE_GUIDE.md" ]; then
        echo -e "${BLUE}=== 使用指南 ===${NC}"
        head -50 USAGE_GUIDE.md
        echo
        echo -e "${YELLOW}完整指南请查看: USAGE_GUIDE.md${NC}"
    else
        echo -e "${RED}使用指南文件不存在${NC}"
    fi
}

# 主循环
main() {
    while true; do
        show_menu
        read -p "请选择 (1-6): " choice
        
        case $choice in
            1)
                run_basic_test
                ;;
            2)
                run_standard_test
                ;;
            3)
                run_stress_test
                ;;
            4)
                run_custom_test
                ;;
            5)
                show_usage_guide
                ;;
            6)
                echo -e "${GREEN}退出${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-6${NC}"
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
    main
else
    # 命令行模式
    case $1 in
        "basic"|"1")
            run_basic_test
            ;;
        "standard"|"2")
            run_standard_test
            ;;
        "stress"|"3")
            run_stress_test
            ;;
        "help"|"-h"|"--help")
            echo "用法: $0 [basic|standard|stress|help]"
            echo "  basic    - 运行基础测试"
            echo "  standard - 运行标准测试"
            echo "  stress   - 运行压力测试"
            echo "  help     - 显示帮助"
            ;;
        *)
            echo -e "${RED}未知参数: $1${NC}"
            echo "使用 '$0 help' 查看帮助"
            exit 1
            ;;
    esac
fi