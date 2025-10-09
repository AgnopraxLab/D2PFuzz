#!/bin/bash

# Quick Blob Test Script - 快速验证 Blob 功能

echo "╔═══════════════════════════════════════════════════════╗"
echo "║     Quick Blob Transaction Test & Verification       ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# 1. 编译
echo "🔨 Step 1: Building manual tool..."
cd cmd/manual
if go build -o manual 2>&1 | head -10; then
    echo "✅ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi
echo ""

# 2. 测试
echo "🧪 Step 2: Running blob-single test..."
echo "This will test:"
echo "  - Blob data generation (with canonical scalar fix)"
echo "  - KZG commitment computation"
echo "  - Blob transaction construction"
echo "  - Transaction sending"
echo ""
echo "Starting test in 3 seconds..."
sleep 3

./manual -mode blob-single 2>&1 | tee /tmp/blob_test_output.log

TEST_RESULT=${PIPESTATUS[0]}
echo ""

if [[ $TEST_RESULT -eq 0 ]]; then
    echo "✅ Test completed successfully!"
else
    echo "⚠️  Test completed with exit code: $TEST_RESULT"
fi
echo ""

# 3. 检查输出
echo "📊 Step 3: Analyzing test output..."
echo ""

# 检查是否有错误
if grep -qi "scalar is not canonical" /tmp/blob_test_output.log; then
    echo "❌ FAILED: 'scalar is not canonical' error still exists!"
    echo "The fix may not have worked."
elif grep -qi "failed to generate blob" /tmp/blob_test_output.log; then
    echo "❌ FAILED: Blob generation error detected"
elif grep -qi "failed to send" /tmp/blob_test_output.log; then
    echo "⚠️  WARNING: Transaction sending error detected"
else
    echo "✅ No critical errors detected in blob generation!"
fi
echo ""

# 检查是否生成了交易哈希
if [[ -f "txhashes.txt" ]]; then
    TX_COUNT=$(wc -l < txhashes.txt)
    echo "✅ Generated $TX_COUNT transaction hash(es):"
    head -3 txhashes.txt | while read hash; do
        echo "   - $hash"
    done
    if [[ $TX_COUNT -gt 3 ]]; then
        echo "   ... and $((TX_COUNT - 3)) more"
    fi
    echo ""
    
    # 4. 查询交易
    echo "🔍 Step 4: Querying transaction status..."
    echo "Waiting 5 seconds for transactions to be mined..."
    sleep 5
    echo ""
    
    cd ../../scripts
    if [[ -f "query_blob_tx.sh" ]]; then
        ./query_blob_tx.sh -f ../cmd/manual/txhashes.txt
    else
        echo "⚠️  query_blob_tx.sh not found, using regular query..."
        if [[ -f "query_tx.sh" ]]; then
            ./query_tx.sh -f ../cmd/manual/txhashes.txt
        fi
    fi
else
    echo "⚠️  No txhashes.txt file found"
    echo "Checking for transaction hashes in log output..."
    if grep -oE '0x[0-9a-fA-F]{64}' /tmp/blob_test_output.log | head -1; then
        echo "✅ Found transaction hashes in output"
    else
        echo "❌ No transaction hashes found"
    fi
fi

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║                  Test Complete                        ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "Full test output saved to: /tmp/blob_test_output.log"
echo ""
echo "To run again: ./test_blob_now.sh"
echo "For more options: ./scripts/verify_blob_test.sh --help"

