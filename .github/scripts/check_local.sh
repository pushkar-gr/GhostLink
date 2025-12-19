#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== Starting Local CI Check ===${NC}"

# 1. Check Formatting
echo -e "\n${GREEN}[1/3] Checking Formatting...${NC}"
if cargo fmt -- --check; then
    echo "Formatting OK"
else
    echo -e "${RED}❌ Formatting Failed. Run 'cargo fmt' to fix automatically.${NC}"
    exit 1
fi

# 2. Check Linting (Clippy)
echo -e "\n${GREEN}[2/3] Running Linter (Clippy)...${NC}"
if cargo clippy -- -D warnings; then
    echo "Linting OK"
else
    echo -e "${RED}❌ Linting Failed. Fix the errors above.${NC}"
    exit 1
fi

# 3. Run Tests
echo -e "\n${GREEN}[3/3] Running Tests...${NC}"
if cargo test; then
    echo "Tests Passed"
else
    echo -e "${RED}❌ Tests Failed.${NC}"
    exit 1
fi

echo -e "\n${GREEN}=== ALL CHECKS PASSED. READY TO PUSH! ===${NC}"
