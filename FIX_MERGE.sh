#!/bin/bash
# Quick fix for merge conflicts

echo "🔧 Fixing merge conflict..."
echo ""

cd ~/build/LulzSec-ULTIMATE-Forensic-Scanner-V2

# Stash local changes
echo "📦 Stashing your local changes..."
git stash

# Pull updates
echo "📥 Pulling latest from GitHub..."
git pull origin main

# Reapply your changes
echo "♻️  Reapplying your changes..."
git stash pop

echo ""
echo "✅ Done! Now you can run:"
echo "   ./BUILD_WINDOWS_ON_LINUX.sh"
