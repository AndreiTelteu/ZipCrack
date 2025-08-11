#!/bin/bash

# Build script for compiling GLSL shaders to SPIR-V
# Requires glslc from the Vulkan SDK

SHADER_DIR="shaders"

if ! command -v glslc &> /dev/null; then
    echo "Error: glslc not found. Please install the Vulkan SDK."
    echo "On Windows: Download from https://vulkan.lunarg.com/sdk/home"
    echo "On Ubuntu: sudo apt install vulkan-sdk"
    echo "On macOS: brew install vulkan-sdk"
    exit 1
fi

echo "Compiling shaders..."
glslc "$SHADER_DIR/zipcrack.comp" -o "$SHADER_DIR/zipcrack.spv"

if [ $? -eq 0 ]; then
    echo "Shader compilation successful!"
else
    echo "Shader compilation failed!"
    exit 1
fi