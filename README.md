# ZipCrack GPU

High-performance ZIP password cracking tool with CPU and GPU (Vulkan) backends.

## Features

- **CPU Backend**: Portable fallback using Go and yeka/zip library
- **GPU Backend**: High-performance Vulkan compute shaders for AMD/NVIDIA GPUs
- **ZipCrypto Support**: Traditional PKWARE encryption (WinZip AES planned for future release)
- **Cross-Platform**: Windows, Linux, macOS (with Vulkan SDK)
- **Real-time TUI**: Progress tracking with per-thread/GPU throughput metrics

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Generator     │───▶│   Runner         │───▶│   Verifier      │
│ (Password       │    │ (Batch           │    │ (CPU/Vulkan)    │
│  Candidates)    │    │  Coordination)   │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   TUI Display    │
                       │ (Stats/Progress) │
                       └──────────────────┘
```

### Backend Selection

- **CPU Backend**: Uses `yeka/zip` library for full ZIP compatibility, per-password verification
- **Vulkan Backend**: Custom ZIP header parser + GLSL compute shader for massive parallelization

## Setup

### Prerequisites

1. **Go 1.23+**
2. **Vulkan SDK** (for GPU backend)

### Windows Setup

1. **Install Vulkan SDK**:
   - Download from [LunarG Vulkan SDK](https://vulkan.lunarg.com/sdk/home)
   - Install and ensure `glslc` is in PATH
   - Update GPU drivers (AMD: Adrenalin, NVIDIA: GeForce Experience)

2. **Build**:
   ```cmd
   git clone <repository>
   cd zipcrack
   go mod tidy
   .\build_shaders.sh   # Compile GLSL to SPIR-V
   go build ./...
   ```

### Linux Setup

1. **Install Vulkan SDK**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install vulkan-sdk vulkan-tools
   
   # Arch Linux
   sudo pacman -S vulkan-devel shaderc
   ```

2. **Build**:
   ```bash
   git clone <repository>
   cd zipcrack
   go mod tidy
   chmod +x build_shaders.sh
   ./build_shaders.sh   # Compile GLSL to SPIR-V
   go build ./...
   ```

## Usage

### Basic Usage

```bash
./zipcrack
```

Interactive prompts will guide you through:
- ZIP file path
- Character set selection (letters, numbers, symbols)
- Password length range
- Number of threads
- Backend selection: **cpu** or **vulkan**

### Example Session

```
ZIP file path [/home/user/target.zip]: ./encrypted.zip
Use letters (a-zA-Z)? (y/n) [y]: y
Use numbers (0-9)? (y/n) [y]: y  
Use special common (!@#$%^&*_-)? (y/n) [y]: n
Use special ALL (ASCII punctuation)? (y/n) [n]: n
Minimum password length [1]: 4
Maximum password length [8]: 6
Threads (logical CPUs=8) [8]: 8
Batch size [8192]: 4096
Verification backend (cpu|vulkan) [cpu]: vulkan

ZIP Password Brute Forcer (q to quit)
Workers: 8 | Refresh: 2s | Elapsed: 15s

[T01:    1250 p/s] [T02:    1180 p/s] [T03:    1220 p/s] [T04:    1190 p/s]
[T05:    1205 p/s] [T06:    1240 p/s] [T07:    1160 p/s] [T08:    1185 p/s]

Progress: [████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 23.4% | ETA: 2m 15s

Throughput total:    9630 p/s | Attempts total: 144450

Password found: pass123
```

## Performance Comparison

| Backend | Throughput | Use Case |
|---------|------------|----------|
| CPU (8 threads) | ~10K p/s | Compatibility, AES support |
| Vulkan GPU (AMD RX 6800) | ~500K p/s | ZipCrypto, high throughput |
| Vulkan GPU (RTX 3080) | ~800K p/s | ZipCrypto, maximum speed |

*Note: Performance varies by password length, GPU model, and zip complexity*

## Limitations

### Current Release
- **ZipCrypto only**: Traditional PKWARE encryption
- **No AES support**: WinZip AES-128/256 planned for v2.0
- **Single file targeting**: Chooses smallest encrypted file in archive

### GPU Backend
- **Vulkan SDK required**: Must install and compile shaders
- **Memory limits**: ~4096 passwords per batch (configurable)
- **Driver dependency**: Requires recent GPU drivers

## Technical Details

### ZipCrypto Algorithm

The GPU implementation uses a GLSL compute shader with the full PKWARE stream cipher:

1. **Key Initialization**: Three 32-bit keys from password
2. **Header Decryption**: 12-byte encrypted header
3. **Check Byte Verification**: CRC32 or MS-DOS time-based validation

### File Structure

```
zipcrack/
├── cmd/zipcrack/main.go           # CLI entry point
├── internal/
│   ├── cracker/
│   │   ├── generator.go           # Password candidate generation
│   │   ├── runner.go              # Batch coordination & workers  
│   │   └── zipcheck.go            # Legacy ZIP verification
│   ├── verifier/
│   │   ├── verifier.go            # Backend interface & CPU impl
│   │   ├── vulkan.go              # GPU backend implementation
│   │   └── zipheader.go           # Lightweight ZIP parser
│   ├── charset/charset.go         # Character set utilities
│   └── tui/model.go               # Terminal UI & progress tracking
├── shaders/
│   ├── zipcrack.comp              # GLSL compute shader
│   └── zipcrack.spv               # Compiled SPIR-V bytecode
└── build_shaders.sh               # Shader compilation script
```

## Troubleshooting

### Vulkan Issues

1. **"Vulkan not found"**:
   - Install Vulkan SDK and GPU drivers
   - Verify: `vulkaninfo` shows device info

2. **"No suitable device"**:
   - GPU must support Vulkan compute
   - Update drivers to latest version

3. **"Shader compilation failed"**:
   - Ensure `glslc` is in PATH
   - Run `./build_shaders.sh` manually

### Performance Issues

1. **Low GPU throughput**:
   - Increase batch size (4096→8192)
   - Check GPU memory usage
   - Verify single-threaded vs multi-worker config

2. **CPU faster than GPU**:
   - GPU overhead for small passwords
   - Switch to CPU for lengths < 4 chars

## Development

### Adding New Backends

1. Implement `Verifier` interface in `internal/verifier/`
2. Add backend selection in `internal/cracker/runner.go`
3. Update CLI prompts in `cmd/zipcrack/main.go`

### Future Roadmap

- **v2.0**: WinZip AES-128/256 support
- **v2.1**: OpenCL backend for broader GPU support
- **v2.2**: Dictionary attacks and hybrid modes
- **v2.3**: Distributed cracking across multiple GPUs/nodes

## License

MIT License - see LICENSE file for details.
