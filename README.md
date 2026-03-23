# WAST - Web Application Security Testing

WAST is a modern web application security testing tool designed for both AI agents and human operators. It provides comprehensive security testing capabilities with structured output formats for seamless automation.

## Features

- **AI-First Design**: All commands support structured output formats (JSON/YAML) for seamless AI agent integration
- **Comprehensive Testing**: Full-spectrum web security testing from reconnaissance to vulnerability scanning
- **Cross-Platform**: Single binary distribution for Linux, macOS, and Windows
- **Modular Architecture**: Command-based structure for targeted testing

### Commands

| Command | Description |
|---------|-------------|
| `wast recon` | Reconnaissance and information gathering |
| `wast crawl` | Web crawling and content discovery |
| `wast intercept` | Traffic interception and analysis |
| `wast scan` | Security vulnerability scanning |
| `wast api` | API security testing |

## Installation

### From Source

Requires Go 1.21 or later.

```bash
# Clone the repository
git clone https://github.com/djannot/wast.git
cd wast

# Build the binary
make build

# The binary will be available at ./bin/wast
```

### Build for All Platforms

```bash
make build-all
```

This creates binaries for:
- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64)

## Usage

### Basic Usage

```bash
# Show help
wast --help

# Show version
wast --version

# Run reconnaissance
wast recon example.com

# Crawl a website
wast crawl https://example.com

# Run a security scan
wast scan https://example.com
```

### Output Formats

WAST supports multiple output formats for different use cases:

```bash
# Human-readable text (default)
wast scan https://example.com

# JSON output (ideal for AI agents and automation)
wast scan https://example.com --output json

# YAML output
wast scan https://example.com --output yaml
```

### Verbosity Control

```bash
# Quiet mode - suppress all output except errors
wast scan https://example.com --quiet

# Verbose mode - detailed output
wast scan https://example.com --verbose
```

## Project Structure

```
wast/
├── cmd/
│   └── wast/
│       ├── main.go           # Entry point
│       └── root.go           # Root command definition
├── internal/
│   └── commands/
│       ├── recon.go          # Reconnaissance command
│       ├── crawl.go          # Crawling command
│       ├── intercept.go      # Traffic interception command
│       ├── scan.go           # Security scanning command
│       └── api.go            # API testing command
├── pkg/
│   └── output/
│       └── formatter.go      # JSON/YAML/text output formatting
├── docs/
├── Makefile
├── go.mod
├── go.sum
├── .gitignore
└── README.md
```

## Development

### Prerequisites

- Go 1.21 or later
- Make (optional, for using Makefile)

### Building

```bash
# Build for current platform
make build

# Build for all platforms
make build-all
```

### Testing

```bash
# Run all tests
make test

# Run tests with coverage report
make test-coverage
```

### Linting

```bash
# Run linters
make lint

# Format code
make fmt

# Check formatting
make fmt-check
```

### Dependencies

```bash
# Download and tidy dependencies
make deps
```

## AI Agent Integration

WAST is designed with first-class support for AI agent integration. Key features:

1. **Structured Output**: All commands support `--output json` and `--output yaml` for machine-readable output
2. **Consistent Schema**: Output follows a consistent structure across all commands
3. **Exit Codes**: Meaningful exit codes for success/failure detection
4. **Quiet Mode**: `--quiet` flag for suppressing non-essential output

### Example AI Agent Usage

```bash
# Get reconnaissance data as JSON
wast recon example.com --output json

# Parse the output in your AI agent
# The output will be structured like:
# {
#   "success": true,
#   "command": "recon",
#   "message": "...",
#   "data": { ... }
# }
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
