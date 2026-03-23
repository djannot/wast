// WAST (Web Application Security Testing) CLI tool.
//
// WAST is a modern web application security testing tool designed for both
// AI agents and human operators. It provides comprehensive testing capabilities
// with structured output formats for seamless automation.
package main

import (
	"os"
)

func main() {
	if err := Execute(); err != nil {
		os.Exit(1)
	}
}
