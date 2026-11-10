// Benchmark fixture: cross-compiled to Linux ELF (static and PIE builds) so the
// ELF checks run against real toolchain output, verified with llvm-objdump.
package main

import "fmt"

func main() { fmt.Println("hello") }
