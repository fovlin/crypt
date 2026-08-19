package record

import (
	"fmt"
	"os"
)

func Info(format string, value ...any) {
	fmt.Fprintf(os.Stdout, "[\033[1;32mINFO\033[0m]: "+format+"\n", value...)
}

func Warn(format string, value ...any) {
	fmt.Fprintf(os.Stdout, "[\033[1;33mWARN\033[0m]: "+format+"\n", value...)
}

func Error(format string, value ...any) {
	fmt.Fprintf(os.Stderr, "[\033[1;31mERROR\033[0m]: "+format+"\n", value...)
}

func Debug(format string, value ...any) {
	fmt.Fprintf(os.Stdout, "[\033[1;34mDebug\033[0m]: "+format+"\n", value...)
}