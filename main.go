package main

import (
	"os"

	"sneaker/cmd"
)

func main() {
	cmd.WebFS = webFS
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
