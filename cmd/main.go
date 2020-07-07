package main

import (
	"log"

	"github.com/rogercoll/snort"
)

func main() {
	err := snort.Watch("wlp58s0", "/path/to/file")
	if err != nil {
		log.Fatal(err)
	}
}
