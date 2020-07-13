package main

import (
	"log"

	"github.com/rogercoll/snort"
)

func main() {
	err := snort.Watch("wlp58s0", "./myrules.yaml")
	if err != nil {
		log.Fatal(err)
	}
}
