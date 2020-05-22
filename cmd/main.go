package main

import (
	"log"

	"github.com/rogercoll/ipselfie"
)

func main() {
	err := ipselfie.Watch("wlp58s0")
	if err != nil {
		log.Fatal(err)
	}
}
