package ipselfie

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/rogercoll/ipselfie/pkg/netutils"
	"github.com/rogercoll/ipselfie/pkg/tcpdata"
)

func Watch(ifaceName string) error {
	iface, err := netutils.GetInterface(ifaceName)
	if err != nil {
		return err
	}

	handler, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handler.Close()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	ipv4packet := make(chan layers.IPv4)

	go tcpdata.ReadIPv4(handler, iface, ipv4packet, c)
	fmt.Println("Starting to read...")
	for {
		select {
		case <-c:
			return errors.New("Program finished by user")
		case apacket := <-ipv4packet:
			fmt.Printf("Source IPv4: %v     Destination IPv4: %v\n", apacket.SrcIP, apacket.DstIP)
		}
	}
	return nil
}
