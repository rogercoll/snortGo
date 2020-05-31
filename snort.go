package snort

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rogercoll/snort/pkg/netutils"
)

type rule struct {
	transport gopacket.LayerType //UDP, TCP, etc
	srcPort   gopacket.Endpoint  //goPacket.Endpoint
	dstPort   gopacket.Endpoint  //goPacket.Endpoint
}

func readInterface(iface *net.Interface, iPacket chan<- gopacket.Packet, stop <-chan os.Signal) {
	defer close(iPacket)
	handler, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		//here must be changed to return the proper error
		return
	}
	defer handler.Close()
	src := gopacket.NewPacketSource(handler, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			iPacket <- packet
		}
	}
}

func snort(iPacket *gopacket.Packet, rules *map[rule]bool) {
	if pTransport := (*iPacket).TransportLayer(); pTransport != nil {
		fmt.Println(pTransport.LayerType().String())
		fmt.Printf("Dst packet: %s\n", pTransport.TransportFlow().Dst().String())
		fmt.Printf("Src packet: %s\n", pTransport.TransportFlow().Src().String())
		tmpRule := rule{
			transport: pTransport.LayerType(),
			srcPort:   pTransport.TransportFlow().Src(),
		}
		if _, ok := (*rules)[tmpRule]; ok {
			fmt.Println("Rule matched executing action")
		}
	}
}

func Watch(ifaceName string) error {
	iface, err := netutils.GetInterface(ifaceName)
	if err != nil {
		return err
	}
	tmpRule := rule{transport: layers.LayerTypeTCP,
		srcPort: layers.NewTCPPortEndpoint(443),
		//dstPort: layers.NewTCPPortEndpoint(41318),
	}

	rules := make(map[rule]bool)
	rules[tmpRule] = true

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	iPacket := make(chan gopacket.Packet)

	go readInterface(iface, iPacket, c)
	fmt.Println("Starting to read...")
	fmt.Println("Starting to read...")
	for {
		select {
		case actualPacket := <-iPacket:
			go snort(&actualPacket, &rules)
		case <-c:
			return errors.New("Program finished by user")
		}
	}
	return nil
}
