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

func snort(iPacket *gopacket.Packet, rules *map[rule]action) {
	if pTransport := (*iPacket).TransportLayer(); pTransport != nil {
		//fmt.Println(pTransport.LayerType().String())
		//fmt.Printf("Dst packet: %s\n", pTransport.TransportFlow().Dst().String())
		tmpRule := rule{
			transport: pTransport.LayerType(),
			dstPort:   pTransport.TransportFlow().Dst(),
			srcPort:   pTransport.TransportFlow().Src(),
		}
		for key, value := range *rules {
			if key.transport == tmpRule.transport || key.transport == -1 {
				if key.dstPort == tmpRule.dstPort || key.dstPort.EndpointType() == -1 {
					if key.srcPort == tmpRule.dstPort || key.srcPort.EndpointType() == -1 {
						fmt.Printf("Packet matched: %v\n", value.msg)
					}
				}
			}
		}

	}
}

func Watch(ifaceName, rulesFile string) error {
	readRulesFile(rulesFile)
	iface, err := netutils.GetInterface(ifaceName)
	if err != nil {
		return err
	}
	tmpRule := rule{transport: layers.LayerTypeTCP,
		dstPort: layers.NewTCPPortEndpoint(443),
		srcPort: gopacket.NewEndpoint(-1, []byte("any")),
	}

	rules := make(map[rule]action)
	rules[tmpRule] = action{msg: "ALERT: Someone trying tcp request to secured port 4444"}

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
