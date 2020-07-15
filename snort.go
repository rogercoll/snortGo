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

func snort(iPacket *gopacket.Packet, rules *[]rule) {
	if pTransport := (*iPacket).TransportLayer(); pTransport != nil {
		//fmt.Println(pTransport.LayerType().String())
		//fmt.Printf("Dst packet: %s\n", pTransport.TransportFlow().Dst().String())
		//fmt.Printf("%+v\n", pTransport)
		tmpRule := rule{
			transport: pTransport.LayerType(),
			dstPort:   pTransport.TransportFlow().Dst(),
			srcPort:   pTransport.TransportFlow().Src(),
		}
		if pNetwork := (*iPacket).NetworkLayer(); pNetwork != nil {
			tmpRule.srcAddr = pNetwork.NetworkFlow().Src()
			tmpRule.dstAddr = pNetwork.NetworkFlow().Dst()
		}
		for _, key := range *rules {
			if key.transport == tmpRule.transport || key.transport == -1 {
				if key.dstPort == tmpRule.dstPort || key.dstPort.EndpointType() == -1 {
					if key.srcPort == tmpRule.dstPort || key.srcPort.EndpointType() == -1 {
						//fmt.Printf("Key Addr: %v   Packet Addr: %v\n", key.srcAddr, tmpRule.srcAddr)
						if key.srcAddr == tmpRule.srcAddr || key.srcAddr.EndpointType() == -1 {
							fmt.Printf("%#v\n", key.act)
							//fmt.Printf("Dst packet port: %s\n", pTransport.TransportFlow().Dst().String())
						}
					}
				}
			}
		}

	}
}

func Watch(ifaceName, rulesFile string) error {
	rules := readRulesFile(rulesFile)
	iface, err := netutils.GetInterface(ifaceName)
	if err != nil {
		return err
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	iPacket := make(chan gopacket.Packet)

	go readInterface(iface, iPacket, c)
	fmt.Println("Starting to sniff...")
	for {
		select {
		case actualPacket := <-iPacket:
			go snort(&actualPacket, rules)
		case <-c:
			return errors.New("Program finished by user")
		}
	}
	return nil
}
