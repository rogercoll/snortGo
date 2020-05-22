package tcpdata

import (
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func ReadIPv4(handler *pcap.Handle, iface *net.Interface, ipv4Packet chan<- layers.IPv4, stop <-chan os.Signal) {
	defer close(ipv4Packet)
	src := gopacket.NewPacketSource(handler, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ipv4Layer == nil {
				continue
			}
			ipv4 := ipv4Layer.(*layers.IPv4)
			ipv4Packet <- *ipv4
		}
	}
}
