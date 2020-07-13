package snort

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gopkg.in/yaml.v2"
)

var (
	LayerTypeAny = gopacket.RegisterLayerType(-1, gopacket.LayerTypeMetadata{Name: "ANY"})
	AnyPort      = gopacket.RegisterEndpointType(-1, gopacket.EndpointTypeMetadata{Name: "ANYPORT"})
)

type rule struct {
	transport gopacket.LayerType //UDP, TCP, etc
	srcAddr   gopacket.Endpoint  //Source Address layers.NewIPEndpoint
	srcPort   gopacket.Endpoint  //goPacket.Endpoint
	dstAddr   gopacket.Endpoint  //Destination Address layers.NewIPEndpoint
	dstPort   gopacket.Endpoint  //goPacket.Endpoint
}

type confRule struct {
	Protocol string `yaml:"protocol"`
	Src      string `yaml:"src"`
	Dst      string `yaml:"dst"`
	SrcP     int16  `yaml:"sport"`
	DstP     int16  `yaml:"dport"`
}

type conf struct {
	Rules []confRule `yaml:"rules"`
}

/*
 TCP ANY ANY ANY ANY => tmpRule := rule{transport: layers.LayerTypeTCP}

 TCP ANY 443 => tmpRule := rule{transport: layers.LayerTypeTCP,
		dstPort: layers.NewTCPPortEndpoint(443),
	}


*/

type action struct {
	msg string
}

func readRulesFile(filepath string) *[]rule {
	var c conf
	yamlFile, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	fileRules := make([]rule, len(c.Rules))
	for i, r := range c.Rules {
		fileRules[i].dstPort = gopacket.NewEndpoint(AnyPort, []byte("unused"))
		fileRules[i].srcPort = gopacket.NewEndpoint(AnyPort, []byte("unused"))
		switch r.Protocol {
		case "TCP":
			fileRules[i].transport = layers.LayerTypeTCP
			if r.DstP >= 0 {
				fileRules[i].dstPort = layers.NewTCPPortEndpoint(layers.TCPPort(uint16(r.DstP)))
			}
			if r.SrcP >= 0 {
				fileRules[i].srcPort = layers.NewTCPPortEndpoint(layers.TCPPort(uint16(r.SrcP)))
			}
		case "UDP":
			fileRules[i].transport = layers.LayerTypeUDP
			if r.DstP >= 0 {
				fileRules[i].dstPort = layers.NewUDPPortEndpoint(layers.UDPPort(uint16(r.DstP)))
			}
			if r.SrcP >= 0 {
				fileRules[i].srcPort = layers.NewUDPPortEndpoint(layers.UDPPort(uint16(r.SrcP)))
			}
		default:
			fileRules[i].transport = LayerTypeAny
		}
	}
	fmt.Printf("%+v\n", c)
	return &fileRules
}
