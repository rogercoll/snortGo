package snort

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gopkg.in/yaml.v2"
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

func readRulesFile(filepath string) {
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
		switch r.Protocol {
		case "TCP":
			fileRules[i].transport = layers.LayerTypeTCP
		case "UDP":
			fileRules[i].transport = layers.LayerTypeUDP
		default:
			fileRules[i].transport = gopacket.RegisterLayerType(-1, gopacket.LayerTypeMetadata{Name: "ANY"})
		}
	}
	fmt.Printf("%+v\n", c)
}
