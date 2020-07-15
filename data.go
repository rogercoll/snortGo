package snort

import (
	"encoding/binary"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gopkg.in/yaml.v2"
)

var (
	LayerTypeAny = gopacket.RegisterLayerType(-1, gopacket.LayerTypeMetadata{Name: "ANY"})
	Any          = gopacket.RegisterEndpointType(-1, gopacket.EndpointTypeMetadata{Name: "ANYPORT"})
)

type rule struct {
	transport gopacket.LayerType //UDP, TCP, etc
	srcAddr   gopacket.Endpoint  //Source Address layers.NewIPEndpoint
	srcPort   gopacket.Endpoint  //goPacket.Endpoint
	dstAddr   gopacket.Endpoint  //Destination Address layers.NewIPEndpoint
	dstPort   gopacket.Endpoint  //goPacket.Endpoint
	act       action             //what to do when a packet matches
}

type action struct {
	Msg   string `yaml:"msg"`
	Level int8   `yaml:"level"`
	Cmd   string `yaml:"cmd"`
}

type confRule struct {
	Protocol string `yaml:"protocol"`
	Src      string `yaml:"src"`
	Dst      string `yaml:"dst"`
	SrcP     int16  `yaml:"sport"`
	DstP     int16  `yaml:"dport"`
	Action   action `yaml:"action"`
}

type conf struct {
	Rules []confRule `yaml:"rules"`
}

func formatAddr(addr string) []byte {
	octets := strings.Split(addr, ".")
	addrbytes := make([]uint8, 4)
	for i, octet := range octets {
		aux, err := strconv.Atoi(octet)
		if err != nil {
			log.Fatal(err)
			return []byte{}
		}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(aux))
		addrbytes[i] = b[0]
	}
	sAddr := net.IPv4(addrbytes[0], addrbytes[1], addrbytes[2], addrbytes[3])
	sAddr = sAddr.To4()
	return sAddr
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
		fileRules[i].act = r.Action
		fileRules[i].dstPort = gopacket.NewEndpoint(Any, []byte("unused"))
		fileRules[i].srcPort = gopacket.NewEndpoint(Any, []byte("unused"))
		fileRules[i].dstAddr = gopacket.NewEndpoint(Any, []byte("unused"))
		fileRules[i].srcAddr = gopacket.NewEndpoint(Any, []byte("unused"))
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
		if r.Dst != "-1" {
			fileRules[i].dstAddr = layers.NewIPEndpoint(formatAddr(r.Dst))
		}
		if r.Src != "-1" {
			fileRules[i].srcAddr = layers.NewIPEndpoint(formatAddr(r.Src))
		}
	}
	return &fileRules
}
