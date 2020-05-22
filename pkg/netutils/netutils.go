package netutils

import (
	"net"
	"fmt"
)


func GetInterface(ifaceName string) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Name == ifaceName {
			return &iface, nil
		}
	}
	return nil, fmt.Errorf("Interface %s not found", ifaceName)
}