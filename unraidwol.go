//
// Virtual Wake-on-LAN
//
// Listens for a WOL magic packet (UDP), then connects to the local libvirt socket and finds a matching VM
// If a matching VM is found, it is started (if not already running)
//
// Assumes the VM has a static MAC configured
// Assumes libvirtd connection is at /var/run/libvirt/libvirt-sock
//
// Filters on len=102 and len=144 (WOL packet) and len=234 (WOL packet with password)

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
)

func main() {
	var iface string                                            // Interface we'll listen on
	var buffer = int32(1600)                                    // Buffer for packets received
	var filter = "ether proto 0x0842 or udp port 9" 			// PCAP filter to catch UDP WOL packets
	var mac string
	var err  error

	flag.StringVar(&iface, "interface", "", "Network interface name to listen on")
	flag.Parse()

	if !deviceExists(iface) {
		log.Fatalf("Unable to open device: %s", iface)
	}

	handler, err := pcap.OpenLive(iface, buffer, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("failed to open device: %v", err)
	}
	defer handler.Close()

	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatalf("Something in the BPF went wrong!: %v", err)
	}

	// Handle every packet received, looping forever
	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			udpLayer := packet.Layer(layers.LayerTypeUDP)

			if ethLayer != nil {
				ethernetPacket, _ := ethLayer.(*layers.Ethernet)
				// Check for Wake-on-LAN EtherType (0x0842)
				if ethernetPacket.EthernetType == 0x0842 {
					fmt.Println("Wake-on-LAN packet")
					dstMAC := ethernetPacket.DstMAC.String()
					// Print Ethernet information
					payload := ethernetPacket.Payload
					//ffffffffffff5254006825ba
					mac = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", payload[6], payload[7], payload[8], payload[9], payload[10], payload[11])
				}
			}
			if udpLayer != nil {
				udpPacket, _ := udpLayer.(*layers.UDP)
				// Check for UDP port 9
				if udpPacket.DstPort == layers.UDPPort(9) {
					fmt.Println("UDP port 9 packet")
					mac, err = GrabMACAddrUDP(packet)
				}
			}
			if err != nil {
				log.Fatalf("Error with packet: %v", err)
			}
			runcmd(mac)
	}
}

func runcmd(mac string) bool {

    app := "/usr/local/sbin/wol.run"   
    arg := mac

    cmd := exec.Command(app, arg)
    stdout, err := cmd.Output()

    if err != nil {
        fmt.Println(err.Error())
        return false
    }
    // Print the output
    fmt.Println(string(stdout))
    return true
}

// Return the first MAC address seen in the UDP WOL packet
func GrabMACAddrUDP(packet gopacket.Packet) (string, error) {
	app := packet.ApplicationLayer()
	if app != nil {
		payload := app.Payload()
		mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", payload[12], payload[13], payload[14], payload[15], payload[16], payload[17])
		fmt.Printf("found MAC: %s\n", mac)
		return mac, nil
	}
	return "", errors.New("no MAC found in packet")
}

// Check if the network device exists
func deviceExists(interfacename string) bool {
	if interfacename == "" {
		fmt.Printf("No interface to listen on specified\n\n")
		flag.PrintDefaults()
		return false
	}
	devices, err := pcap.FindAllDevs()

	if err != nil {
		log.Panic(err)
	}

	for _, device := range devices {
		if device.Name == interfacename {
			return true
		}
	}
	return false
}
