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
	//"net"
	//"strings"
	//"time"
	"os/exec"

	//"github.com/antchfx/xmlquery"
	//"github.com/digitalocean/go-libvirt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
)

func main() {
	var iface string                                            // Interface we'll listen on
	var buffer = int32(1600)                                    // Buffer for packets received
	var filter = "ether proto 0x0842 or udp port 9" // PCAP filter to catch UDP WOL packets

	flag.StringVar(&iface, "interface", "", "Network interface name to listen on")
	flag.Parse()

	if !deviceExists(iface) {
		log.Fatalf("Unable to open device: %s", iface)
	}

	handler, err := pcap.OpenLive(iface, buffer, true, pcap.BlockForever)
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
			if ethernetPacket.EthernetType == 2114 {
				fmt.Println("Wake-on-LAN packet")
							// Print Ethernet information
			fmt.Printf("Source MAC: %s\n", ethernetPacket.SrcMAC)
			fmt.Printf("Destination MAC: %s\n", ethernetPacket.DstMAC)
			fmt.Printf("EtherType: %v\n", ethernetPacket.EthernetType)

			// Decode the payload for EtherType 2114
			payload := ethernetPacket.Payload
			fmt.Printf("Payload (hex): %x\n", payload)
				mac:= ethernetPacket.DstMAC
				err:= nil
			}
		}

		if udpLayer != nil {
			udpPacket, _ := udpLayer.(*layers.UDP)

			// Check for UDP port 9
			if udpPacket.DstPort == layers.UDPPort(9) {
				fmt.Println("UDP port 9 packet")
				mac, err := GrabMACAddrUDP(packet)
			}
		}
		// Called for each packet received
		fmt.Println(packet)
		//mac, err := GrabMACAddr(packet)
		if err != nil {
			log.Fatalf("Error with packet: %v", err)
		}
		runcmd(mac)
	}
}

func runcmd(mac string) bool {
    app := "echo"

    arg0 := "-e"
    arg1 := "Hello world"
    arg2 := "\n\tfrom"
    arg3 := mac

    cmd := exec.Command(app, arg0, arg1, arg2, arg3)
    stdout, err := cmd.Output()

    if err != nil {
        fmt.Println(err.Error())
        return false
    }

    // Print the output
    fmt.Println(string(stdout))

    app2 := "/usr/local/sbin/wol.run"   
    arg4 := mac

    cmd2 := exec.Command(app2, arg4)
    stdout2, err := cmd2.Output()

    if err != nil {
        fmt.Println(err.Error())
        return false
    }

    // Print the output
    fmt.Println(string(stdout2))
    return true
}

// Return the first MAC address seen in the Ether WOL packet
func GrabMACAddrEther(packet gopacket.Packet) (string, error) {
	app := packet.ApplicationLayer()
	if app != nil {
		payload := app.Payload()
		fmt.Println(payload)
		mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", payload[12], payload[13], payload[14], payload[15], payload[16], payload[17])
		fmt.Printf("found MAC: %s\n", mac)
		return mac, nil
	}
	return "", errors.New("no MAC found in packet")
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
