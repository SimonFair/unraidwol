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
	package main

	import (
		"fmt"
		"log"
		"os"
		"os/exec"
		"os/signal"
		"syscall"
	
		"github.com/google/gopacket"
		"github.com/google/gopacket/pcap"
		"github.com/google/gopacket/layers"
		"github.com/urfave/cli/v2"
	)
	
	func main() {
		app := &cli.App{
			Name:  "PacketDaemon",
			Usage: "Capture and process network packets",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "daemon",
					Usage: "Run as a daemon",
				},
				&cli.StringFlag{
					Name:  "interface",
					Usage: "Network interface name",
				},
			},
			Action: func(c *cli.Context) error {
				if c.Bool("daemon") {
					// Run as a new process (daemon)
					return runAsDaemon(c.String("interface"))
				}
	
				// Run as a regular program
				return runRegular(c.String("interface"))
			},
		}
	
		err := app.Run(os.Args)
		if err != nil {
			log.Fatal(err)
		}
	}
	
	func runRegular(interfaceName string) error {
		handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
		if err != nil {
			return err
		}
		defer handle.Close()
	
		return processPackets(handle)
	}
	
	func runAsDaemon(interfaceName string) error {
		// Build the command to run the program as a daemon
		cmd := exec.Command(os.Args[0], "--daemon=false", "--interface="+interfaceName)
	
		// Start the new process in the background
		err := cmd.Start()
		if err != nil {
			return err
		}
	
		// Detach the child process from the parent process
		err = cmd.Process.Release()
		if err != nil {
			return err
		}
	
		fmt.Printf("Daemon started with PID %d\n", cmd.Process.Pid)
		return nil
	}
	
func processPackets(handle *pcap.Handle) error {
	// Start processing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case packet, ok := <-packetSource.Packets():
			if !ok {
				fmt.Println("Packet source closed. Exiting.")
				return nil
			}

			// Decode and process the packet
			processPacket(packet)
		}
	}
}

func processPacket(packet gopacket.Packet) {
	// Decode the Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		ethernetPacket, _ := ethLayer.(*layers.Ethernet)

		// Convert MAC addresses to string
		srcMAC := ethernetPacket.SrcMAC.String()
		dstMAC := ethernetPacket.DstMAC.String()

		// Print Ethernet information
		fmt.Printf("Source MAC: %s\n", srcMAC)
		fmt.Printf("Destination MAC: %s\n", dstMAC)
		fmt.Printf("EtherType: %v\n", ethernetPacket.EthernetType)

		// Decode the payload for EtherType 2114
		payload := ethernetPacket.Payload
		fmt.Printf("Payload (hex): %x\n", payload)

		// Convert payload to string and print (assuming it's ASCII text)
		payloadString := string(payload)
		fmt.Printf("Payload (string): %s\n", payloadString)
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
