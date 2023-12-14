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
		"os"
		"os/exec"
	//	"os/signal"
	//	"syscall"
	
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
		var filter = "ether proto 0x0842 or udp port 9" 
		handle, err := pcap.OpenLive(interfaceName, 1600, false, pcap.BlockForever)
		if err != nil {
			return err
		}
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatalf("Something in the BPF went wrong!: %v", err)
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
		var mac string
	
		source := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range source.Packets() {
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			udpLayer := packet.Layer(layers.LayerTypeUDP)
	
			if ethLayer != nil {
				ethernetPacket, _ := ethLayer.(*layers.Ethernet)
				if ethernetPacket.EthernetType == 0x0842 {
					fmt.Println("Wake-on-LAN packet")
					mac = extractMACFromPayload(ethernetPacket.Payload)
				}
			}
	
			if udpLayer != nil {
				udpPacket, _ := udpLayer.(*layers.UDP)
				if udpPacket.DstPort == layers.UDPPort(9) {
					fmt.Println("UDP port 9 packet")
					mac = extractMACFromPayload(packet.Data())
				}
			}
			if err := runcmd(mac); err != true {
				return nil
			}
		
		return nil
		
		}
		return nil
	}

	func extractMACFromPayload(payload []byte) string {
		// Assuming payload structure for Wake-on-LAN or UDP packet
		if len(payload) >= 12 {
			return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", payload[6], payload[7], payload[8], payload[9], payload[10], payload[11])
		}
		return ""
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
