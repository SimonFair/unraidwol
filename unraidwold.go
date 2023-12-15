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
		"io"
		"io/ioutil"
		"log"
		"log/syslog"
		"os"
		"os/exec"
		//"os/signal"
		//"syscall"
	
		"github.com/google/gopacket"
		"github.com/google/gopacket/pcap"
		"github.com/google/gopacket/layers"
		"github.com/urfave/cli/v2"
	)

	var logger *log.Logger
	
	func main() {
		app := &cli.App{
			Name:    "unraidwold",
			Usage:   "Capture and process WOL Network packages",
			Version: "1.0.0",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "interface",
					Usage: "Network interface name",
				},
				&cli.StringFlag{
					Name:  "log",
					Usage: "Log file path",
				},
				&cli.BoolFlag{
					Name:  "promiscuous",
					Usage: "Enable promiscuous mode",
				},
				&cli.BoolFlag{
					Name:  "version",
					Usage: "Print the version",
				},
			},
			Action: func(c *cli.Context) error {
				// Check if the version flag is set
				if c.Bool("version") {
					fmt.Printf("unraidwold version %s\n", app.Version)
					return nil
				}
	
				// Set up logging
				logFile := c.String("log")
	
				setupLogging(logFile)
	
				// Check if promiscuous mode is enabled
				if c.Bool("promiscuous") {
					logger.Info("Promiscuous mode is enabled")
					// Additional actions for promiscuous mode can be added here
				}
	
				return runRegular(c.String("interface"))
			},
		}
	
		err := app.Run(os.Args)
		if err != nil {
			logger.Fatal(err)
		}
	}


	func setupLogging(logFile string) {
		var logOutput io.Writer
	
		if logFile != "" {
			// If a log file is specified, create or append to the file
			file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				logger.Fatal(err)
			}
			//defer file.Close()
			logOutput = io.MultiWriter(file, os.Stdout) // Log to both file and stdout
		} else {
			// If no log file is specified, log to syslog
			syslogWriter, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "PacketDaemon")
			if err != nil {
				logger.Fatal(err)
			}
			logOutput = syslogWriter
		}
	
		// Create a logger that writes to the specified output
		logger = log.New(logOutput, "", log.LstdFlags)
	}
	
	
	
	func runRegular(interfaceName string) error {


		var filter = "ether proto 0x0842 or udp port 9" 

		// Create a PID file
		pidFile := "/var/run/unraidwold.pid" // Change the path as needed
		err := writePIDFile(pidFile)
		if err != nil {
			return err
		}
		defer removePIDFile(pidFile)
		fmt.Printf("Starting")
		logger.Println("Processing WOL Requests.")

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
	

	func writePIDFile(pidFile string) error {
		pid := os.Getpid()
		pidStr := fmt.Sprintf("%d\n", pid)
		return ioutil.WriteFile(pidFile, []byte(pidStr), 0644)
	}
	
	func removePIDFile(pidFile string) {
		err := os.Remove(pidFile)
		if err != nil {
			logger.Printf("Error removing PID file: %v\n", err)
		}
	}
	
	
	func processPackets(handle *pcap.Handle) error {
		var mac string
		var err error

	
		source := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range source.Packets() {
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			udpLayer := packet.Layer(layers.LayerTypeUDP)
	
			if ethLayer != nil {
				ethernetPacket, _ := ethLayer.(*layers.Ethernet)
				if ethernetPacket.EthernetType == 0x0842 {
					logger.Println("Wake-on-LAN packet")
					payload := ethernetPacket.Payload
					mac = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", payload[6], payload[7], payload[8], payload[9], payload[10], payload[11])
				}
			}
	
			if udpLayer != nil {
				udpPacket, _ := udpLayer.(*layers.UDP)
				if udpPacket.DstPort == layers.UDPPort(9) {
					fmt.Println("UDP port 9 packet")
					mac, err = GrabMACAddrUDP(packet)
					if (err != nil) {
						fmt.Printf("Error")
					}
				}
			}
			runcmd(mac)
		
		
		}
		return nil

	}


func runcmd(mac string) bool {
    app := "/usr/local/emhttp/plugins/dynamix/include/WOLrun.php"   
    arg := mac
    cmd := exec.Command(app, arg)
    stdout, err := cmd.Output()
    if err != nil {
        fmt.Println(err.Error())
        return false
    }
    // Print the output
    logger.Println(string(stdout))
    return true
}

// Return the first MAC address seen in the UDP WOL packet
func GrabMACAddrUDP(packet gopacket.Packet) (string, error) {
	app := packet.ApplicationLayer()
	if app != nil {
		payload := app.Payload()
		mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", payload[12], payload[13], payload[14], payload[15], payload[16], payload[17])
		//fmt.Printf("found MAC: %s\n", mac)
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
