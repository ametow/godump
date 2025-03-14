package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

var (
	interfaceName string
	protocol      string
	port          int
	follow        bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "godump",
		Short: "A simple packet capture tool like tcpdump",
		Run:   runCapture,
	}

	rootCmd.Flags().StringVarP(&interfaceName, "interface", "i", "en0", "Network interface to capture on")
	rootCmd.Flags().StringVarP(&protocol, "protocol", "P", "", "Filter by protocol (tcp/udp)")
	rootCmd.Flags().IntVarP(&port, "port", "p", 0, "Filter by port")
	rootCmd.Flags().BoolVarP(&follow, "follow", "f", false, "Attach to terminal and display live packets")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runCapture(cmd *cobra.Command, args []string) {
	fmt.Printf("Capturing packets on interface: %s\n", interfaceName)

	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("\nStopping capture...")
		handle.Close()
		os.Exit(0)
	}()

	for packet := range packetSource.Packets() {
		if follow {
			processPacket(packet)
		} else {
			go processPacket(packet)
		}
	}
}

func processPacket(packet gopacket.Packet) {
	var srcIP, dstIP, proto string
	var srcPort, dstPort int

	if netLayer := packet.NetworkLayer(); netLayer != nil {
		srcIPRaw, dstIPRaw := netLayer.NetworkFlow().Endpoints()
		srcIP, dstIP = srcIPRaw.String(), dstIPRaw.String()
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if protocol == "tcp" || protocol == "" {
			tcp := tcpLayer.(*layers.TCP)
			srcPort, dstPort = int(tcp.SrcPort), int(tcp.DstPort)
			proto = "TCP"
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if protocol == "udp" || protocol == "" {
			udp := udpLayer.(*layers.UDP)
			srcPort, dstPort = int(udp.SrcPort), int(udp.DstPort)
			proto = "UDP"
		}
	}

	if proto != "" && (port == 0 || srcPort == port || dstPort == port) {
		fmt.Printf("%s %s:%d -> %s:%d\n", proto, srcIP, srcPort, dstIP, dstPort)
	}
}
