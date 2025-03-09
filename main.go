package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	_ "modernc.org/sqlite"
)

var (
	packetCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "network_packets_total",
			Help: "Total number of network packets captured",
		},
		[]string{"protocol"},
	)
	db *sql.DB
)

func init() {
	prometheus.MustRegister(packetCount)
}

func main() {
	var err error
	db, err = sql.Open("sqlite", "packets.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS packets (id INTEGER PRIMARY KEY, src_ip TEXT, dst_ip TEXT, protocol TEXT, src_port INTEGER, dst_port INTEGER)")
	if err != nil {
		log.Fatal(err)
	}

	go capturePackets()

	r := gin.Default()
	r.GET("/api/packets", getPackets)
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	r.Run(":8080")
}

func capturePackets() {
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	var srcIP, dstIP, protocol string
	var srcPort, dstPort int

	if netLayer := packet.NetworkLayer(); netLayer != nil {
		srcIPRaw, dstIPRaw := netLayer.NetworkFlow().Endpoints()
		srcIP = srcIPRaw.String()
		dstIP = dstIPRaw.String()
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort, dstPort = int(tcp.SrcPort), int(tcp.DstPort)
		protocol = "TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort, dstPort = int(udp.SrcPort), int(udp.DstPort)
		protocol = "UDP"
	}

	if protocol != "" {
		packetCount.WithLabelValues(protocol).Inc()
		_, err := db.Exec("INSERT INTO packets (src_ip, dst_ip, protocol, src_port, dst_port) VALUES (?, ?, ?, ?, ?)", srcIP, dstIP, protocol, srcPort, dstPort)
		if err != nil {
			log.Println("DB Insert Error:", err)
		}
	}
}

func getPackets(c *gin.Context) {
	rows, err := db.Query("SELECT src_ip, dst_ip, protocol, src_port, dst_port FROM packets ORDER BY id DESC LIMIT 100")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var packets []map[string]interface{}
	for rows.Next() {
		var srcIP, dstIP, protocol string
		var srcPort, dstPort int
		if err := rows.Scan(&srcIP, &dstIP, &protocol, &srcPort, &dstPort); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		packets = append(packets, gin.H{
			"src_ip":   srcIP,
			"dst_ip":   dstIP,
			"protocol": protocol,
			"src_port": srcPort,
			"dst_port": dstPort,
		})
	}
	c.JSON(http.StatusOK, packets)
}
