package openPcap

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

var (
	device            = "en0"
	snapshotLen int32 = 1024
	promiscuous       = false
	err         error
	timeout     = 30 * time.Second
	handle      *pcap.Handle
)

func OpenPcap() {
	// Open device
	if handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout); err != nil {
		log.Fatal(err)
	}

	defer handle.Close()
	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		fmt.Println(packet)
	}
}
