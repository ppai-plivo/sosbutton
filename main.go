package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/plivo/plivo-go"
)

// amazon dash button config (set these)
const (
	NIC        = ""
	BUTTON_MAC = ""
)

// plivo config (set these)
const (
	DEST_NUMBER      = ""
	PLIVO_AUTH_ID    = ""
	PLIVO_AUTH_TOKEN = ""
)

func sendMessage() error {

	client, err := plivo.NewClient(PLIVO_AUTH_ID, PLIVO_AUTH_TOKEN, &plivo.ClientOptions{})
	if err != nil {
		return err
	}

	resp, err := client.Messages.Create(plivo.MessageCreateParams{
		Src:  "+919876543210",
		Dst:  DEST_NUMBER,
		Text: BUTTON_MAC + " sent SOS.",
	})
	if err != nil {
		return err
	}

	fmt.Printf("%v\n", resp)
	return nil
}

func main() {

	buttonMac, err := net.ParseMAC(BUTTON_MAC)
	if err != nil {
		log.Fatalf("net.ParseMAC failed: %s", err.Error())
	}

	handle, err := pcap.OpenLive(NIC, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("pcap.OpenLive() failed: %s", err.Error())
	}
	defer handle.Close()

	filter := "ether src host " + BUTTON_MAC
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("handle.SetBPFFilter() failed: %s", err.Error())
	}

	var lastARPTime time.Time

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range src.Packets() {
		ethPacket, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if !ok {
			continue
		}
		if bytes.Equal(ethPacket.SrcMAC, buttonMac) {
			// dash buttons generate multiple ARP packets, so place a time guard
			if time.Since(lastARPTime) < time.Duration(2*time.Second) {
				continue
			}
			lastARPTime = time.Now()

			fmt.Printf("Button %s was pressed.\n", ethPacket.SrcMAC.String())
			if err := sendMessage(); err != nil {
				log.Printf("sendMessage() failed: %s", err.Error())
			}
		}
	}
}
