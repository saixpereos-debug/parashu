package scanner

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CraftSYNPacket crafts a raw TCP SYN packet for a target port
// Note: This requires absolute raw socket access (sudo) in real use.
func CraftSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort) ([]byte, error) {
	// TCP Layer
	tcp := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     1105024978,
		SYN:     true,
		Window:  14600,
	}

	// IPv4 Layer
	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	// Pseudo-header for checksum
	tcp.SetNetworkLayerForChecksum(ip)

	// Buffer to store the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
		return nil, fmt.Errorf("failed to serialize layers: %v", err)
	}

	return buf.Bytes(), nil
}

// CraftACKPacket crafts a raw TCP ACK packet
func CraftACKPacket(srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort) ([]byte, error) {
	tcp := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     1105024978,
		ACK:     true,
		Ack:     1,
		Window:  14600,
	}

	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
