package findInterfaces

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"log"
)

func FindDevices() {
	// 查看网卡信息
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("interfaces found:")
	for _, device := range interfaces {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}
