#include <iostream>
#include <vector>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>



#pragma comment(lib, "ws2_32.lib")
#define _WIN32_WINNT 0x0600 

// Ethernet Header Structure
struct EthHeader {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
};

// IP Header Structure
struct IpHeader {
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t ecn : 2;
    uint8_t dscp : 6;
    uint16_t total_length;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dest_addr;
  
};

// TCP Header Structure
struct TcpHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t res1 : 4;
    uint8_t doff : 4;
    uint8_t fin : 1;
    uint8_t syn : 1;
    uint8_t rst : 1;
    uint8_t psh : 1;
    uint8_t ack : 1;
    uint8_t urg : 1;
    uint8_t ece : 1;
    uint8_t cwr : 1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
  
};

void printEthHeader(const EthHeader& eth);
void printIpHeader(const IpHeader& ip);
void printTcpHeader(const TcpHeader& tcp);
void printPayload(const std::vector<uint8_t>& payload);

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary file>\n";
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << argv[1] << "\n";
        return 1;
    }

    EthHeader eth;
    if (!file.read(reinterpret_cast<char*>(&eth), sizeof(EthHeader))) {
        std::cerr << "Error reading Ethernet header.\n";
        return 1;
    }

    printEthHeader(eth);

    IpHeader ip;
    if (!file.read(reinterpret_cast<char*>(&ip), sizeof(IpHeader))) {
        std::cerr << "Error reading IP header.\n";
        return 1;
    }

 
    printIpHeader(ip);



    TcpHeader tcp;
    if (!file.read(reinterpret_cast<char*>(&tcp), sizeof(TcpHeader))) {
        std::cerr << "Error reading TCP header.\n";
        return 1;
    }
    printTcpHeader(tcp);

    // Calculate payload size
    int payloadSize = ntohs(ip.total_length) - (ip.ihl * 4) - (tcp.doff * 4);
    std::vector<uint8_t> payload(payloadSize);

    if (payloadSize > 0) {
        if (!file.read(reinterpret_cast<char*>(payload.data()), payloadSize)) {
            std::cerr << "Error reading payload.\n";
            return 1;
        }
    }

    printPayload(payload);

    return 0;
}

void printEthHeader(const EthHeader& eth) {
    std::cout << "Ethernet Header:\n";
    std::cout << "----------------\n";
    std::cout << "Destination MAC address: ";
    for (int i = 0; i < 6; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(eth.dest[i]);
        if (i < 5) std::cout << ":";
    }
    std::cout << "\nSource MAC address:      ";
    for (int i = 0; i < 6; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(eth.src[i]);
        if (i < 5) std::cout << ":";
    }
    std::cout << "\nType:            " << std::hex << std::setw(4) << std::setfill('0') << ntohs(eth.type) << "\n\n";
}







void printIpHeader(const IpHeader& ip) {
    std::cout << "IPv4 Header:\n";
    std::cout << "----------\n";
    std::cout << "Version: " << static_cast<unsigned>(ip.version) << "\n";
    std::cout << "Internet Header Length: " << static_cast<unsigned>(ip.ihl * 4) << " bytes\n";
    std::cout << "DSCP: " << static_cast<unsigned>(ip.dscp) << "\n";
    std::cout << "ECN: " << static_cast<unsigned>(ip.ecn) << "\n";
    std::cout << "Total Length: " << ntohs(ip.total_length) << "\n";
    std::cout << "Identification: " << ntohs(ip.id) << "\n";
    std::cout << "Flags: " << ((ntohs(ip.frag_off) & 0xE000) >> 13) << "\n";
    std::cout << "Fragment Offset: " << (ntohs(ip.frag_off) & 0x1FFF) << "\n";
    std::cout << "Time to Live: " << static_cast<unsigned>(ip.ttl) << "\n";
    std::cout << "Protocol: " << static_cast<unsigned>(ip.protocol) << "\n";
    std::cout << "IP Checksum: " << std::hex << ntohs(ip.checksum) << std::dec << "\n";

    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip.src_addr), src_ip, INET_ADDRSTRLEN);
    std::cout << "Source IP Address: " << src_ip << "\n";

    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip.dest_addr), dest_ip, INET_ADDRSTRLEN);
    std::cout << "Destination IP Address: " << dest_ip << "\n\n";

}


void printTcpHeader(const TcpHeader& tcp) {
    std::cout << "TCP Header:\n";
    std::cout << "-----------\n";
    std::cout << "Source Port: " << std::dec << ntohs(tcp.src_port) << "\n";
    std::cout << "Destination Port: " << ntohs(tcp.dest_port) << "\n";
    std::cout << "Raw Sequence Number: " << ntohl(tcp.seq) << "\n";
    std::cout << "Raw Acknowledgment Number: " << ntohl(tcp.ack_seq) << "\n";
    std::cout << "Data Offset: " << static_cast<unsigned>(tcp.doff * 4) << " bytes\n";

    // Print each flag
    std::cout << "Flags: ";
    std::cout << (tcp.urg ? "URG " : "");
    std::cout << (tcp.ack ? "ACK " : "");
    std::cout << (tcp.psh ? "PSH " : "");
    std::cout << (tcp.rst ? "RST " : "");
    std::cout << (tcp.syn ? "SYN " : "");
    std::cout << (tcp.fin ? "FIN " : "");
    std::cout << "\n";

    std::cout << "Window Size: " << std::dec << ntohs(tcp.window) << "\n";
    std::cout << "TCP Checksum: " << std::hex << ntohs(tcp.check) << "\n";
    std::cout << "Urgent Pointer: " << std::dec << ntohs(tcp.urg_ptr) << "\n\n";

}

void printPayload(const std::vector<uint8_t>& payload) {
    std::cout << "Payload (" << payload.size() << " bytes):\n";
    for (size_t i = 0; i < payload.size(); ++i) {
        if (i > 0 && i % 16 == 0) {
            std::cout << std::endl;
        }
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<unsigned>(payload[i]) << " ";
    }
    std::cout << std::dec << std::endl; 
}


