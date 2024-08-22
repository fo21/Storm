#include <iostream>
#include <fstream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <unordered_map>
#include <vector>
#include <algorithm>

// Function to convert integer IP to string
std::string ipToString(uint32_t ip) {
    return std::to_string(ip & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 24) & 0xFF);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *packet;
    int packetCount = 0;
    int totalVolume = 0;

    std::unordered_map<std::string, int> destIpCount;
    std::unordered_map<std::string, int> protocolCount;
    protocolCount["TCP"] = 0;
    protocolCount["UDP"] = 0;
    protocolCount["ICMP"] = 0;
    protocolCount["Other"] = 0;


    // Open the pcap file
    handle = pcap_open_offline("packet-storm.pcap", errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return 1;
    }

    // Output file
    std::ofstream outfile("analysis_output.txt");

    // Process each packet
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        packetCount++;
        totalVolume += header->len;

        // Extract the IP header
        struct ip *ipHeader = (struct ip *)(packet + 14); // 14 bytes for Ethernet header

        std::string destIp = ipToString(ntohl(ipHeader->ip_dst.s_addr));
        destIpCount[destIp]++;

        // Determine the protocol
        switch (ipHeader->ip_p) {
            case IPPROTO_TCP:
                protocolCount["TCP"]++;
                break;
            case IPPROTO_UDP:
                protocolCount["UDP"]++;
                break;
            case IPPROTO_ICMP:
                protocolCount["ICMP"]++;
                break;
            default:
                protocolCount["Other"]++;
                break;
        }
    }

    pcap_close(handle);

    // Calculate average packet size
    double averagePacketSize = packetCount > 0 ? static_cast<double>(totalVolume) / packetCount : 0.0;

    // Sort destination IPs by frequency
    std::vector<std::pair<std::string, int>> sortedDestIps(destIpCount.begin(), destIpCount.end());
    struct {
    bool operator()(const std::pair<std::string, int>& a, const std::pair<std::string, int>& b) const {
        return b.second < a.second;
    }
    } customLess;

    std::sort(sortedDestIps.begin(), sortedDestIps.end(), customLess);


    // Output results
    outfile << "Total packets: " << packetCount << std::endl;
    outfile << "Total volume of data received: " << totalVolume << " bytes" << std::endl;
    outfile << "Average packet size: " << averagePacketSize << " bytes" << std::endl;
    outfile << "Top Destination IPs by Frequency:" << std::endl;
    for (std::vector<std::pair<std::string, int>>::const_iterator entry = sortedDestIps.begin(); entry != sortedDestIps.end(); ++entry){
        outfile << entry->first << ": " << entry->second << " packets" << std::endl;
    }

    outfile << "Transport Layer Protocols Count:" << std::endl;
    for (std::unordered_map<std::string, int>::const_iterator entry = protocolCount.begin(); entry != protocolCount.end(); ++entry){
        outfile << entry->first << ": " << entry->second << " packets" << std::endl;
    }

    outfile.close();

    std::cout << "Analysis complete. Results saved to analysis_output.txt" << std::endl;

    return 0;
}
