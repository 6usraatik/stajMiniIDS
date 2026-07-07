#include <iostream>
#include <pcap.h>
#pragma comment(lib, "ws2_32.lib")

// 14 bayt
struct ethernet_header {
    u_char hedef_mac[6];  
    u_char kaynak_mac[6]; 
    u_short eth_type;     
};


void mac_yazdir(const u_char* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// paket her geldiðinde çalýþýr
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    static int paket_sayisi = 1;

    //type casting
    const struct ethernet_header* eth = (struct ethernet_header*)pkt_data;

    std::cout << "\n[" << paket_sayisi++ << ". Paket] - Toplam Boyut: " << header->len << " bayt\n";

    // katman 2
    std::cout << " [Katman 2] Kaynak MAC : ";
    mac_yazdir(eth->kaynak_mac);

    std::cout << "\n [Katman 2] Hedef MAC  : ";
    mac_yazdir(eth->hedef_mac);

    // big endian to ntohs
    u_short protokol = ntohs(eth->eth_type);
    std::cout << "\n [Katman 2] EtherType  : 0x" << std::hex << protokol << std::dec;

    if (protokol == 0x0800) std::cout << " (IPv4 Paketi - Katman 3'te IP var!)";
    else if (protokol == 0x0806) std::cout << " (ARP Paketi - Katman 3'te ARP var!)";
    else if (protokol == 0x86DD) std::cout << " (IPv6 Paketi)";
    else std::cout << " (Diger Protokol)";

    std::cout << "\n-------------------------------------------------------------";
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs, * d;
    int i = 0, secim;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) return 1;

    for (d = alldevs; d != NULL; d = d->next) {
        std::cout << ++i << ". " << d->name << " (" << (d->description ? d->description : "Tanim yok") << ")\n";
    }

    if (i == 0) return 0;

    std::cout << "\nDinlenecek adaptor numarasi (1-" << i << "): ";
    std::cin >> secim;

    if (secim < 1 || secim > i) {
        pcap_freealldevs(alldevs);
        return 0;
    }

    for (d = alldevs, i = 0; i < secim - 1; d = d->next, i++);

    std::cout << "\n[" << d->description << "] uzerinden Katman 2 (Ethernet) analizi basladi...\n";

    pcap_t* adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (adhandle == NULL) {
        pcap_freealldevs(alldevs);
        return -1;
    }

    pcap_freealldevs(alldevs);

    // 15 paket yakala
    pcap_loop(adhandle, 15, packet_handler, NULL);

    pcap_close(adhandle);
    std::cout << "\nKatman 2 dinlemesi tamamlandi. Cikmak icin bir tusa basin...";
    std::cin.ignore();
    std::cin.get();

    return 0;
}