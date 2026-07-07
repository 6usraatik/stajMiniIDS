#include <iostream>
#include <pcap.h>
#pragma comment(lib, "ws2_32.lib") //LNK2019 hatasýný almamak için

// 14 bayt
struct ethernet_header {
    u_char hedef_mac[6]; //6 bayt
    u_char kaynak_mac[6]; //6 bayt
    u_short eth_type; //2 bayt
};

// 28 bayt
struct arp_header {
    u_short donanim_tipi; // ethernet için her zaman 1 
    u_short protokol_tipi;// IPv4 için 0x0800 
    u_char  donanim_len;  // MAC adresi uzunluðu (6 bayt)
    u_char  protokol_len; // IP adresi uzunluðu (4 bayt)
    u_short islem_tipi;   // 1 = ARP request (soru), 2 = ARP reply (cevap)
    u_char  gonderen_mac[6]; // gönderen cihazýn MAC'i
    u_char  gonderen_ip[4];  // gönderen cihazýn IP'si 
    u_char  hedef_mac[6];    // aranan cihazýn MAC'i
    u_char  hedef_ip[4];     // aranan cihazýn IP'si 
};

void mac_yazdir(const u_char* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// IP adresini basan fonksiyon
void ip_yazdir(const u_char* ip) {
    printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    
    const struct ethernet_header* eth = (struct ethernet_header*)pkt_data;
    u_short protokol = ntohs(eth->eth_type); //network to host short

    // sadece ARP paketleri
    if (protokol == 0x0806) {
        static int arp_sayisi = 1;
        std::cout << "\n[" << arp_sayisi++ << ". ARP PAKETÝ YAKALANDI!]\n";

        
        const struct arp_header* arp = (struct arp_header*)(pkt_data + 14);

        u_short islem = ntohs(arp->islem_tipi);
        if (islem == 1) std::cout << " [Tur] : ARP SORUSU (Who has...?) -> Bir IP'nin MAC'i araniyor.\n";
        else if (islem == 2) std::cout << " [Tur] : ARP CEVABI (Reply) -> MAC adresi bildiriliyor.\n";

        std::cout << " Gönderen : IP ("; ip_yazdir(arp->gonderen_ip); std::cout << ") - MAC ("; mac_yazdir(arp->gonderen_mac); std::cout << ")\n";
        std::cout << " Aranan   : IP ("; ip_yazdir(arp->hedef_ip); std::cout << ") - MAC ("; mac_yazdir(arp->hedef_mac); std::cout << ")\n";
        std::cout << "-------------------------------------------------------------";
    }
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
    std::cout << "\nDinlenecek adaptor numarasi: ";
    std::cin >> secim;

    for (d = alldevs, i = 0; i < secim - 1; d = d->next, i++);
    std::cout << "\n[" << d->description << "] uzerinden ARP paketleri bekleniyor...\n";

    pcap_t* adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (adhandle == NULL) return -1;
    pcap_freealldevs(alldevs);

    // zorla durdurulana kadar dinle
    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);
    return 0;
}