#include <iostream>
#include <pcap.h>
#include <map>
#include <string>
#pragma comment(lib, "ws2_32.lib") // LNK2019 hatasý almamak için

// ethernet baþlýðý
struct ethernet_header {
    u_char hedef_mac[6];
    u_char kaynak_mac[6];
    u_short eth_type;
};

// arp baþlýðý
struct arp_header {
    u_short donanim_tipi;
    u_short protokol_tipi;
    u_char  donanim_len;
    u_char  protokol_len;
    u_short islem_tipi;
    u_char  gonderen_mac[6];
    u_char  gonderen_ip[4];
    u_char  hedef_mac[6];
    u_char  hedef_ip[4];
};

// ipv4 baþlýðý
struct ip_header {
    u_char  ver_ihl;        // versiyon (4 bit) + baþlýk uzunluðu (4 bit)
    u_char  tos;            // hizmet tipi
    u_short tlen;           // toplam uzunluk
    u_short id;             // kimlik
    u_short flags_fo;       // bayraklar + fragman offseti
    u_char  ttl;            // yaþam süresi (time to live)
    u_char  proto;          // üst katman protokolü (TCP=6, UDP=17, ICMP=1)
    u_short crc;            // baþlýk saðlama toplamý
    u_char  kaynak_ip[4];   // gönderen cihazýn ip'si
    u_char  hedef_ip[4];    // hedef cihazýn ip'si
};

// güvenlik hafýzasý
std::map<std::string, std::string> ip_mac_tablosu;

// yard. fonk.
std::string ip_to_string(const u_char* ip) {
    return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." +
        std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}

std::string mac_to_string(const u_char* mac) {
    char buffer[18];
    sprintf_s(buffer, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buffer);
}


void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    const struct ethernet_header* eth = (struct ethernet_header*)pkt_data;
    u_short protokol = ntohs(eth->eth_type);

    // eðer paket arp ise
    if (protokol == 0x0806) {
        const struct arp_header* arp = (struct arp_header*)(pkt_data + 14);
        std::string gonderen_ip = ip_to_string(arp->gonderen_ip);
        std::string gonderen_mac = mac_to_string(arp->gonderen_mac);

        if (ip_mac_tablosu.find(gonderen_ip) == ip_mac_tablosu.end()) {
            ip_mac_tablosu[gonderen_ip] = gonderen_mac;
            std::cout << "\n[+] [ARP BELLEK] YENI CIHAZ ADRESI GUVENLE KAYDEDILDI -> IP: " << gonderen_ip << " | MAC: " << gonderen_mac << std::endl;
        }
        else {
            std::string bilinen_mac = ip_mac_tablosu[gonderen_ip];
            if (bilinen_mac != gonderen_mac) {
                std::cout << "\n=============================================================\n";
                std::cout << " KRITIK GUVENLIK ALARMI: ARP SPOOFING / MITM TESPITI!\n";
                std::cout << "=============================================================\n";
                std::cout << " -> Sahtekarlik Yapilan IP Adresi : " << gonderen_ip << std::endl;
                std::cout << " -> Hafizadaki Gercek MAC Adresi  : " << bilinen_mac << std::endl;
                std::cout << " -> Saldirgandan Gelen Sahte MAC  : " << gonderen_mac << std::endl;
                std::cout << "=============================================================\n";
            }
        }
    }

    // eðer paket ip ise
    else if (protokol == 0x0800) {
        static int ip_paket_sayisi = 1;

        
        const struct ip_header* ip = (struct ip_header*)(pkt_data + 14);

        std::cout << "\n[" << ip_paket_sayisi++ << ". IPv4 Internet Paketi] - Boyut: " << header->len << " bayt\n";
        std::cout << "   Kaynak IP -> " << ip_to_string(ip->kaynak_ip) << std::endl;
        std::cout << "   Hedef IP  -> " << ip_to_string(ip->hedef_ip) << std::endl;

        // içerideki taþýnan protokolün tespiti
        std::cout << "   Tasinan Protokol: ";
        if (ip->proto == 1)       std::cout << "ICMP (Ping Sinyali)" << std::endl;
        else if (ip->proto == 6)  std::cout << "TCP (Web / Guvenli Veri Trafigi)" << std::endl;
        else if (ip->proto == 17) std::cout << "UDP (Canli Yayin / DNS Sorgusu)" << std::endl;
        else                      std::cout << "Diger (" << (int)ip->proto << ")" << std::endl;

        std::cout << "   Yasam Suresi (TTL): " << (int)ip->ttl << " hop\n";
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
    std::cout << "\n[" << d->description << "] uzerinden Akilli Paket Analizi (IDS) Aktif...\n";

    pcap_t* adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (adhandle == NULL) return -1;
    pcap_freealldevs(alldevs);

    pcap_loop(adhandle, 0, packet_handler, NULL);
    pcap_close(adhandle);
    return 0;
}