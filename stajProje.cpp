#include <iostream>
#include <pcap.h>
#include <map>
#include <string>
#include <fstream> // dosya okuma/yazma kütüphanesi
#pragma comment(lib, "ws2_32.lib") // LNK2019


struct ethernet_header { u_char hedef_mac[6]; u_char kaynak_mac[6]; u_short eth_type; };

struct arp_header {
    u_short donanim_tipi; u_short protokol_tipi; u_char donanim_len; u_char protokol_len;
    u_short islem_tipi; u_char gonderen_mac[6]; u_char gonderen_ip[4]; u_char hedef_mac[6]; u_char hedef_ip[4];
};

struct ip_header {
    u_char ver_ihl; u_char tos; u_short tlen; u_short id; u_short flags_fo;
    u_char ttl; u_char proto; u_short crc; u_char kaynak_ip[4]; u_char hedef_ip[4];
};

// port numaralarýný okumak için
struct tcp_header {
    u_short kaynak_port;
    u_short hedef_port;
};

struct udp_header {
    u_short kaynak_port;
    u_short hedef_port;
};

std::map<std::string, std::string> ip_mac_tablosu;

// log dosyasý oluþturucu
std::ofstream log_dosyasi("ids_guvenlik_log.txt", std::ios::app);


std::string ip_to_string(const u_char* ip) {
    return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." + std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}
std::string mac_to_string(const u_char* mac) {
    char buffer[18];
    sprintf_s(buffer, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buffer);
}


void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    const struct ethernet_header* eth = (struct ethernet_header*)pkt_data;
    u_short protokol = ntohs(eth->eth_type);

    // arp
    if (protokol == 0x0806) {
        const struct arp_header* arp = (struct arp_header*)(pkt_data + 14);
        std::string gonderen_ip = ip_to_string(arp->gonderen_ip);
        std::string gonderen_mac = mac_to_string(arp->gonderen_mac);

        if (ip_mac_tablosu.find(gonderen_ip) == ip_mac_tablosu.end()) {
            ip_mac_tablosu[gonderen_ip] = gonderen_mac;
        }
        else {
            std::string bilinen_mac = ip_mac_tablosu[gonderen_ip];
            // test için baþta == yaptým sonra !='e çevirdim
            if (bilinen_mac != gonderen_mac) {
                std::cout << "\n KRITIK GUVENLIK ALARMI: ARP SPOOFING! -> IP: " << gonderen_ip << "\n";

                // alarmlarý dosyaya kaydet
                if (log_dosyasi.is_open()) {
                    log_dosyasi << "[ALARM] ARP Spoofing Tespiti! IP: " << gonderen_ip
                        << " | Kayitli MAC: " << bilinen_mac
                        << " | Sahte MAC: " << gonderen_mac << "\n";
                }
            }
        }
    }
    // ipv4
    else if (protokol == 0x0800) {
        const struct ip_header* ip = (struct ip_header*)(pkt_data + 14);

        
        int ip_baslik_uzunlugu = (ip->ver_ihl & 0x0F) * 4;

        std::string s_ip = ip_to_string(ip->kaynak_ip);
        std::string h_ip = ip_to_string(ip->hedef_ip);

        // tcp
        if (ip->proto == 6) {
            
            const struct tcp_header* tcp = (struct tcp_header*)(pkt_data + 14 + ip_baslik_uzunlugu);

            u_short s_port = ntohs(tcp->kaynak_port);
            u_short h_port = ntohs(tcp->hedef_port);

            std::cout << "[TCP] " << s_ip << ":" << s_port << " --> " << h_ip << ":" << h_port;
            if (h_port == 443 || s_port == 443) std::cout << " (Guvenli Web / HTTPS)";
            else if (h_port == 80 || s_port == 80) std::cout << " (Normal Web / HTTP)";
            std::cout << "\n";
        }
        // udp
        else if (ip->proto == 17) {
            const struct udp_header* udp = (struct udp_header*)(pkt_data + 14 + ip_baslik_uzunlugu);
            u_short s_port = ntohs(udp->kaynak_port);
            u_short h_port = ntohs(udp->hedef_port);

            std::cout << "[UDP] " << s_ip << ":" << s_port << " --> " << h_ip << ":" << h_port;
            if (h_port == 53 || s_port == 53) std::cout << " (DNS Sorgusu)";
            std::cout << "\n";
        }
    }
}

int main() {
    std::cout << "--- Mini-IDS ve Trafik Analizoru ---\n";
    if (log_dosyasi.is_open()) {
        std::cout << "[+] ids_guvenlik_log.txt dosyasi kayit icin basariyla acildi.\n";
        log_dosyasi << "\n--- YENI OTURUM BASLADI ---\n";
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs, * d;
    int i = 0, secim;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) return 1;
    for (d = alldevs; d != NULL; d = d->next) std::cout << ++i << ". " << d->name << "\n";
    if (i == 0) return 0;

    std::cout << "\nDinlenecek adaptor numarasi: ";
    std::cin >> secim;
    for (d = alldevs, i = 0; i < secim - 1; d = d->next, i++);

    pcap_t* adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (adhandle == NULL) return -1;
    pcap_freealldevs(alldevs);

    std::cout << "\nAg dinleniyor...\n";
    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);
    if (log_dosyasi.is_open()) log_dosyasi.close(); // dosya açýk kalmýþsa kapat
    return 0;
}