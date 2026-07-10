#include <iostream>
#include <pcap.h>
#include <map>
#include <string>
#include <fstream>
#pragma comment(lib, "ws2_32.lib")

// istatistik sayacý
int toplam_paket = 0;
int tcp_sayisi = 0;
int udp_sayisi = 0;
int arp_sayisi = 0;
int alarm_sayisi = 0;


struct ethernet_header { u_char hedef_mac[6]; u_char kaynak_mac[6]; u_short eth_type; };

struct arp_header {
    u_short donanim_tipi; u_short protokol_tipi; u_char donanim_len; u_char protokol_len;
    u_short islem_tipi; u_char gonderen_mac[6]; u_char gonderen_ip[4]; u_char hedef_mac[6]; u_char hedef_ip[4];
};

struct ip_header {
    u_char ver_ihl; u_char tos; u_short tlen; u_short id; u_short flags_fo;
    u_char ttl; u_char proto; u_short crc; u_char kaynak_ip[4]; u_char hedef_ip[4];
};

struct tcp_header { u_short kaynak_port; u_short hedef_port; };
struct udp_header { u_short kaynak_port; u_short hedef_port; };

std::map<std::string, std::string> ip_mac_tablosu;

// log dosyasý
std::ofstream log_dosyasi("C:\\Users\\HUAWEI\\Desktop\\ids_guvenlik_log.txt", std::ios::app);

std::string ip_to_string(const u_char* ip) {
    return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." + std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}
std::string mac_to_string(const u_char* mac) {
    char buffer[18];
    sprintf_s(buffer, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buffer);
}


void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    toplam_paket++; // her gelen pakette sayacý artýr
    const struct ethernet_header* eth = (struct ethernet_header*)pkt_data;
    u_short protokol = ntohs(eth->eth_type);

    // arp
    if (protokol == 0x0806) {
        arp_sayisi++; 
        const struct arp_header* arp = (struct arp_header*)(pkt_data + 14);
        std::string gonderen_ip = ip_to_string(arp->gonderen_ip);
        std::string gonderen_mac = mac_to_string(arp->gonderen_mac);

        if (ip_mac_tablosu.find(gonderen_ip) == ip_mac_tablosu.end()) {
            ip_mac_tablosu[gonderen_ip] = gonderen_mac;
        }
        else {
            std::string bilinen_mac = ip_mac_tablosu[gonderen_ip];
            // test için baþta == yapýldý sonra olmasý gereken != formatýna çevrildi
            if (bilinen_mac != gonderen_mac) {
                alarm_sayisi++; 
                std::cout << "\nKRITIK GUVENLIK ALARMI: ARP SPOOFING! -> IP: " << gonderen_ip << "\n";
                if (log_dosyasi.is_open()) {
                    log_dosyasi << "[ALARM] ARP Spoofing! IP: " << gonderen_ip << " | MAC: " << gonderen_mac << "\n";
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

        if (ip->proto == 6) {
            tcp_sayisi++; 
            const struct tcp_header* tcp = (struct tcp_header*)(pkt_data + 14 + ip_baslik_uzunlugu);
            u_short s_port = ntohs(tcp->kaynak_port);
            u_short h_port = ntohs(tcp->hedef_port);
            std::cout << "[TCP] " << s_ip << ":" << s_port << " --> " << h_ip << ":" << h_port << "\n";
        }
        else if (ip->proto == 17) {
            udp_sayisi++; 
            const struct udp_header* udp = (struct udp_header*)(pkt_data + 14 + ip_baslik_uzunlugu);
            u_short s_port = ntohs(udp->kaynak_port);
            u_short h_port = ntohs(udp->hedef_port);
            std::cout << "[UDP] " << s_ip << ":" << s_port << " --> " << h_ip << ":" << h_port << "\n";
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs, * d;
    int i = 0, secim, paket_limiti;
    std::string filtre_girdisi;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) return 1;
    for (d = alldevs; d != NULL; d = d->next) std::cout << ++i << ". " << d->name << "\n";
    if (i == 0) return 0;

    std::cout << "\nDinlenecek adaptor numarasi: ";
    std::cin >> secim;
    for (d = alldevs, i = 0; i < secim - 1; d = d->next, i++);

    pcap_t* adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (adhandle == NULL) return -1;
    pcap_freealldevs(alldevs);

    // bpf filtresi
    std::cout << "\n[BPF] Uygulanacak filtreyi yazin (Orn: tcp, udp, arp) veya tumu icin bos birakin: ";
    std::cin.ignore();
    std::getline(std::cin, filtre_girdisi);

    if (!filtre_girdisi.empty()) {
        struct bpf_program fcode;
        
        if (pcap_compile(adhandle, &fcode, filtre_girdisi.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
            std::cout << "\n[HATA] Hatali filtre soz dizimi!\n";
            return -1;
        }
        pcap_setfilter(adhandle, &fcode);
        std::cout << "[+] BPF Filtresi Aktif: " << filtre_girdisi << "\n";
    }

    std::cout << "Kac paket yakalandiktan sonra oturum sonlansin? (Orn: 50, 1000): ";
    std::cin >> paket_limiti;

    std::cout << "\nAg dinleniyor... Bitis limiti: " << paket_limiti << " paket.\n";

    
    pcap_loop(adhandle, paket_limiti, packet_handler, NULL);
    pcap_close(adhandle);
    if (log_dosyasi.is_open()) log_dosyasi.close();

    // istatistik raporu
    std::cout << "\n================ OTURUM OZETI ================\n";
    std::cout << " Toplam Incelenen Paket  : " << toplam_paket << "\n";
    std::cout << " Analiz Edilen TCP       : " << tcp_sayisi << "\n";
    std::cout << " Analiz Edilen UDP       : " << udp_sayisi << "\n";
    std::cout << " Yakalanan ARP           : " << arp_sayisi << "\n";
    std::cout << " Uretilen Guvenlik Alarmi: " << alarm_sayisi << "\n";
    std::cout << "==============================================\n";
    std::cout << "Log dosyasi Masaustune kaydedildi.\n";

    std::cout << "Cikmak icin bir tusa basin...";
    std::cin.ignore();
    std::cin.get();

    return 0;
}