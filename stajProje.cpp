#include <iostream>
#include <pcap.h>
#include <map>
#include <set>
#include <string>
#include <fstream>
#pragma comment(lib, "ws2_32.lib")


int toplam_paket = 0;
int tcp_sayisi = 0;
int udp_sayisi = 0;
int arp_sayisi = 0;
int alarm_sayisi = 0;
int port_tarama_sayisi = 0;
int syn_flood_sayisi = 0;  
int kara_liste_engeli = 0;


struct ethernet_header { u_char hedef_mac[6]; u_char kaynak_mac[6]; u_short eth_type; };

struct arp_header {
    u_short donanim_tipi; u_short protokol_tipi; u_char donanim_len; u_char protokol_len;
    u_short islem_tipi; u_char gonderen_mac[6]; u_char gonderen_ip[4]; u_char hedef_mac[6]; u_char hedef_ip[4];
};

struct ip_header {
    u_char ver_ihl; u_char tos; u_short tlen; u_short id; u_short flags_fo;
    u_char ttl; u_char proto; u_short crc; u_char kaynak_ip[4]; u_char hedef_ip[4];
};


struct tcp_header {
    u_short kaynak_port;
    u_short hedef_port;
    u_int seq;
    u_int ack;
    u_char data_offset; 
    u_char flags;       // control flags
    u_short window;
    u_short checksum;
    u_short urgent_ptr;
};

struct udp_header { u_short kaynak_port; u_short hedef_port; };


std::map<std::string, std::string> ip_mac_tablosu;
std::set<std::string> kara_liste;
std::map<std::string, std::set<u_short>> port_tarama_takibi;
std::map<std::string, int> syn_sayaci; 

const int PORT_TARAMA_LIMITI = 4;
const int SYN_FLOOD_LIMITI = 5; // 10dan fazla üst üste syn gönderisini saldýrý kabul et

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
    toplam_paket++;
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
            if (bilinen_mac != gonderen_mac) { // test için baþta == sonra !=
                alarm_sayisi++;
                std::cout << "\nKRITIK ALARM: ARP SPOOFING! -> IP: " << gonderen_ip << "\n";
                kara_liste.insert(gonderen_ip);
                if (log_dosyasi.is_open()) log_dosyasi << "[ALARM - ARP] Sahte MAC! IP: " << gonderen_ip << " Kara Listeye Alindi.\n";
            }
        }
    }
    // ipv4
    else if (protokol == 0x0800) {
        const struct ip_header* ip = (struct ip_header*)(pkt_data + 14);
        int ip_baslik_uzunlugu = (ip->ver_ihl & 0x0F) * 4;

        std::string s_ip = ip_to_string(ip->kaynak_ip);
        std::string h_ip = ip_to_string(ip->hedef_ip);

        
        if (kara_liste.find(s_ip) != kara_liste.end()) {
            kara_liste_engeli++;
            std::cout << "[KARA LISTE ENGELLI TRAFIK] Kaynak: " << s_ip << " -> Hedef: " << h_ip << "\n";
            if (log_dosyasi.is_open()) log_dosyasi << "[KARA LISTE TRAFIGI] " << s_ip << " engellendi.\n";
            return;
        }

        u_short s_port = 0, h_port = 0;

        if (ip->proto == 6) {
            tcp_sayisi++;
            const struct tcp_header* tcp = (struct tcp_header*)(pkt_data + 14 + ip_baslik_uzunlugu);
            s_port = ntohs(tcp->kaynak_port);
            h_port = ntohs(tcp->hedef_port);
            std::cout << "[TCP] " << s_ip << ":" << s_port << " --> " << h_ip << ":" << h_port;

            
            // 0x02 syn flag
            if (tcp->flags & 0x02) {
                syn_sayaci[s_ip]++;
                std::cout << " [SYN Bayragi Yetkili -> Sayac: " << syn_sayaci[s_ip] << "]";

                // limitin üstünde syn flag saldýrý kabul edilir
                if (syn_sayaci[s_ip] == SYN_FLOOD_LIMITI) {
                    alarm_sayisi++;
                    syn_flood_sayisi++;
                    std::cout << "\n=============================================================\n";
                    std::cout << "KRITIK ALARM: SYN FLOOD (DoS/DDoS) TESPITI!\n";
                    std::cout << "=============================================================\n";
                    std::cout << " -> Saldirgan IP : " << s_ip << "\n";
                    std::cout << " -> Durum        : Cok kýsa surede " << SYN_FLOOD_LIMITI << " adet SYN paketi firlatildi!\n";
                    std::cout << " -> Aksiyon      : Hizmet Reddi saldirisi durduruldu, IP KARA LISTEYE alindi.\n";
                    std::cout << "=============================================================\n";

                    kara_liste.insert(s_ip);
                    if (log_dosyasi.is_open()) log_dosyasi << "[ALARM - SYN FLOOD] " << s_ip << " DoS saldirisi firlatti! Kara listeye eklendi.\n";
                }
            }
            std::cout << "\n";
        }
        else if (ip->proto == 17) {
            udp_sayisi++;
            const struct udp_header* udp = (struct udp_header*)(pkt_data + 14 + ip_baslik_uzunlugu);
            s_port = ntohs(udp->kaynak_port);
            h_port = ntohs(udp->hedef_port);
            std::cout << "[UDP] " << s_ip << ":" << s_port << " --> " << h_ip << ":" << h_port << "\n";
        }

        // nmap
        if (h_port != 0) {
            port_tarama_takibi[s_ip].insert(h_port);
            if (port_tarama_takibi[s_ip].size() == PORT_TARAMA_LIMITI) {
                alarm_sayisi++;
                port_tarama_sayisi++;
                std::cout << "\n=============================================================\n";
                std::cout << "KRITIK ALARM: PORT TARAMASI (NMAP) TESPITI!\n";
                std::cout << "=============================================================\n";
                std::cout << " -> Saldirgan IP : " << s_ip << " -> KARA LISTEYE ALINDI!\n";
                kara_liste.insert(s_ip);
                if (log_dosyasi.is_open()) log_dosyasi << "[ALARM - PORT SCAN] " << s_ip << " port taramasi yapti! Kara listeye eklendi.\n";
            }
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

    std::cout << "\n[BPF] Uygulanacak filtreyi yazin (tcp, udp, arp, [hepsi icin bos birakin]): ";
    std::cin.ignore();
    std::getline(std::cin, filtre_girdisi);

    if (!filtre_girdisi.empty()) {
        struct bpf_program fcode;
        if (pcap_compile(adhandle, &fcode, filtre_girdisi.c_str(), 1, PCAP_NETMASK_UNKNOWN) >= 0) {
            pcap_setfilter(adhandle, &fcode);
            std::cout << "[+] BPF Filtresi Aktif: " << filtre_girdisi << "\n";
        }
    }

    std::cout << "Kac paket yakalandiktan sonra oturum sonlansin?: ";
    std::cin >> paket_limiti;

    std::cout << "\nAg dinleniyor...\n";
    pcap_loop(adhandle, paket_limiti, packet_handler, NULL);
    pcap_close(adhandle);
    if (log_dosyasi.is_open()) log_dosyasi.close();

    // oturum özeti
    std::cout << "\n================ OTURUM OZETI ================\n";
    std::cout << " Toplam Incelenen Paket  : " << toplam_paket << "\n";
    std::cout << " Analiz Edilen TCP/UDP   : " << tcp_sayisi << " / " << udp_sayisi << "\n";
    std::cout << " Tespit Edilen Port Scan : " << port_tarama_sayisi << "\n";
    std::cout << " Tespit Edilen SYN Flood : " << syn_flood_sayisi << "\n";
    std::cout << " Toplam Guvenlik Alarmi  : " << alarm_sayisi << "\n";
    std::cout << " Kara Listeden Engellenen: " << kara_liste_engeli << " paket\n";
    std::cout << "==============================================\n";

    std::cout << "Cikmak icin bir tusa basin...";
    std::cin.ignore();
    std::cin.get();

    return 0;
}