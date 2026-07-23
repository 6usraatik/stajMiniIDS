#include <iostream>
#include <pcap.h>
#include <map>
#include <set>
#include <string>
#include <fstream>
#include <thread>
#include <mutex>
#include <memory>
#pragma comment(lib, "ws2_32.lib")

int toplam_paket = 0;
int tcp_sayisi = 0;
int udp_sayisi = 0;
int icmp_sayisi = 0;
int arp_sayisi = 0;
int alarm_sayisi = 0;
int port_tarama_sayisi = 0;
int syn_flood_sayisi = 0;
int ping_of_death_sayisi = 0;
int kara_liste_engeli = 0;

std::mutex mtx;

struct ethernet_header { u_char hedef_mac[6]; u_char kaynak_mac[6]; u_short eth_type; };

struct arp_header {
    u_short donanim_tipi; u_short protokol_tipi; u_char donanim_len; u_char protokol_len;
    u_short islem_tipi; u_char gonderen_mac[6]; u_char gonderen_ip[4]; u_char hedef_mac[6]; u_char hedef_ip[4];
};

struct ip_header {
    u_char ver_ihl; u_char tos; u_short tlen;
    u_short id; u_short flags_fo;
    u_char ttl; u_char proto; u_short crc; u_char kaynak_ip[4]; u_char hedef_ip[4];
};

struct tcp_header {
    u_short kaynak_port; u_short hedef_port; u_int seq; u_int ack;
    u_char data_offset; u_char flags; u_short window; u_short checksum; u_short urgent_ptr;
};

struct udp_header { u_short kaynak_port; u_short hedef_port; };

struct icmp_header {
    u_char type; u_char code; u_short checksum; u_short id; u_short seq;
};

std::map<std::string, std::string> ip_mac_tablosu;
std::set<std::string> kara_liste;
std::map<std::string, std::set<u_short>> port_tarama_takibi;
std::map<std::string, int> syn_sayaci;

const int PORT_TARAMA_LIMITI = 4;
const int SYN_FLOOD_LIMITI = 5;
const int ICMP_MAX_GIVEN_SIZE = 1000;

std::ofstream log_dosyasi("C:\\Users\\HUAWEI\\Desktop\\ids_guvenlik_log.txt", std::ios::app);

void ip_engelle_ve_logla(const std::string& ip_adresi, const std::string& sebep) {
    std::lock_guard<std::mutex> lock(mtx);

    if (kara_liste.find(ip_adresi) != kara_liste.end()) return;

    kara_liste.insert(ip_adresi);

    if (log_dosyasi.is_open()) {
        log_dosyasi << "[ALARM - " << sebep << "] " << ip_adresi << " tespit edildi. Kara listeye alindi.\n";
    }

    std::string komut = "netsh advfirewall firewall add rule name=\"MiniIDS_Block_" + ip_adresi + "\" dir=in action=block remoteip=" + ip_adresi;
    system(komut.c_str());

    std::cout << "[IPS AKTIF] " << ip_adresi << " Windows Guvenlik Duvari seviyesinde FIZIKSEL OLARAK ENGELLENDI!\n";
}

std::string ip_to_string(const u_char* ip) {
    return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." + std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}
std::string mac_to_string(const u_char* mac) {
    char buffer[18];
    sprintf_s(buffer, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buffer);
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    {
        std::lock_guard<std::mutex> lock(mtx);
        toplam_paket++;
    }

    std::unique_ptr<ethernet_header> eth(new ethernet_header);
    std::memcpy(eth.get(), pkt_data, sizeof(ethernet_header));

    u_short protokol = ntohs(eth->eth_type);

    if (protokol == 0x0806) {
        {
            std::lock_guard<std::mutex> lock(mtx);
            arp_sayisi++;
        }
        std::unique_ptr<arp_header> arp(new arp_header);
        std::memcpy(arp.get(), pkt_data + 14, sizeof(arp_header));

        std::string gonderen_ip = ip_to_string(arp->gonderen_ip);
        std::string gonderen_mac = mac_to_string(arp->gonderen_mac);

        std::lock_guard<std::mutex> lock(mtx);
        if (ip_mac_tablosu.find(gonderen_ip) == ip_mac_tablosu.end()) {
            ip_mac_tablosu[gonderen_ip] = gonderen_mac;
        }
        else {
            std::string bilinen_mac = ip_mac_tablosu[gonderen_ip];
            if (bilinen_mac != gonderen_mac) {
                alarm_sayisi++;
                std::cout << "\nKRITIK ALARM: ARP SPOOFING! -> IP: " << gonderen_ip << "\n";
                mtx.unlock();
                ip_engelle_ve_logla(gonderen_ip, "ARP SPOOFING");
                mtx.lock();
            }
        }
    }
    else if (protokol == 0x0800) {
        std::unique_ptr<ip_header> ip(new ip_header);
        std::memcpy(ip.get(), pkt_data + 14, sizeof(ip_header));

        int ip_baslik_uzunlugu = (ip->ver_ihl & 0x0F) * 4;
        u_short toplam_ip_boyutu = ntohs(ip->tlen);

        std::string s_ip = ip_to_string(ip->kaynak_ip);
        std::string h_ip = ip_to_string(ip->hedef_ip);

        {
            std::lock_guard<std::mutex> lock(mtx);
            if (kara_liste.find(s_ip) != kara_liste.end()) {
                kara_liste_engeli++;
                return;
            }
        }

        u_short h_port = 0;

        if (ip->proto == 6) {
            {
                std::lock_guard<std::mutex> lock(mtx);
                tcp_sayisi++;
            }
            std::unique_ptr<tcp_header> tcp(new tcp_header);
            std::memcpy(tcp.get(), pkt_data + 14 + ip_baslik_uzunlugu, sizeof(tcp_header));

            h_port = ntohs(tcp->hedef_port);

            if (tcp->flags & 0x02) {
                std::lock_guard<std::mutex> lock(mtx);
                syn_sayaci[s_ip]++;
                if (syn_sayaci[s_ip] == SYN_FLOOD_LIMITI) {
                    alarm_sayisi++; syn_flood_sayisi++;
                    std::cout << "\n=============================================================\n";
                    std::cout << " KRITIK ALARM: SYN FLOOD (DoS/DDoS) TESPITI!\n";
                    std::cout << "=============================================================\n";
                    std::cout << " -> Saldirgan IP : " << s_ip << "\n";
                    mtx.unlock();
                    ip_engelle_ve_logla(s_ip, "SYN FLOOD");
                    mtx.lock();
                }
            }
        }
        else if (ip->proto == 17) {
            {
                std::lock_guard<std::mutex> lock(mtx);
                udp_sayisi++;
            }
            std::unique_ptr<udp_header> udp(new udp_header);
            std::memcpy(udp.get(), pkt_data + 14 + ip_baslik_uzunlugu, sizeof(udp_header));

            h_port = ntohs(udp->hedef_port);

            if (h_port == 53) {
                int udp_baslik_uzunlugu = 8;
                int veri_baslangici = 14 + ip_baslik_uzunlugu + udp_baslik_uzunlugu;
                int veri_uzunlugu = toplam_ip_boyutu - ip_baslik_uzunlugu - udp_baslik_uzunlugu;

                if (veri_uzunlugu > 0) {
                    const u_char* dns_verisi = pkt_data + veri_baslangici;
                    std::string dns_string = "";
                    int anlamsiz_karakter_serisi = 0;

                    for (int j = 0; j < veri_uzunlugu; j++) {
                        unsigned char c = (unsigned char)dns_verisi[j];

                        if (std::isalnum(c) || c == '-' || c == '.') {
                            dns_string += c;
                            anlamsiz_karakter_serisi++;
                        }
                        else {
                            anlamsiz_karakter_serisi = 0;
                        }

                        if (anlamsiz_karakter_serisi > 50) {
                            std::lock_guard<std::mutex> lock(mtx);
                            alarm_sayisi++;
                            std::cout << "\n=============================================================\n";
                            std::cout << " KRITIK ALARM: DNS TUNELLEME TESPITI!\n";
                            std::cout << "=============================================================\n";
                            std::cout << " -> Saldirgan IP : " << s_ip << "\n";
                            mtx.unlock();
                            ip_engelle_ve_logla(s_ip, "DNS TUNNELING");
                            mtx.lock();
                            break;
                        }
                    }
                }
            }
        }
        else if (ip->proto == 1) {
            {
                std::lock_guard<std::mutex> lock(mtx);
                icmp_sayisi++;
            }
            if (toplam_ip_boyutu > ICMP_MAX_GIVEN_SIZE) {
                std::lock_guard<std::mutex> lock(mtx);
                alarm_sayisi++; ping_of_death_sayisi++;
                std::cout << "\n=============================================================\n";
                std::cout << " KRITIK ALARM: PING OF DEATH TESPITI!\n";
                std::cout << "=============================================================\n";
                std::cout << " -> Saldirgan IP : " << s_ip << "\n";
                mtx.unlock();
                ip_engelle_ve_logla(s_ip, "PING OF DEATH");
                mtx.lock();
            }
        }

        if (h_port != 0 && ip->proto == 6) {
            std::lock_guard<std::mutex> lock(mtx);
            port_tarama_takibi[s_ip].insert(h_port);
            if (port_tarama_takibi[s_ip].size() == PORT_TARAMA_LIMITI) {
                alarm_sayisi++; port_tarama_sayisi++;
                std::cout << "\n=============================================================\n";
                std::cout << " KRITIK ALARM: NMAP TESPITI!\n";
                std::cout << "=============================================================\n";
                std::cout << " -> Saldirgan IP : " << s_ip << "\n";
                mtx.unlock();
                ip_engelle_ve_logla(s_ip, "PORT SCAN");
                mtx.lock();
            }
        }
    }
}

void packet_listener_thread(pcap_t* adhandle, int packet_limit) {
    std::cout << "\n[THREAD] Ag dinleme arka plan is parcacigi baslatildi.\n";
    pcap_loop(adhandle, packet_limit, packet_handler, NULL);
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

    std::cout << "\n[BPF] Uygulanacak filtreyi yazin (Hepsi icin bos birakin): ";
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

    std::cout << "\n[SISTEM] Modern bellek yonetimi (Smart Pointers & RAII) devreye aliniyor...\n";

    std::thread listener_thread(packet_listener_thread, adhandle, paket_limiti);

    std::cout << "[MAIN] Ana is parcacigi bosta, arka planda ag guvenle izleniyor...\n";

    listener_thread.join();

    pcap_close(adhandle);
    if (log_dosyasi.is_open()) log_dosyasi.close();

    std::cout << "\n================ OTURUM OZETI ================\n";
    std::cout << " Toplam Incelenen Paket  : " << toplam_paket << "\n";
    std::cout << " Analiz Edilen TCP/UDP   : " << tcp_sayisi << " / " << udp_sayisi << "\n";
    std::cout << " Analiz Edilen ICMP      : " << icmp_sayisi << "\n";
    std::cout << " Analiz Edilen ARP       : " << arp_sayisi << "\n";
    std::cout << " Tespit Edilen Port Scan : " << port_tarama_sayisi << "\n";
    std::cout << " Tespit Edilen SYN Flood : " << syn_flood_sayisi << "\n";
    std::cout << " Yakalanan Ping of Death : " << ping_of_death_sayisi << "\n";
    std::cout << " Toplam Guvenlik Alarmi  : " << alarm_sayisi << "\n";
    std::cout << " Kara Listeden Engellenen: " << kara_liste_engeli << " paket\n";
    std::cout << "==============================================\n";

    std::cout << "Cikmak icin bir tusa basin...";
    std::cin.ignore();
    std::cin.get();

    return 0;
}