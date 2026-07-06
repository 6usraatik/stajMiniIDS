#include <iostream>
#include <pcap.h>


void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    static int paket_sayisi = 1;
    std::cout << "\n[" << paket_sayisi++ << ". Paket Yakalandi!]" << std::endl;
    std::cout << " -> Paket Boyutu: " << header->len << " bayt" << std::endl;
    std::cout << " -> Yakalanan Kisim: " << header->caplen << " bayt" << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i = 0;
    int secim;

    std::cout << "Ag adaptorleri taraniyor...\n\n";

    // 1. Cihazlarý Listele
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Cihazlar listelenirken hata olustu: " << errbuf << std::endl;
        return 1;
    }

    for (d = alldevs; d != NULL; d = d->next) {
        std::cout << ++i << ". " << d->name << std::endl;
        if (d->description)
            std::cout << "   -> " << d->description << std::endl;
        else
            std::cout << "   -> Tanim yok" << std::endl;
    }

    if (i == 0) {
        std::cout << "\nHicbir ag karti bulunamadi!\n";
        return 0;
    }

    // 2. Kullanýcýdan Dinlenecek Adaptörü Seçmesini Ýste
    std::cout << "\n----------------------------------------------------\n";
    std::cout << "Dinlemek istediginiz adaptörün numarasini girin (1-" << i << "): ";
    std::cin >> secim;

    if (secim < 1 || secim > i) {
        std::cout << "\nGecersiz bir numara girdiniz! Program sonlandiriliyor.\n";
        pcap_freealldevs(alldevs);
        return 0;
    }

    // Seçilen cihazýn pointerýný bul
    for (d = alldevs, i = 0; i < secim - 1; d = d->next, i++);

    std::cout << "\n[" << d->description << "] dinleniyor...\n";
    std::cout << "Paket yakalamayi test etmek icin bir web sayfasi acmayi deneyin!\n";

    // 3. Seçilen Adaptörü Dinlemek Ýçin Aç 
    pcap_t* adhandle;
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
        std::cerr << "\nAdaptor acilamadi. Npcap bu cihazda desteklenmiyor olabilir: " << d->name << std::endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    
    pcap_freealldevs(alldevs);

    // 4. Sonsuz Döngüye Gir ve Paket Yakala
    pcap_loop(adhandle, 10, packet_handler, NULL);

    std::cout << "\n10 adet paket basariyla yakalandi! Dinleme bitti.\n";
    pcap_close(adhandle);

    std::cout << "\nCikmak icin bir tusa basin...";
    std::cin.ignore();
    std::cin.get();

    return 0;
}