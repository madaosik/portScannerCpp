//
// Created by Adam Láníček on 2019-04-14.
//

#include "TcpScanner.h"

TcpScanner::TcpScanner(vector<int>& ports, ArgParser& args) : Scanner(ports, args) {}

State TcpScanner::scan_port(int port) {
    State state = NOT_CHECKED;
    int sock;
    int pid;
    int one = 1;
    int headerSize;
    string filter_exp;
    pcap_t *pcap_handler;
    struct bpf_program filter;
    const u_char *next_packet;
    struct pcap_pkthdr *header;
    bool repeat = true;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    static short *reading_ok;

    char packet[BUFSIZ];
    char errorBuffer[PCAP_ERRBUF_SIZE];

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock ==-1)
        Logger::error_exit("Error while creating socket!");

    if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, this->ifa->ifa_name, strlen(this->ifa->ifa_name))<0)
        Logger::error_exit("Error while connecting socket to interface!");

    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one) < 0))
        Logger::error_exit("Error while editing socket!");

    if (sock ==0) { Logger::error_exit("Error socket descriptor after editing socket!");}

    if(pcap_lookupnet(this->ifa->ifa_name, &net, &mask, errorBuffer)==-1)
        Logger::error_exit(string(errorBuffer));

    if(this->target->ai_addr->sa_family == AF_INET) {
        headerSize = sizeof(struct ip) + sizeof(struct tcphdr);

        reading_ok = (short *) mmap(NULL, sizeof *reading_ok, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        *reading_ok = 0;

        this->create_tcp_header(packet, port);

        while (repeat) {
            filter_exp = "tcp port " + to_string(port) + " and src host " + this->args.getHost();
            pcap_handler = pcap_open_live(this->ifa->ifa_name, BUFSIZ, 0, 2000, errorBuffer);
            if (pcap_handler == NULL) { Logger::error_exit("pcap_open_live() error!"); }

            // PCAP proceedings
            if (pcap_compile(pcap_handler, &filter, filter_exp.c_str(), 0, net) != 0)
                Logger::error_exit("Error in PCAP compilation!");
            if (pcap_setfilter(pcap_handler, &filter) != 0) { Logger::error_exit("Error in setting PCAP filter!"); }

            if ((sendto(sock, packet, headerSize, 0, (struct sockaddr *) target->ai_addr, sizeof(struct sockaddr))) == -1)
                Logger::error_exit("Error in sendto() function when sending TCP packet!");

            next_packet = NULL;
            if ((pid = fork()) == 0) {
                pcap_next_ex(pcap_handler, &header, &next_packet);

                u_char *flags = (u_char *) (next_packet + 47);

                if (*flags == 18) {
                    *reading_ok = 3;
                    state = OPEN;
                } else if (*flags == 18) {
                    *reading_ok = 2;
                    state = CLOSED;
                }
                break;
            }

            sleep(TIMEOUT);
            kill(pid, SIGKILL);
            if (*reading_ok == 0) {
                repeat = true;
                *reading_ok = 1;
            }
            else if (*reading_ok == 1)
            {
                state = FILTERED;
                repeat = false;
                *reading_ok = 0;
            }
            else
            {
                repeat = false;
                *reading_ok = 0;
            }
            pcap_close(pcap_handler);
        }
    }
    else
        Logger::error_exit("Program does not support IPv6 protocol.");

    close(sock);
    return state;
}

void TcpScanner::create_tcp_header(char *packet, int port) {
    struct pseudoTcpHdr pseudoTcp;

    int headerSize = sizeof(struct ip) + sizeof(struct tcphdr);
    memset(packet, 0, headerSize);

    struct ip *ipHeader = (struct ip*)(packet);
    struct tcphdr *tcpHeader = (struct tcphdr*)(packet + sizeof(struct ip));

    ipHeader->ip_v = 4;
    ipHeader->ip_hl = 5;
    ipHeader->ip_tos = 16;
    ipHeader->ip_len = headerSize;
    ipHeader->ip_off = htons(0x4000);
    ipHeader->ip_ttl = 64;
    ipHeader->ip_p = 6;
    ipHeader->ip_dst = ((struct sockaddr_in *)(this->target->ai_addr))->sin_addr;
    ipHeader->ip_src = ((struct sockaddr_in *)(this->ifa->ifa_addr))->sin_addr;

    tcpHeader->th_seq = 0x0;
    tcpHeader->th_ack = 0x0;
    tcpHeader->th_off = 5;
    tcpHeader->th_flags = TH_SYN;
    tcpHeader->th_win = htons(155);
    tcpHeader->th_sum = 0;
    tcpHeader->th_urp = 0;

    ipHeader->ip_id = htons(rand() % 65536);

    tcpHeader->th_sport = htons((rand() % 14354) + 47331);
    tcpHeader->th_dport = htons(port);

    memset(&pseudoTcp, 0, sizeof(struct pseudoTcpHdr));
    memcpy(&(pseudoTcp.real_tcp),tcpHeader,sizeof(struct tcphdr));
    memcpy(&(pseudoTcp.ip_src),&(ipHeader->ip_src), sizeof(struct in_addr));
    memcpy(&(pseudoTcp.ip_dst),&(ipHeader->ip_dst), sizeof(struct in_addr));
    pseudoTcp.protocol = IPPROTO_TCP;
    pseudoTcp.tcp_len = htons(sizeof(struct tcphdr));

    tcpHeader->th_sum = this->check_sum((unsigned short *)(&pseudoTcp), sizeof(struct pseudoTcpHdr));
    ipHeader->ip_sum = this->check_sum((unsigned short *)(packet), sizeof(struct ip));

    return;
}



