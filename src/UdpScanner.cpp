//
// Created by Adam Láníček on 2019-04-14.
//

#include "UdpScanner.h"

UdpScanner::UdpScanner(vector<int>& ports, ArgParser& args) : Scanner(ports, args) {}

State UdpScanner::scan_port(int port) {
    State state = NOT_CHECKED;

    int sock;
    static short *reading_ok;
    char packet[BUFSIZ];
    int one = 1;
    int header_size;
    pcap_t *pcap_handler;
    struct bpf_program filter;
    char filterExp[] = "icmp[icmptype] == 3 and icmp[icmpcode] == 3";
    char errorBuffer[PCAP_ERRBUF_SIZE];

    const u_char *pkt_data;
    struct pcap_pkthdr *header;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if ((sock = socket( (this->target->ai_addr->sa_family == AF_INET) ? AF_INET : AF_INET6, SOCK_RAW, IPPROTO_UDP)) == -1)
        Logger::error_exit("Error while creating socket!");

    if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, this->ifa->ifa_name, strlen(this->ifa->ifa_name)) == -1)
         Logger::error_exit("Error while connecting socket to interface!");

    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    if( sock == 0) {Logger::error_exit("Error while editing socket!");}

    if(pcap_lookupnet(this->ifa->ifa_name, &net, &mask, errorBuffer)==-1) { Logger::error_exit(errorBuffer); }

    if(this->target->ai_addr->sa_family == AF_INET)
    {
        header_size = sizeof(struct ip) + sizeof(struct udphdr);
        reading_ok = (short *)mmap(NULL, sizeof *reading_ok, PROT_READ | PROT_WRITE , MAP_SHARED | MAP_ANONYMOUS, -1, 0);

        pcap_handler = pcap_open_live(this->ifa->ifa_name, BUFSIZ, 0, 2000, errorBuffer);
        if(pcap_handler == NULL) { Logger::error_exit("Pcap open live error!"); }
        if(pcap_compile(pcap_handler, &filter, filterExp, 0,net) != 0) { Logger::error_exit("Pcap compile error!"); }
        if(pcap_setfilter(pcap_handler, &filter) != 0) { Logger::error_exit("Pcap set filter error!"); }

        this->create_udp_header(packet, port);
        if( sendto(sock, packet, header_size, 0, (struct sockaddr *)target->ai_addr, sizeof(struct sockaddr)) == -1)
            Logger::error_exit("Can't send a UDP packet!");

        *reading_ok = 0;
        int pid;
        if((pid = fork()) == 0)
        {
            *reading_ok = 0;
            if(pcap_next_ex(pcap_handler, &header, &pkt_data) == 1)
            {
                *reading_ok = 1;
            }
            else *reading_ok = 0;
            exit(0);
        }
        sleep(TIMEOUT);
        kill(pid, SIGKILL);
        if(*reading_ok)
        {
            state = CLOSED;
        } else {
            state = OPEN;
        }
    }
    else
        Logger::error_exit("Not IPV4 protocol");
    close(sock);
    return state;
}

void UdpScanner::create_udp_header(char *packet, int port) {
    struct pseudoUdpHdr pseudoUdp;
    int currentPort;

    int headerSize = sizeof(struct ip) + sizeof(struct udphdr);

    memset(packet, 0, headerSize);

    struct ip *ipHeader = (struct ip*)packet;
    struct udphdr *udpHeader = (struct udphdr*)(packet + sizeof(struct ip));

    ipHeader->ip_v = 4;
    ipHeader->ip_hl = 5;
    ipHeader->ip_tos = 16;
    ipHeader->ip_len = headerSize;
    ipHeader->ip_id = htons(54321);
    ipHeader->ip_off = htons(0x4000);
    ipHeader->ip_ttl = 64;
    ipHeader->ip_p = 17;
    ipHeader->ip_sum = 0;
    ipHeader->ip_dst = ((struct sockaddr_in *)(this->target->ai_addr))->sin_addr;
    ipHeader->ip_src = ((struct sockaddr_in *)(this->ifa->ifa_addr))->sin_addr;

    //udpHeader->uh_sport = htons(PORTNO);
    udpHeader->uh_sport = htons((rand() % 16385) + 49150);
    udpHeader->uh_ulen = htons(8);
    udpHeader->uh_sum = 0;

    currentPort = port;
    udpHeader->uh_dport = htons(currentPort);

    memset(&pseudoUdp, 0, sizeof(struct pseudoUdpHdr));
    memcpy(&(pseudoUdp.real_udp),udpHeader,sizeof(struct udphdr));
    memcpy(&(pseudoUdp.ip_src),&(ipHeader->ip_src), sizeof(struct in_addr));
    memcpy(&(pseudoUdp.ip_dst),&(ipHeader->ip_dst), sizeof(struct in_addr));
    pseudoUdp.protocol = 17;
    pseudoUdp.udp_len = htons(sizeof(struct udphdr));

    udpHeader->uh_sum = this->check_sum((unsigned short*)(&pseudoUdp), sizeof(struct pseudoUdpHdr));
    ipHeader->ip_sum = this->check_sum((short unsigned int*)(packet), headerSize);

    return;
}

