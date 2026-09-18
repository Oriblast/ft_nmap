#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <pthread.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025 // Maximum length of a hostname 
#endif

#ifndef NI_NUMERICHOST
#define NI_NUMERICHOST 1
#endif

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_length;
};


struct ethernet_header {
    uint8_t dest[6];   // MAC destination
    uint8_t src[6];    // MAC source
    uint16_t ethertype; // arp = 0x0806, ipv4 = 0x0800
} __attribute__((packed));

struct interphase {
    char *name;
    char *ip;
    char *mac;
};

typedef struct s_opts
{ //  chaque option est un int qui vaut 1 si l'option est activée, 0 sinon

    int h; // help
    char *ip; 
    char *scan;
    int file; // File name containing IP addresses to scan,
    int speedUp;
    int port;
}   t_opts;

struct packet {
    struct iphdr ip;
    struct tcphdr tcp;
};

struct udp_packet {
    struct iphdr ip;
    struct udphdr udp;
};

typedef struct nmap {
    struct interphase reseau;
    t_opts opts;
    struct in_addr tip; // target ip
    struct in_addr sip; // source ip

    char nb1[7];
    char nb2[7];
    int onePort;
    struct tcphdr **tcp;
    struct iphdr **ip;
    struct udphdr *udp;
    struct icmphdr *icmp;
    long **time;

} Nmap;
    

Nmap nmap;

/*
    *@brief: easy if c it's between 0 and 9 c - '0' and if c is between a and f c - 'a' + 10
    *@param: c: char to convert
    *@return: int value of the char c 
*/

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return (c - '0');
    if (c >= 'a' && c <= 'f')
        return (c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return (c - 'A' + 10);
    return (-1);
}

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

char *find_ip(char *hostname)
{
    struct addrinfo hints, *res, *p;
    static char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // IPv4 + IPv6

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        perror("getaddrinfo");
        exit(1);
    }

    for(p = res; p != NULL; p = p->ai_next) {
        void *addr;

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else {
            continue;
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        break;
    }

    freeaddrinfo(res);
    return ipstr;
}

char *find_dns(char *ip)
{
    struct sockaddr_in sa;
    char host[1024];

    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip);
        return NULL;
    }

    int ret = getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                          host, sizeof(host),
                          NULL, 0,
                          0);
    if (ret != 0) {
        fprintf(stderr, "getnameinfo: %s\n", gai_strerror(ret));
        return NULL;
    }

    return strdup(host); // caller must free
}


/*
* @brief: get network interface information, eth0 interess me 
* @param: reseau: struct interphase to fill with network interface information
* @return: 0 on success, 1 on error
*/

int getInterfaceReseau(struct interphase *reseau)
{
    struct ifaddrs *ifaddr, *ifa;
    char ip[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        int family = ifa->ifa_addr->sa_family;

        if (family == AF_INET) {
            // IPv4 address
            getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                        ip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if(strcmp(ifa->ifa_name, "eth0") == 0) {
                reseau->name = strdup(ifa->ifa_name);
                reseau->ip = strdup(ip);
            }
            //printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, ip);
        }
        if (ifa->ifa_addr->sa_family == AF_PACKET)
        {
            struct sockaddr_ll *s =
                (struct sockaddr_ll *)ifa->ifa_addr;
            if(strcmp(ifa->ifa_name, "eth0") == 0) {
                char mac[18];
                snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                         s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
                         s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
                reseau->mac = strdup(mac);
            }
            /*printf("Interface: %s\tMAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   ifa->ifa_name,
                   s->sll_addr[0],
                   s->sll_addr[1],
                   s->sll_addr[2],
                   s->sll_addr[3],
                   s->sll_addr[4],
                   s->sll_addr[5]);*/
        }

    }

    freeifaddrs(ifaddr);
    return 0;
}

void scanudp(int port)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

    if (sock < 0)
    {
        perror("socket");
        return;
    }

    struct udp_packet pkt;
    struct pseudo_header psh;
    struct bpf_program fp;

    struct udphdr *udp = NULL;
    struct iphdr *ip = NULL;
    struct icmphdr *icmp = NULL;

    memset(&pkt, 0, sizeof(pkt));


    pkt.ip.version = 4;
    pkt.ip.ihl = 5;
    pkt.ip.tos = 0;
    pkt.ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
    pkt.ip.protocol = IPPROTO_UDP;
    pkt.ip.saddr = nmap.sip.s_addr;
    pkt.ip.daddr = nmap.tip.s_addr;
    pkt.ip.id = htons(1234);
    pkt.ip.frag_off = 0;
    pkt.ip.ttl = 64;
    pkt.ip.check = 0;

    pkt.ip.check = checksum(&pkt.ip, sizeof(struct iphdr));

    pkt.udp.source = htons(4242);
    pkt.udp.dest = htons(port);
    pkt.udp.len = htons(sizeof(struct udphdr));
    pkt.udp.check = 0;

    // check sum

    unsigned char buf[
        sizeof(struct pseudo_header) +
        sizeof(struct udphdr)
    ];

    memset(&psh, 0, sizeof(psh));

    psh.source_address = nmap.sip.s_addr;
    psh.dest_address = nmap.tip.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.tcp_length = htons(sizeof(struct udphdr));

    memcpy(buf, &psh, sizeof(psh));
    memcpy(buf + sizeof(psh), &pkt.udp, sizeof(struct udphdr));

    pkt.udp.check = checksum(buf, sizeof(buf));


    int one = 1;

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                   &one, sizeof(one)) < 0)
    {
        perror("setsockopt");
        close(sock);
        return;
    }


    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(
        nmap.reseau.name,
        65535,
        1,
        100,
        errbuf
    );

    if (handle == NULL)
    {
        fprintf(stderr,
                "Could not open device %s: %s\n",
                nmap.reseau.name,
                errbuf);
        close(sock);
        return;
    }

    // filtre udp and icmp

    char filter_exp[256];

    snprintf(
        filter_exp,
        sizeof(filter_exp),
        "(udp and src host %s and src port %d) "
        "or (icmp and src host %s)",
        inet_ntoa(nmap.tip),
        port,
        inet_ntoa(nmap.tip)
    );

    if (pcap_compile(
        handle,
        &fp,
        filter_exp,
        0,
        PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr,
                "pcap_compile: %s\n",
                pcap_geterr(handle));

        pcap_close(handle);
        close(sock);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr,
                "pcap_setfilter: %s\n",
                pcap_geterr(handle));

        pcap_freecode(&fp);
        pcap_close(handle);
        close(sock);
        return;
    }

    pcap_freecode(&fp);

    
    if (pcap_setnonblock(handle, 1, errbuf) == -1)
    {
        fprintf(stderr,
                "pcap_setnonblock: %s\n",
                errbuf);

        pcap_close(handle);
        close(sock);
        return;
    }
    // send

    struct sockaddr_in dest_addr;

    memset(&dest_addr, 0, sizeof(dest_addr));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = nmap.tip;

    ssize_t sent = sendto(
        sock,
        &pkt,
        sizeof(pkt),
        0,
        (struct sockaddr *)&dest_addr,
        sizeof(dest_addr)
    );

    if (sent < 0)
    {
        perror("sendto");
        pcap_close(handle);
        close(sock);
        return;
    }

    printf("Waiting for response...\n");


    struct timeval start;
    struct timeval now;
    long elapsed_ms;
    gettimeofday(&start, NULL);

    while (1)
    {
        gettimeofday(&now, NULL);

        elapsed_ms =
            (now.tv_sec - start.tv_sec) * 1000L +
            (now.tv_usec - start.tv_usec) / 1000L;

        if (elapsed_ms >= 1000)
        {
            printf("UDP port %d is OPEN|FILTERED\n", port);
            break;
        }

        struct pcap_pkthdr *header;
        const u_char *packet;

        int ret = pcap_next_ex(
            handle,
            &header,
            &packet
        );

        if (ret == -1)
        {
            fprintf(stderr,
                    "pcap_next_ex: %s\n",
                    pcap_geterr(handle));
            break;
        }

        if (ret == 0)
        {
            usleep(10000);
            continue;
        }

        if (header->caplen < sizeof(struct ethernet_header))
            continue;

        struct ethernet_header *eth =
            (struct ethernet_header *)packet;

        if (ntohs(eth->ethertype) != ETH_P_IP)
            continue;

        if (header->caplen <
            sizeof(struct ethernet_header) +
            sizeof(struct iphdr))
        {
            continue;
        }

        ip = (struct iphdr *)
            (packet + sizeof(struct ethernet_header));

        if (ip->version != 4)
            continue;

        if (ip->ihl < 5)
            continue;

        size_t ip_len = ip->ihl * 4;

        if (header->caplen <
            sizeof(struct ethernet_header) +
            ip_len)
        {
            continue;
        }

        // rep udp

        if (ip->protocol == IPPROTO_UDP)
        {
            if (header->caplen <
                sizeof(struct ethernet_header) +
                ip_len +
                sizeof(struct udphdr))
            {
                continue;
            }

            udp = (struct udphdr *)
                ((unsigned char *)ip + ip_len);

            
            if (ntohs(udp->source) != port)
                continue;

            if (ntohs(udp->dest) != 4242)
                continue;

            printf("UDP port %d is OPEN\n", port);

            break;
        }

        // icmp rrep

        if (ip->protocol == IPPROTO_ICMP)
        {
            if (header->caplen <
                sizeof(struct ethernet_header) +
                ip_len +
                sizeof(struct icmphdr))
            {
                continue;
            }

            icmp = (struct icmphdr *)
                ((unsigned char *)ip + ip_len);

            /*
             * On ne s'intéresse ici qu'au
             * ICMP Destination Unreachable.
             */
            if (icmp->type != ICMP_DEST_UNREACH)
                continue;

            if (icmp->code != ICMP_PORT_UNREACH)
                continue;

            /*
             * Un paquet ICMP error contient
             * l'ancien paquet IP + les premiers
             * octets du paquet UDP.
             */

            unsigned char *inner =
                (unsigned char *)icmp +
                sizeof(struct icmphdr);

            if (header->caplen <
                sizeof(struct ethernet_header) +
                ip_len +
                sizeof(struct icmphdr) +
                sizeof(struct iphdr))
            {
                continue;
            }

            struct iphdr *inner_ip =
                (struct iphdr *)inner;

            if (inner_ip->version != 4)
                continue;

            if (inner_ip->ihl < 5)
                continue;

            size_t inner_ip_len =
                inner_ip->ihl * 4;

            if (inner_ip->protocol != IPPROTO_UDP)
                continue;

            if (inner_ip->saddr != nmap.sip.s_addr)
                continue;

            if (inner_ip->daddr != nmap.tip.s_addr)
                continue;

            if (header->caplen <
                sizeof(struct ethernet_header) +
                ip_len +
                sizeof(struct icmphdr) +
                inner_ip_len +
                sizeof(struct udphdr))
            {
                continue;
            }

            struct udphdr *inner_udp =
                (struct udphdr *)
                ((unsigned char *)inner_ip +
                 inner_ip_len);

            if (ntohs(inner_udp->source) != 4242)
                continue;

            if (ntohs(inner_udp->dest) != port)
                continue;

            printf("UDP port %d is CLOSED\n", port);

            break;
        }
    }
    //nmap.time[port - atoi(nmap.nb1)][5] = elapsed_ms;
   // memcpy(&nmap.udp[port - atoi(nmap.nb1)], udp, sizeof(struct udphdr));
    //memcpy(&nmap.icmp[port - atoi(nmap.nb1)], icmp, sizeof(struct icmphdr));
    pcap_close(handle);
    close(sock);
}

void scantcp(int port, int scan) 
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    struct packet pkt;
    // int sock2 = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    struct pseudo_header psh;
    memset(&pkt, 0, sizeof(pkt));
    struct bpf_program fp;
    struct tcphdr *tcp;
    struct iphdr *ip;   
    
    
// configure IP
    pkt.ip.version = 4; // IPv4
    pkt.ip.ihl = 5; // header length
    pkt.ip.tos = 0;
    pkt.ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    pkt.ip.protocol = IPPROTO_TCP;
    pkt.ip.saddr = nmap.sip.s_addr;
    pkt.ip.daddr = nmap.tip.s_addr;
    pkt.ip.id = htons(1234);
    pkt.ip.frag_off = 0;
    pkt.ip.ttl = 64;
    pkt.ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    pkt.ip.check = checksum(&pkt.ip, sizeof(struct iphdr));

// configure tcp 
    pkt.tcp.source = htons(4242); // source port
   // nmap.pkt.tcp.dest = htons(atoi(nmap.opts.port)); // destination port
    pkt.tcp.dest = htons(port);
    pkt.tcp.seq = htonl(0);
    pkt.tcp.ack_seq = htonl(0);
    pkt.tcp.doff = 5; // data offset
    pkt.tcp.window = htons(5840); // maximum allowed window size
    pkt.tcp.check = 0; // checksum (will be calculated later
    pkt.tcp.urg_ptr = 0;
    
    if (scan == 1)
        pkt.tcp.syn = 1; // SYN flag
    else if (scan == 2)
        pkt.tcp.fin = 1; // FIN flag

    else if (scan == 4)
    {
        pkt.tcp.fin = 1; // FIN flag
        pkt.tcp.psh = 1; // PSH flag
        pkt.tcp.urg = 1; // URG flag
    }
    else if (scan == 5)
        pkt.tcp.ack = 1; // ACK flag
    else if (scan == 6)
        pkt.tcp.rst = 1; // RST flag


// config pseudo header
    unsigned char buf[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];

    memset(&psh, 0, sizeof(psh));

    psh.source_address = nmap.sip.s_addr;
    psh.dest_address   = nmap.tip.s_addr;
    psh.placeholder    = 0;
    psh.protocol       = IPPROTO_TCP;
    psh.tcp_length     = htons(sizeof(struct tcphdr));

    memcpy(buf, &psh, sizeof(psh));
    memcpy(buf + sizeof(psh), &pkt.tcp, sizeof(struct tcphdr));
    pkt.tcp.check = checksum(&buf, sizeof(buf));

    int one = 1;

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                &one, sizeof(one)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_live(
        nmap.reseau.name,
        65535, // snaplen
        1,  // promisc
        1000, // timeout in ms
        errbuf
    );

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", nmap.reseau.name, errbuf);
        exit(EXIT_FAILURE);
    }

    char filter_exp[256];

    snprintf(filter_exp, sizeof(filter_exp),
        "tcp and src host %s and src port %d",
        inet_ntoa(nmap.tip),
    ntohs(pkt.tcp.dest));
    pcap_compile(
        handle,
        &fp,
        filter_exp,
        0,
        PCAP_NETMASK_UNKNOWN // mask no correctly connection
    );

    pcap_setfilter(handle, &fp);

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = nmap.tip;

    ssize_t sent =  sendto(sock, &pkt, sizeof(pkt), 0,
           (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    
    if (sent < 0) {
        printf("Error sending packet: %s\n", strerror(errno));
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int ret;
    printf("Waiting for response...\n");
    while (1)
    {
        ret = pcap_next_ex(handle, &header, &packet);

        if (ret == -1)
        {
            fprintf(stderr, "pcap_next_ex: %s\n",
                    pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

        if (ret == 0)
        {
            printf("Timeout\n");
            break;
        }

        printf("Packet captured: %u bytes\n", header->caplen);

        if (header->caplen < sizeof(struct ethernet_header))
            continue;

        struct ethernet_header *eth =
            (struct ethernet_header *)packet;

        if (ntohs(eth->ethertype) != ETH_P_IP)
            continue;

        if (header->caplen <
            sizeof(struct ethernet_header) + sizeof(struct iphdr))
            continue;

        ip =
            (struct iphdr *)(packet + sizeof(struct ethernet_header));

        printf("IP version = %u\n", ip->version);
        printf("IP header length = %u bytes\n", ip->ihl * 4);
        printf("IP protocol = %u\n", ip->protocol);

        if (ip->protocol != IPPROTO_TCP)
            continue;

        if (header->caplen <
            sizeof(struct ethernet_header)
            + ip->ihl * 4
            + sizeof(struct tcphdr))
            continue;

        tcp =
            (struct tcphdr *)((unsigned char *)ip + ip->ihl * 4);

        struct in_addr packet_src;
        struct in_addr packet_dst;

        packet_src.s_addr = ip->saddr;
        packet_dst.s_addr = ip->daddr;

        printf("packet src = %s\n", inet_ntoa(packet_src));
        printf("packet dst = %s\n", inet_ntoa(packet_dst));

        printf("TCP src port = %u\n", ntohs(tcp->source));
        printf("TCP dst port = %u\n", ntohs(tcp->dest));

        printf("SYN = %u\n", tcp->syn);
        printf("ACK = %u\n", tcp->ack);
        printf("RST = %u\n", tcp->rst);
        

        break;
    }
    int index = port - atoi(nmap.nb1);
    printf("after while\n");
    //nmap.time[index][scan - 1] = ret;
    printf("Time recorded: %ld\n", nmap.time[index][scan - 1]);
   // memcpy(&nmap.tcp[index][scan - 1], tcp, sizeof(struct tcphdr));
    //memcpy(&nmap.ip[index][scan - 1], ip, sizeof(struct iphdr));
    pcap_close(handle);
    close(sock);
}

void * workers(void *arg)
{
    int *port = (int*) arg;
    if (nmap.opts.scan == NULL)
    {
        printf("all scn\n");
        scantcp(*port + atoi(nmap.nb1), 1);
        scantcp(*port + atoi(nmap.nb1), 2);
        scantcp(*port + atoi(nmap.nb1), 3);
        scantcp(*port + atoi(nmap.nb1), 4);
        scantcp(*port + atoi(nmap.nb1), 5);
        scanudp(*port + atoi(nmap.nb1));
    }
    else if (strcmp(nmap.opts.scan, "SYN") == 0)
    {
        scantcp(*port + atoi(nmap.nb1), 1);
    }
    else if (strcmp(nmap.opts.scan, "FIN") == 0)
    {
        scantcp(*port + atoi(nmap.nb1), 2);
    }
    else if (strcmp(nmap.opts.scan, "NUL") == 0)
    {
        scantcp(*port + atoi(nmap.nb1), 3);
    }
    else if (strcmp(nmap.opts.scan, "XMAS") == 0)
    {
        scantcp(*port + atoi(nmap.nb1), 4);
    }
    else if (strcmp(nmap.opts.scan, "ACK") == 0)
    {
        scantcp(*port + atoi(nmap.nb1), 5);
    }
    else if (strcmp(nmap.opts.scan, "UDP") == 0)
    {
        scanudp(*port + atoi(nmap.nb1));
    }
    return NULL;
}

void scanManager()
{
    pthread_t threads[250];

  //  nmap.udp = malloc(sizeof(struct udphdr) * nmap.opts.port);
    //nmap.icmp = malloc(sizeof(struct icmphdr) * nmap.opts.port);
   // Nmap nm[250];
    nmap.udp = malloc(sizeof(struct udphdr) * nmap.opts.port);
    nmap.icmp = malloc(sizeof(struct icmphdr) * nmap.opts.port);
    int j = 0;
    if (nmap.onePort == 0)
    {
        for (int i = 0; i < nmap.opts.port; i++)
        {
                nmap.tcp[i - atoi(nmap.nb1)] = malloc(sizeof(struct tcphdr) * 6);
                nmap.ip[i - atoi(nmap.nb1)] = malloc(sizeof(struct iphdr) * 6 );
                nmap.time[i - atoi(nmap.nb1)] = malloc(sizeof(long) * 6);
            if (j == 250)
            {
                j = 0;
                for (int k = 0; k < nmap.opts.speedUp; k++)
                {
                    pthread_join(threads[k], NULL);
                }
            }
        }
    }
    else 
    {
        nmap.tcp[0] = malloc(sizeof(struct tcphdr) * 6);
        nmap.ip[0] = malloc(sizeof(struct iphdr) * 6 );
        nmap.time[0] = malloc(sizeof(long) * 6);
        printf("one = %d", nmap.onePort - atoi(nmap.nb1));
        int p = 0;
        workers(&p);
    }
}

void print_help(void)
{
    printf("ft_nmap [OPTIONS]\n");
    printf("--help Print this help screen\n");
    printf("--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
    printf("--ip ip address to scan\n");
    printf("--file File name containing IP addresses to scan\n");
    printf("--speedup [250 max] number of parallel threads\n");
    printf("--scan SYN/NULL/FIN/XMAS/ACK/UDP\n");
}


int main(int argc, char **argv)
{

    if (geteuid() != 0) {
        fprintf(stderr, "Erreur: ce programme doit être exécuté en root.\n");
        return 1;
    }
    nmap.opts.speedUp = 0;
    nmap.onePort = -1;
    nmap.opts.scan = NULL;
    if (argc < 2) {
        print_help();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        print_help();
        return 0;
    }

    if (argc > 1)
    {
        for(int i = 1; i < argc; i++)
        {
            if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc)
            {
                nmap.opts.ip = argv[i + 1];
                if(!inet_pton(AF_INET, nmap.opts.ip, &nmap.tip))
                {
                    fprintf(stderr, "Invalid IP address: %s\n", nmap.opts.ip);
                    return 1;
                }
                i++;
            }
            else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc)
            {
                nmap.onePort = 0;
                int index = 0;
                if (argv[i+1][index] == '-')
                {
                    printf("Port: bad port arg\n;");
                    return -1;
                }
                while (argv[i+1][index] != '-' && argv[i+1][index] != '\0')
                {
                    nmap.nb1[index] = argv[i+1][index];
                    index++;
                }
                nmap.nb1[index] = 0;
                if (argv[i+1][index] == '\0')
                {
                    nmap.opts.port = atoi(nmap.nb1);
                    nmap.onePort = nmap.opts.port;
                    nmap.ip = malloc(sizeof(struct iphdr*) * 1);
                    nmap.tcp = malloc(sizeof(struct tcphdr*) * 1);
                    nmap.time = malloc(sizeof(long*) * 1);
                    break;
                }
                index++; 
                int i1 = 0;

                while (argv[i+1][index] != '\0')
                {
                    nmap.nb2[i1] = argv[i+1][index];
                    index++;
                    i1++;
                }

                nmap.nb2[i1] = 0;
                nmap.opts.port = atoi(nmap.nb2) - atoi(nmap.nb1);

                if (nmap.opts.port < 0)
                {
                    printf("Port: bad port arg\n;");
                    return -1;
                }

                if (nmap.opts.port > 1024)
                {
                    printf("Port: bad port arg\n;");
                    return -1;
                }

                nmap.ip = malloc(sizeof(struct iphdr*) * nmap.opts.port);
                nmap.tcp = malloc(sizeof(struct tcphdr*) * nmap.opts.port);
                nmap.time = malloc(sizeof(long*) * nmap.opts.port);
                i++;
            }
            else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc)
            {
                nmap.opts.file = 1;
                nmap.opts.ip = argv[i + 1];
                i++;
            }
            else if (strcmp(argv[i], "--speedup") == 0 && i + 1 < argc)
            {
                nmap.opts.speedUp = atoi(argv[i + 1]);
                if (nmap.opts.speedUp > 250)
                    nmap.opts.speedUp = 250;
                if (nmap.opts.speedUp < 0)
                {
                    printf("speedup: bad arg\n");
                    return -1;
                }
                i++;
            }
            else if (strcmp(argv[i], "--scan") == 0 && i + 1 < argc)
            {
                if (strcmp(argv[i + 1], "SYN") == 0 || strcmp(argv[i + 1], "NUL") == 0 || 
                strcmp(argv[i + 1], "FIN") == 0 || strcmp(argv[i + 1], "XMAS") == 0 || 
                    strcmp(argv[i + 1], "ACK") == 0 || strcmp(argv[i + 1], "UDP") == 0)
                    nmap.opts.scan = argv[i + 1];
                else
                {
                    printf("scan: bad arg\n");
                    return -1;
                }
                nmap.opts.scan = argv[i + 1];
                
                i++;
            }
            else if (strcmp(argv[1], "--help") == 0) {
                print_help();
                return 0;
            }
        }
    }

    getInterfaceReseau(&nmap.reseau);
    inet_pton(AF_INET, nmap.reseau.ip, &nmap.sip); // source ip
    if (nmap.onePort == -1)
        nmap.onePort = 42;
    scanManager();
    hex_value('F');
    free(nmap.ip);
    free(nmap.tcp);
    free(nmap.udp);
    free(nmap.icmp);
}