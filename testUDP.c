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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <pcap.h>
#include <errno.h>

#define SOURCE_PORT 4242
#define DEST_PORT   42

struct pseudo_header
{
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t udp_length;
};

struct ethernet_header
{
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t ethertype;
} __attribute__((packed));

struct udp_packet
{
    struct iphdr ip;
    struct udphdr udp;
};

struct interphase
{
    char *name;
    char *ip;
    char *mac;
};

typedef struct s_nmap
{
    struct interphase reseau;
    struct udp_packet pkt;
    struct in_addr tip;
    struct in_addr sip;
    struct bpf_program fp;
} Nmap;

Nmap nmap;

/*
 * Calcul du checksum Internet.
 */
unsigned short checksum(unsigned short *buffer, int size)
{
    unsigned long sum = 0;

    while (size > 1)
    {
        sum += *buffer++;
        size -= 2;
    }

    if (size == 1)
        sum += *(unsigned char *)buffer;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

/*
 * Récupère la première interface réseau UP qui possède une adresse IPv4.
 */
int getInterfaceReseau(struct interphase *interface)
{
    struct ifaddrs *ifaddr;
    struct ifaddrs *ifa;
    static char name[IFNAMSIZ];
    static char ip[INET_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;

        if (!(ifa->ifa_flags & IFF_UP))
            continue;

        if (ifa->ifa_flags & IFF_LOOPBACK)
            continue;

        struct sockaddr_in *addr =
            (struct sockaddr_in *)ifa->ifa_addr;

        if (inet_ntop(AF_INET, &addr->sin_addr,
                      ip, sizeof(ip)) == NULL)
            continue;

        strncpy(name, ifa->ifa_name, IFNAMSIZ - 1);
        name[IFNAMSIZ - 1] = '\0';

        interface->name = name;
        interface->ip = ip;
        interface->mac = NULL;

        freeifaddrs(ifaddr);
        return 0;
    }

    freeifaddrs(ifaddr);
    return -1;
}

int main(int argc, char **argv)
{
    int sock;
    int one = 1;
    struct sockaddr_in dest_addr;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    char filter_exp[256];
    struct bpf_program fp;

    const unsigned char *packet;
    struct pcap_pkthdr *header;

    int ret;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <IPv4>\n", argv[0]);
        return 1;
    }

    /*
     * ------------------------------------------------------------
     * 1. Socket RAW UDP
     * ------------------------------------------------------------
     */

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0)
    {
        perror("socket");
        return 1;
    }

    /*
     * ------------------------------------------------------------
     * 2. Récupération de l'interface et de l'IP source
     * ------------------------------------------------------------
     */

    if (getInterfaceReseau(&nmap.reseau) < 0)
    {
        fprintf(stderr, "Unable to find network interface\n");
        close(sock);
        return 1;
    }

    printf("Interface : %s\n", nmap.reseau.name);
    printf("Source IP : %s\n", nmap.reseau.ip);

    if (inet_pton(AF_INET, nmap.reseau.ip, &nmap.sip) != 1)
    {
        fprintf(stderr, "Invalid source IP\n");
        close(sock);
        return 1;
    }

    /*
     * IP cible.
     */

    if (inet_pton(AF_INET, argv[1], &nmap.tip) != 1)
    {
        fprintf(stderr, "Invalid target IP: %s\n", argv[1]);
        close(sock);
        return 1;
    }

    printf("Target IP : %s\n", argv[1]);
    printf("Target port : %d\n", DEST_PORT);

    /*
     * ------------------------------------------------------------
     * 3. Construction du paquet IP + UDP
     * ------------------------------------------------------------
     */

    memset(&nmap.pkt, 0, sizeof(nmap.pkt));

    /*
     * IP HEADER
     */

    nmap.pkt.ip.version = 4;
    nmap.pkt.ip.ihl = 5;
    nmap.pkt.ip.tos = 0;

    nmap.pkt.ip.tot_len =
        htons(sizeof(struct iphdr) +
               sizeof(struct udphdr));

    nmap.pkt.ip.id = htons(1234);
    nmap.pkt.ip.frag_off = 0;
    nmap.pkt.ip.ttl = 64;

    nmap.pkt.ip.protocol = IPPROTO_UDP;

    nmap.pkt.ip.saddr = nmap.sip.s_addr;
    nmap.pkt.ip.daddr = nmap.tip.s_addr;

    /*
     * Le checksum doit être calculé avec check = 0.
     */

    nmap.pkt.ip.check = 0;

    nmap.pkt.ip.check =
        checksum((unsigned short *)&nmap.pkt.ip,
                 sizeof(struct iphdr));

    /*
     * UDP HEADER
     */

    nmap.pkt.udp.source = htons(SOURCE_PORT);
    nmap.pkt.udp.dest = htons(DEST_PORT);

    nmap.pkt.udp.len =
        htons(sizeof(struct udphdr));

    nmap.pkt.udp.check = 0;

    /*
     * ------------------------------------------------------------
     * 4. Checksum UDP
     * ------------------------------------------------------------
     */

    struct pseudo_header psh;

    unsigned char buffer[
        sizeof(struct pseudo_header) +
        sizeof(struct udphdr)
    ];

    memset(&psh, 0, sizeof(psh));

    psh.source_address = nmap.sip.s_addr;
    psh.dest_address = nmap.tip.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr));

    memcpy(buffer,
           &psh,
           sizeof(struct pseudo_header));

    memcpy(buffer + sizeof(struct pseudo_header),
           &nmap.pkt.udp,
           sizeof(struct udphdr));

    nmap.pkt.udp.check =
        checksum((unsigned short *)buffer,
                 sizeof(buffer));

    /*
     * ------------------------------------------------------------
     * 5. IP_HDRINCL
     * ------------------------------------------------------------
     *
     * On dit au kernel que nous fournissons nous-mêmes
     * le header IP.
     */

    if (setsockopt(sock,
                   IPPROTO_IP,
                   IP_HDRINCL,
                   &one,
                   sizeof(one)) < 0)
    {
        perror("setsockopt");
        close(sock);
        return 1;
    }

    /*
     * ------------------------------------------------------------
     * 6. Ouverture de libpcap
     * ------------------------------------------------------------
     */

    handle = pcap_open_live(
        nmap.reseau.name,
        65535,
        1,
        1000,
        errbuf
    );

    if (handle == NULL)
    {
        fprintf(stderr,
                "Could not open device %s: %s\n",
                nmap.reseau.name,
                errbuf);

        close(sock);
        return 1;
    }

    /*
     * ------------------------------------------------------------
     * 7. Filtre BPF
     * ------------------------------------------------------------
     *
     * On veut :
     *
     *   - une réponse UDP provenant de la cible
     *   - OU un ICMP provenant de la cible
     *
     * Le deuxième cas correspond notamment à :
     *
     *   ICMP Destination Unreachable
     *   ICMP Port Unreachable
     *
     * lorsqu'un port UDP est fermé.
     */

    snprintf(
        filter_exp,
        sizeof(filter_exp),
        "(udp and src host %s and src port %d) or "
        "(icmp and src host %s)",
        inet_ntoa(nmap.tip),
        DEST_PORT,
        inet_ntoa(nmap.tip)
    );

    printf("BPF filter : %s\n", filter_exp);

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
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr,
                "pcap_setfilter: %s\n",
                pcap_geterr(handle));

        pcap_freecode(&fp);
        pcap_close(handle);
        close(sock);
        return 1;
    }

    /*
     * ------------------------------------------------------------
     * 8. Adresse destination
     * ------------------------------------------------------------
     */

    memset(&dest_addr, 0, sizeof(dest_addr));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = nmap.tip;

    /*
     * ------------------------------------------------------------
     * 9. Envoi du paquet UDP
     * ------------------------------------------------------------
     */

    printf("Sending UDP packet...\n");

    ssize_t sent = sendto(
        sock,
        &nmap.pkt,
        sizeof(nmap.pkt),
        0,
        (struct sockaddr *)&dest_addr,
        sizeof(dest_addr)
    );

    if (sent < 0)
    {
        perror("sendto");
        pcap_freecode(&fp);
        pcap_close(handle);
        close(sock);
        return 1;
    }

    printf("UDP packet sent: %zd bytes\n", sent);

    /*
     * ------------------------------------------------------------
     * 10. Capture
     * ------------------------------------------------------------
     */

    printf("Waiting for response...\n");

    ret = pcap_next_ex(
        handle,
        &header,
        &packet
    );

    if (ret == 0)
    {
        /*
         * Timeout.
         *
         * Pour UDP, un timeout ne permet pas de dire avec
         * certitude que le port est ouvert.
         */

        printf("No response received.\n");
        printf("UDP port %d: OPEN|FILTERED\n", DEST_PORT);
    }
    else if (ret == -1)
    {
        fprintf(stderr,
                "pcap_next_ex: %s\n",
                pcap_geterr(handle));
    }
    else if (ret == -2)
    {
        fprintf(stderr, "pcap EOF\n");
    }
    else if (ret == 1)
    {
        /*
         * --------------------------------------------------------
         * 11. Ethernet
         * --------------------------------------------------------
         */

        if (header->caplen < sizeof(struct ethernet_header))
        {
            fprintf(stderr, "Captured packet too small\n");
        }
        else
        {
            struct ethernet_header *eth =
                (struct ethernet_header *)packet;

            if (ntohs(eth->ethertype) != ETH_P_IP)
            {
                printf("Non IPv4 packet captured\n");
            }
            else
            {
                /*
                 * ------------------------------------------------
                 * 12. IP
                 * ------------------------------------------------
                 */

                struct iphdr *ip =
                    (struct iphdr *)(packet +
                                     sizeof(struct ethernet_header));

                size_t ip_offset =
                    sizeof(struct ethernet_header);

                size_t ip_header_length =
                    ip->ihl * 4;

                if (ip_header_length < sizeof(struct iphdr) ||
                    header->caplen <
                    ip_offset + ip_header_length)
                {
                    fprintf(stderr, "Invalid IP header\n");
                }
                else
                {
                    char src_ip[INET_ADDRSTRLEN];
                    char dst_ip[INET_ADDRSTRLEN];

                    inet_ntop(
                        AF_INET,
                        &ip->saddr,
                        src_ip,
                        sizeof(src_ip)
                    );

                    inet_ntop(
                        AF_INET,
                        &ip->daddr,
                        dst_ip,
                        sizeof(dst_ip)
                    );

                    printf("\nPacket captured: %u bytes\n",
                           header->caplen);

                    printf("IP version = %d\n",
                           ip->version);

                    printf("IP header length = %zu bytes\n",
                           ip_header_length);

                    printf("IP protocol = %d\n",
                           ip->protocol);

                    printf("packet src = %s\n",
                           src_ip);

                    printf("packet dst = %s\n",
                           dst_ip);

                    /*
                     * ------------------------------------------------
                     * 13. Réponse UDP
                     * ------------------------------------------------
                     */

                    if (ip->protocol == IPPROTO_UDP)
                    {
                        size_t udp_offset =
                            ip_offset + ip_header_length;

                        if (header->caplen <
                            udp_offset + sizeof(struct udphdr))
                        {
                            fprintf(stderr,
                                    "Captured UDP packet too small\n");
                        }
                        else
                        {
                            struct udphdr *udp =
                                (struct udphdr *)
                                (packet + udp_offset);

                            printf("UDP src port = %d\n",
                                   ntohs(udp->source));

                            printf("UDP dst port = %d\n",
                                   ntohs(udp->dest));

                            printf("UDP length = %d\n",
                                   ntohs(udp->len));

                            /*
                             * Une réponse UDP venant du port
                             * testé signifie que le service a
                             * répondu.
                             */

                            if (ntohs(udp->source) == DEST_PORT)
                            {
                                printf(
                                    "UDP port %d: OPEN\n",
                                    DEST_PORT
                                );
                            }
                        }
                    }

                    /*
                     * ------------------------------------------------
                     * 14. Réponse ICMP
                     * ------------------------------------------------
                     */

                    else if (ip->protocol == IPPROTO_ICMP)
                    {
                        size_t icmp_offset =
                            ip_offset + ip_header_length;

                        if (header->caplen <
                            icmp_offset + sizeof(struct icmphdr))
                        {
                            fprintf(stderr,
                                    "Captured ICMP packet too small\n");
                        }
                        else
                        {
                            struct icmphdr *icmp =
                                (struct icmphdr *)
                                (packet + icmp_offset);

                            printf("ICMP type = %d\n",
                                   icmp->type);

                            printf("ICMP code = %d\n",
                                   icmp->code);

                            /*
                             * ICMP type 3 = Destination Unreachable
                             *
                             * code 3 = Port Unreachable
                             */

                            if (icmp->type == ICMP_DEST_UNREACH &&
                                icmp->code == ICMP_PORT_UNREACH)
                            {
                                printf(
                                    "UDP port %d: CLOSED\n",
                                    DEST_PORT
                                );
                            }
                            else
                            {
                                printf(
                                    "ICMP response received\n"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /*
     * ------------------------------------------------------------
     * 15. Nettoyage
     * ------------------------------------------------------------
     */

    pcap_freecode(&fp);
    pcap_close(handle);
    close(sock);

    return 0;
}
