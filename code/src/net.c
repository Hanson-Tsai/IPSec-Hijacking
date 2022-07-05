#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"

// #define DEBUG

uint16_t cal_ipv4_cksm(struct iphdr* iphdr)
{
    // [TODO]: Finish IP checksum calculation
    iphdr->check = 0;
    unsigned short *addr = (unsigned short *)iphdr;
    unsigned int count = iphdr->ihl<<2;
    register unsigned long sum = 0;
    while ( count > 1)
    {
        sum += *addr++;
        count -= 2;
    }
    if (count > 0)
    {
        sum += ((*addr)&htons(0xFF00));
    }
    while ( sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    iphdr->check = (uint16_t)sum;
    return ((uint16_t)sum);
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt.
    // Return payload of network layer
    struct sockaddr_in source,dest;
    struct iphdr *ip = (struct iphdr *)pkt;
    memcpy(&self->ip4hdr, ip, sizeof(struct iphdr));
    // set hdrlen
	self->hdrlen = (size_t)ip->ihl<<2;
    // set plen
    self->plen = pkt_len - self->hdrlen;
    // set pro
    switch (ip->protocol)
    {
    case ESP:
        self->pro = ESP;
        break;
    case IPv4:
        self->pro = IPv4;
        break;
    case TCP:
        self->pro = TCP;
        break;
    default:
        self->pro = UNKN_PROTO;
        break;
    }
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;
    // set sorce & dest IP

    strcpy(self->src_ip,inet_ntoa(source.sin_addr));
    strcpy(self->dst_ip,inet_ntoa(dest.sin_addr));

#ifdef DEBUG
	printf("\nIP Header\n");
	printf("\t|-Version              : %d\n",(unsigned int)ip->version);
	printf("\t|-Internet Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
	printf("\t|-Type Of Service   : %d\n",(unsigned int)ip->tos);
	printf("\t|-Total Length      : %d  Bytes\n",ntohs(ip->tot_len));
	printf("\t|-Identification    : %d\n",ntohs(ip->id));
	printf("\t|-Time To Live	    : %d\n",(unsigned int)ip->ttl);
	printf("\t|-Protocol 	    : %d\n",(unsigned int)ip->protocol);
	printf("\t|-Header Checksum   : %d\n",ntohs(ip->check));
	printf("\t|-Source IP         : %s\n", inet_ntoa(source.sin_addr));
	printf("\t|-Destination IP    : %s\n",inet_ntoa(dest.sin_addr));
    printf("!my checksum: %d\n",ntohs(cal_ipv4_cksm(ip)));
    printf("IP pkt srcIP: %s\n", self->src_ip);
    printf("IP pkt dstIP: %s\n", self->dst_ip);
    printf("IP pkt protocol: %d\n", self->pro);
    printf("self->ip4hdr.Protocol: %d\n", (unsigned int)self->ip4hdr.protocol);
#endif

    return pkt + self->hdrlen;
}

Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)
    // printf("x src ip %s\n",self->x_src_ip);
    // printf("x dst ip %s\n", self->x_dst_ip);

    // struct sockaddr_in source,dest;
    // memset(&source, 0, sizeof(source));
	// source.sin_addr.s_addr = self->ip4hdr.saddr;
	// memset(&dest, 0, sizeof(dest));
	// dest.sin_addr.s_addr = self->ip4hdr.daddr;
    // // set sorce & dest IP
    // printf("src ip %x\n",self->ip4hdr.saddr);
    // printf("dst ip %x\n",self->ip4hdr.daddr);

    self->ip4hdr.tot_len = htons(sizeof(struct iphdr) + self->plen);
    self->ip4hdr.check = 0;
    self->ip4hdr.check = cal_ipv4_cksm(&(self->ip4hdr));
    return self;
}

void init_net(Net *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}
