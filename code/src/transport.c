#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"

// #define DEBUG

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphder, uint8_t *pl, int plen)
{
    // // // [TODO]: Finish TCP checksum calculation

    uint32_t sum = 0;
    unsigned short headerlen = tcphder.doff << 2;
    unsigned short tcplen = headerlen+plen;
    sum += (iphdr.saddr >> 16)&0xFFFF;
    sum += (iphdr.saddr)&0xFFFF;
    sum += (iphdr.daddr >> 16)&0xFFFF;
    sum += (iphdr.daddr)&0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcplen);
    /* tcp header */
    unsigned short *tcp = (unsigned short *)(void *)&tcphder;
    while(headerlen > 1){
        sum += *tcp;
        tcp++;
        headerlen -=2;
    }
    /* tcp payload */
    tcp = (unsigned short*)pl;
    tcplen = plen;
    while(tcplen > 1){
        sum += *tcp;
        tcp++;
        tcplen -=2;
    }
    if(tcplen > 0){
        sum += ((*tcp)&htons(0xFF00));
    }
    while(sum >> 16){
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    return (uint16_t)sum;

}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP
    struct tcphdr *tcp = (struct tcphdr *)segm;
    memcpy(&self->thdr, tcp, sizeof(struct tcphdr));
    self->hdrlen = (uint8_t)tcp->doff<<2;
    self->pl = segm + self->hdrlen;
    uint8_t* payload = segm;
    uint8_t count = self->hdrlen;
    while( payload[count+1] != 0x00 && payload[count+1] != 0x01){
        // printf("%c",*data);
        // data++;
        count++;
    }
    count++;

    self->pl = segm + self->hdrlen;
    self->plen = count-(self->hdrlen);
    // printf("\ndata length %d\n",self->plen);
    // if((unsigned int)tcp->psh == 1){
    //     printf("\t|-Checksum             : %d\n",ntohs(tcp->check));
    //     //cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
    //     self->thdr.check = 0;
    //     printf("my checksum %d\n",ntohs(cal_tcp_cksm(net->ip4hdr, self->thdr, self->pl, self->plen)));
    // }

#ifdef DEBUG
   	printf("\nTCP Header\n");
   	printf("\t|-Source Port          : %u\n",ntohs(tcp->source));
   	printf("\t|-Destination Port     : %u\n",ntohs(tcp->dest));
   	printf("\t|-Sequence Number      : %u\n",ntohl(tcp->seq));
   	printf("\t|-Acknowledge Number   : %u\n",ntohl(tcp->ack_seq));
   	printf("\t|-Header Length        : %d DWORDS or %d BYTES\n" ,(unsigned int)tcp->doff,(unsigned int)tcp->doff*4);
	printf("\t|----------Flags-----------\n");
	printf("\t\t|-Urgent Flag          : %d\n",(unsigned int)tcp->urg);
	printf("\t\t|-Acknowledgement Flag : %d\n",(unsigned int)tcp->ack);
	printf("\t\t|-Push Flag            : %d\n",(unsigned int)tcp->psh);
	printf("\t\t|-Reset Flag           : %d\n",(unsigned int)tcp->rst);
	printf("\t\t|-Synchronise Flag     : %d\n",(unsigned int)tcp->syn);
	printf("\t\t|-Finish Flag          : %d\n",(unsigned int)tcp->fin);
	printf("\t|-Window size          : %d\n",ntohs(tcp->window));
	printf("\t|-Checksum             : %d\n",ntohs(tcp->check));
    //cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
    // printf("my checksum %d\n",ntohs(cal_tcp_cksm(net->ip4hdr, self->thdr, segm, segm_len)));
	printf("\t|-Urgent Pointer       : %d\n",tcp->urg_ptr);
    printf("self->thdr.ack_seq: %u\n", ntohl(self->thdr.ack_seq));
    printf("self->thdr.psh: %d\n", (unsigned int)(self->thdr.psh));
#endif
    return  self->pl;
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)
    self->thdr.th_sport = htons(self->x_src_port);
    self->thdr.th_dport = htons(self->x_dst_port);
    self->thdr.seq = htonl(self->x_tx_seq);
    self->thdr.ack_seq = htonl(self->x_tx_ack);
    // memset(self->pl, 0, sizeof(uint8_t)*dlen);
    memcpy(self->pl, data, dlen);

    // self->thdr.ack_seq = (uint32_t)1;
    self->thdr.psh = self->thdr.psh;
    self->thdr.check = 0;

    self->thdr.check = cal_tcp_cksm(iphdr, self->thdr, data, dlen);
    // printf("\t|-Sequence Number      : %u\n",ntohl(self->thdr.seq));
   	// printf("\t|-Acknowledge Number   : %u\n",ntohl(self->thdr.ack_seq));
    // printf("\t\t|-Push Flag            : %d\n",(unsigned int)self->thdr.psh);
    // printf("\t|-Checksum             : %d\n",ntohs(self->thdr.check));
    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

