#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "dev.h"
#include "net.h"
#include "esp.h"
#include "replay.h"
#include "transport.h"

inline static int get_ifr_mtu(struct ifreq *ifr)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, SIOCGIFMTU, ifr) < 0) {
        perror("ioctl()");
        close(fd);
        exit(EXIT_FAILURE);
    }

    return ifr->ifr_mtu;
}

inline static struct sockaddr_ll init_addr(char *name)
{
    struct sockaddr_ll addr;
    struct ifreq ifstruct;
    bzero(&addr, sizeof(addr));

    // [TODO]: Fill up struct sockaddr_ll addr which will be used to bind in func set_sock_fd
    printf("setup socket\n");
    int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    addr.sll_family = PF_PACKET;

    strcpy(ifstruct.ifr_name, name);
    if(ioctl(sockfd, SIOGIFINDEX, &ifstruct) < 0){
        perror("ioctl()");
    }

    addr.sll_ifindex = ifstruct.ifr_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);

    close(sockfd);

    if (addr.sll_ifindex == 0) {
        perror("if_nameindex()");
        exit(EXIT_FAILURE);
    }

    return addr;
}

inline static int set_sock_fd(struct sockaddr_ll dev)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    bind(fd, (struct sockaddr *)&dev, sizeof(dev));

    return fd;
}

void fmt_frame(Dev *self, Net net, Esp esp, Txp txp)
{
    // [TODO]: store the whole frame into self->frame
    // and store the length of the frame into self->framelen
    // memcpy
    self->framelen = 0;
    self->framelen += LINKHDRLEN;
    memcpy(self->frame+self->framelen, &net.ip4hdr, sizeof(struct iphdr));
    self->framelen += sizeof(struct iphdr);
    memcpy(self->frame+self->framelen, &esp.hdr, sizeof(struct esp_header));
    self->framelen += sizeof(struct esp_header);
    memcpy(self->frame+self->framelen, &txp.thdr, sizeof(struct tcphdr));
    self->framelen += sizeof(struct tcphdr);
    memcpy(self->frame+self->framelen, txp.pl, txp.plen);
    self->framelen += txp.plen;
    memcpy(self->frame+self->framelen, esp.pad, esp.tlr.pad_len);
    self->framelen += esp.tlr.pad_len;
    memcpy(self->frame+self->framelen, &esp.tlr, sizeof(struct esp_trailer));
    self->framelen += sizeof(struct esp_trailer);
    memcpy(self->frame+self->framelen, esp.auth, esp.authlen);
    self->framelen += esp.authlen;
    // printf("dev fmt\n");
    // uint16_t total_len = 0;
    // total_len += LINKHDRLEN;
    // total_len += sizeof(struct iphdr);
    // total_len += 20;
    // total_len += net.plen;

    // uint8_t* sendbuff = (uint8_t *)malloc(total_len);
    // memcpy(sendbuff, self->linkhdr, LINKHDRLEN);

    // struct iphdr *iph = (struct iphdr*)(sendbuff + sizeof(self->linkhdr));
    // memcpy(iph, &net.ip4hdr, sizeof(struct iphdr));

    // struct esp_header *esph = (struct esp_header*)(sendbuff + sizeof(self->linkhdr) + sizeof(struct iphdr));
    // memcpy(esph, &esp.hdr, sizeof(struct esp_header));

    // struct tcphdr *tcph = (struct tcphdr*)((sendbuff + sizeof(self->linkhdr)) + sizeof(struct iphdr) + sizeof(struct esp_header));
    // memcpy(tcph, &txp.thdr, sizeof(struct tcphdr));

    // uint8_t *tcppl = (uint8_t *)((sendbuff + sizeof(self->linkhdr)) + sizeof(struct iphdr) + sizeof(struct esp_header) + txp.hdrlen);
    // memcpy(tcppl, txp.pl, txp.plen);

    // uint8_t *pad = (uint8_t *)((sendbuff + sizeof(self->linkhdr)) + sizeof(struct iphdr) + sizeof(struct esp_header) + esp.plen);
    // memcpy(pad, esp.pad, esp.tlr.pad_len);

    // struct esp_trailer *espt = (struct esp_trailer *)((sendbuff + sizeof(self->linkhdr)) + sizeof(struct iphdr) + sizeof(struct esp_header) + esp.plen + esp.tlr.pad_len);
    // memcpy(espt, &esp.tlr, sizeof(struct esp_trailer));

    // uint8_t *espa = (uint8_t *)((sendbuff + sizeof(self->linkhdr)) + sizeof(struct iphdr) + sizeof(struct esp_header) + esp.plen + esp.tlr.pad_len + sizeof(struct esp_trailer));
    // memcpy(espa, esp.auth, esp.authlen);

    // printf("total len %d\n",total_len);

    // memcpy(self->frame, sendbuff, total_len);
    // self->framelen = total_len;

    // printf("!!!\n");
}

ssize_t tx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = sendto(self->fd, self->frame, self->framelen,
                0, (struct sockaddr *)&self->addr, addrlen);

    if (nb <= 0) perror("sendto()");

    return nb;
}

ssize_t rx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = recvfrom(self->fd, self->frame, self->mtu,
                  0, (struct sockaddr *)&self->addr, &addrlen);
    if (nb <= 0)
        perror("recvfrom()");

    return nb;
}

void init_dev(Dev *self, char *dev_name)
{
    if (!self || !dev_name || strlen(dev_name) + 1 > IFNAMSIZ) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);

    self->mtu = get_ifr_mtu(&ifr);

    self->addr = init_addr(dev_name);
    // printf("init addr success\n");
    self->fd = set_sock_fd(self->addr);
    // printf("set socket success\n");

    self->frame = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));
    self->framelen = 0;

    self->fmt_frame = fmt_frame;
    self->tx_frame = tx_frame;
    self->rx_frame = rx_frame;

    self->linkhdr = (uint8_t *)malloc(LINKHDRLEN);
}
