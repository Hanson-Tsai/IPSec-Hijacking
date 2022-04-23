#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

#define DEBUG

EspHeader esp_hdr_rec;

void get_ik(int type, uint8_t *key)
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self)
{
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)
    return self->pad;
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // [TODO]: Put everything needed to be authenticated into buff and add up nb

    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP

    // struct esp {
    //     EspHeader hdr;

    //     uint8_t *pl;    // ESP payload
    //     size_t plen;    // ESP payload length

    //     uint8_t *pad;   // ESP padding

    //     EspTrailer tlr;

    //     uint8_t *auth;
    //     size_t authlen;

    //     uint8_t *esp_key;

    //     uint8_t *(*set_padpl)(Esp *self);
    //     uint8_t *(*set_auth)(Esp *self,
    //                         ssize_t (*hmac)(uint8_t const *, size_t,
    //                                         uint8_t const *, size_t,
    //                                         uint8_t *));
    //     void (*get_key)(Esp *self);
    //     uint8_t *(*dissect)(Esp *self, uint8_t *esp_pkt, size_t esp_len);
    //     Esp *(*fmt_rep)(Esp *self, Proto p);
    // };
    struct esp_header *esphdr = (struct esp_header *)esp_pkt;

    self->hdr.seq = esphdr->seq;
    self->hdr.spi = esphdr->spi;

#ifdef DEBUG
    printf("ESP seq: %d\n",ntohl(esphdr->seq));
    printf("ESP spi: %x\n",ntohl(esphdr->spi));
#endif

    return esp_pkt + sizeof(struct esp_header);
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)
}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
}
