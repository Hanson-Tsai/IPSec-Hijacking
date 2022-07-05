#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

// #define DEBUG

EspHeader esp_hdr_rec;

void key_print(struct sadb_ext *ext, uint8_t* k)
{
	struct sadb_key *key = (struct sadb_key *)ext;
	int bits;

	unsigned char *p;
	int i;

	uint8_t * kk = (uint8_t *)realloc(k,(key->sadb_key_bits/8)*sizeof(uint8_t));

	if(key->sadb_key_exttype == SADB_EXT_KEY_AUTH){
		// printf(" %s key, %d bits: 0x","Authentication",key->sadb_key_bits);
		for (i=0, p = (uint8_t *)(key + 1), bits = key->sadb_key_bits; bits > 0; p++, bits -= 8, i++){
			kk[i] = *p;
		}
	}
}

void print_sadb_msg(struct sadb_msg *msg, int msglen, uint8_t* key)
{
	struct sadb_ext *ext;

	if (msglen != msg->sadb_msg_len * 8) {
		printf("SADB Message length (%d) doesn't match msglen (%d)\n",
			msg->sadb_msg_len * 8, msglen);
		return;
	}
	if (msg->sadb_msg_version != PF_KEY_V2) {
		printf("SADB Message version not PF_KEY_V2\n");
		return;
	}

	if (msg->sadb_msg_errno != 0)
		printf(" errno %s\n", strerror(msg->sadb_msg_errno));
	if (msglen == sizeof(struct sadb_msg))
		return;	/* no extensions */
	msglen -= sizeof(struct sadb_msg);
	ext = (struct sadb_ext *)(msg + 1);
	while (msglen > 0) {
		if(ext->sadb_ext_type == SADB_EXT_KEY_AUTH){
			key_print(ext,key);
		}

		msglen -= ext->sadb_ext_len << 3;
		ext = (char *)ext + (ext->sadb_ext_len << 3);
	}
}


void get_ik(int type, uint8_t *key)
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)

    int s;
	char buf[4096];
	struct sadb_msg msg;
	int goteof;
    s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);

	if(s < 0)
        printf("[get_ik]: socket error");

	/* Build and write SADB_DUMP request */
	bzero(&msg, sizeof(msg));
	msg.sadb_msg_version = PF_KEY_V2;
	msg.sadb_msg_type = SADB_DUMP;
	msg.sadb_msg_satype = type;
	msg.sadb_msg_len = sizeof(msg) / 8;
	msg.sadb_msg_pid = getpid();

	if(write(s, &msg, sizeof(msg)) != sizeof(msg))
        printf("[get_ik]: write error");

	/* Read and print SADB_DUMP replies until done */
	goteof = 0;
	while (goteof == 0) {
		int msglen;
		struct sadb_msg *msgp;

		msglen = read(s, &buf, sizeof(buf));
		msgp = (struct sadb_msg *)&buf;
		print_sadb_msg(msgp, msglen, key);

		if (msgp->sadb_msg_seq == 0)
			goteof = 1;
	}
	close(s);
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);

#ifdef DEBUG
	printf("----Success Dump Key----\n");
	for(int i=0; i<16; i++){
		printf("%02x", self->esp_key[i]);
	}
	printf("------------------------\n");
	printf("\n");
#endif

}

uint8_t *set_esp_pad(Esp *self)
{
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)
#ifdef DEBUG1
	printf("[set_esp_pad]: Start\n");
#endif
	// printf("self->plen : %d\n", self->plen);
	size_t pad = self->plen%4;
	// printf("self->plen mod 4 : %d\n", pad);

	if(pad != 0){
		self->tlr.pad_len = 2 + (4-pad);
	}else{
		self->tlr.pad_len = 2;
	}

	int n = (int)(self->tlr.pad_len);
	// printf("Pad lenght (int): %d\n", n);

	if(n != 0){
		uint8_t *pad_pkt = (uint8_t *)realloc(self->pad,n*sizeof(uint8_t));
		// printf("Padding content\n");
		for(int i = 0; i<n; i++){
			pad_pkt[i] = (uint8_t)(i+1);
			// printf("%d", pad_pkt[i]);
		}
		// printf("\n");
	}

#ifdef DEBUG1
	printf("ESP tlr.pad_len: %d\n", self->tlr.pad_len);
	printf("[set_esp_pad]: End\n");
#endif

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
	// printf("ESP seq: %d\n",ntohl(self->hdr.seq));
    // printf("ESP spi: %x\n",ntohl(self->hdr.spi));
    // [TODO]: Put everything needed to be authenticated into buff and add up nb
	memcpy(buff, &self->hdr, sizeof(struct esp_header));
	nb += sizeof(struct esp_header);
	memcpy(buff+nb, self->pl, self->plen);
	nb += self->plen;
	memcpy(buff+nb, self->pad, self->tlr.pad_len);
	nb += self->tlr.pad_len;
	memcpy(buff+nb, &self->tlr, sizeof(struct esp_trailer));
	nb += sizeof(struct esp_trailer);
	// printf("[set_esp_auth] nb: %d\n buffer ", nb);
	// for( int i=0 ; i<nb ; i++){
	// 	printf("%02x",buff[i]);
	// }
	// printf("\n");
    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
	// printf("auth len %d\n",self->authlen);
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP
    // esp header
    struct esp_header *esphdr = (struct esp_header *)esp_pkt;
    self->hdr.seq = esphdr->seq;
    self->hdr.spi = esphdr->spi;
    // esp pl & plen
    self->pl = esp_pkt + sizeof(struct esp_header);
    self->plen = esp_len - sizeof(struct esp_header);

#ifdef DEBUG
    printf("ESP seq: %d\n",ntohl(esphdr->seq));
    printf("ESP spi: %x\n",ntohl(esphdr->spi));
#endif

    return esp_pkt + sizeof(struct esp_header);
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)
#ifdef DEBUG1
	printf("[fmt_esp_rep]: Start\n");
#endif
	self->hdr.seq = htonl(ntohl(self->hdr.seq) + 1);
	self->tlr.nxt = (uint8_t)p;

#ifdef DEBUG1
	printf("ESP seq: %d\n", ntohl(self->hdr.seq));
	printf("ESP tlr.nxt: %d\n", self->tlr.nxt);
	printf("[fmt_esp_rep]: End\n");
#endif
	return self;
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
