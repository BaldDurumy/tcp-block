#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

struct ethernet_hdr
{
    u_int8_t  ether_dhost[6];	/* destination ethernet address */
    u_int8_t  ether_shost[6];	/* source ethernet address */
    u_int16_t ether_type;		/* protocol */
};

struct ipv4_hdr
{
    u_int8_t ip_hl:4, ip_v:4;	/* version, header length*/
    u_int8_t ip_tos;			/* type of service */
    u_int16_t ip_len;         	/* total length */
    u_int16_t ip_id;          	/* identification */
    u_int16_t ip_off:13, ip_flag:3;	/* flag, fragment offset*/
    u_int8_t ip_ttl;          	/* time to live */
    u_int8_t ip_p;            	/* protocol */
    u_int16_t ip_sum;         	/* checksum */
    u_int32_t ip_src, ip_dst; 	/* source and dest address */
};

struct tcp_hdr
{
    u_int16_t th_sport;       	/* source port */
    u_int16_t th_dport;       	/* destination port */
    u_int32_t th_seq;          	/* sequence number */
    u_int32_t th_ack;          	/* acknowledgement number */
    u_int8_t th_x2:4,         /* (unused) */
    		th_off:4;        /* data offset */
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

struct packet_hdr
{
	struct ethernet_hdr* pEther;	/* ethernet header */
	struct ipv4_hdr* pIpv4;			/* ipv4 header */
	struct tcp_hdr* pTcp;			/* tcp header */
	u_char* pData;					/* tcp data */
	u_int data_len;					/* tcp data length */
};

struct pseudo_hdr
{
	u_int32_t src_ip; 
	u_int32_t dst_ip;
	u_int8_t reserved; 
	u_int8_t protocol; 
	u_int16_t tcp_len;
};


void pkt_parse(struct packet_hdr* pPkt_hdr, u_char* packet){
	//ethernet
	pPkt_hdr->pEther = packet;
	//ipv4
	pPkt_hdr->pIpv4 = (u_int8_t*)pPkt_hdr->pEther + sizeof(struct ethernet_hdr);
	//tcp
	pPkt_hdr->pTcp = (u_int8_t*)pPkt_hdr->pIpv4 + (pPkt_hdr->pIpv4->ip_hl << 2);
	//tcp data
	pPkt_hdr->pData = (u_int8_t*)pPkt_hdr->pTcp + (pPkt_hdr->pTcp->th_off << 2);
	pPkt_hdr->data_len = ntohs(pPkt_hdr->pIpv4->ip_len) - (pPkt_hdr->pIpv4->ip_hl << 2) - (pPkt_hdr->pTcp->th_off << 2);
}

bool check_pkt(struct packet_hdr* pPkt_hdr, char* pattern){
	//check ipv4
	if(ntohs(pPkt_hdr->pEther->ether_type) != 0x0800) return false;
	if(pPkt_hdr->pIpv4->ip_v != 0x4) return false;

	//check tcp
	if(pPkt_hdr->pIpv4->ip_p != 0x6) return false;

	//check http(s)
	if((ntohs(pPkt_hdr->pTcp->th_sport) != 80) && (ntohs(pPkt_hdr->pTcp->th_dport) != 80) && (ntohs(pPkt_hdr->pTcp->th_sport) != 443) && (ntohs(pPkt_hdr->pTcp->th_dport) != 443)) return false;

	//check pattern
	if(pPkt_hdr->data_len < strlen(pattern)) return false;
	for(int i = 0; i<(pPkt_hdr->data_len - strlen(pattern)); i++) {
		if(!memcmp(pPkt_hdr->pData+i, pattern, strlen(pattern))) return true;
	}
	return false;
}

void calc_checksum(struct packet_hdr* pPkt_hdr){
	struct pseudo_hdr ph;
	u_int32_t tmp;

	//calc ip checksum
	tmp = 0;
	for(int i = 0; i<(pPkt_hdr->pIpv4->ip_hl<<1); i++){
		tmp += ntohs(*((u_int16_t*)pPkt_hdr->pIpv4+i));
		if(tmp & 0x10000){
			tmp &= 0xffff;
			tmp++;
		}
	}
	tmp ^= 0xffff;
	pPkt_hdr->pIpv4->ip_sum = htons((u_int16_t)tmp);

	//calc tcp checksum
	tmp = 0;
	ph.src_ip = pPkt_hdr->pIpv4->ip_src;
	ph.dst_ip = pPkt_hdr->pIpv4->ip_dst;
	ph.reserved = 0;
	ph.protocol = pPkt_hdr->pIpv4->ip_p;
	ph.tcp_len = htons(ntohs(pPkt_hdr->pIpv4->ip_len) - (pPkt_hdr->pIpv4->ip_hl << 2));

	for(int i = 0; i<(sizeof(struct pseudo_hdr)>>1); i++){
		tmp += ntohs(*((u_int16_t*)&ph+i));
		if(tmp & 0x10000){
			tmp &= 0xffff;
			tmp++;
		}
	}

	pPkt_hdr->pData[pPkt_hdr->data_len] = 0;	//padding
	for(int i = 0; i<((ntohs(ph.tcp_len)+1)>>1); i++){
		tmp += ntohs(*((u_int16_t*)pPkt_hdr->pTcp+i));
		if(tmp & 0x10000){
			tmp &= 0xffff;
			tmp++;
		}
	}
	tmp ^= 0xffff;
	pPkt_hdr->pTcp->th_sum = htons((u_int16_t)tmp);
}

int main(int argc, char* argv[]) {
	if (argc != 3){
		fprintf(stderr, "syntax : tcp-block <interface> <pattern>\n");
		fprintf(stderr, "sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
		exit(1);
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		exit(1);
	}

	struct pcap_pkthdr* header;
	const u_char* packet;
	int res;
	u_char fp[256];
	u_char bp[256];
	struct packet_hdr op_hdr;
	struct packet_hdr fp_hdr;
	struct packet_hdr bp_hdr;
	u_char* redirect = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.kr\r\n\r\n";

	//raw socket
    int sockfd; 
    int opt;
    struct sockaddr_ll sock_addr;
    memset(&sock_addr, 0, sizeof(struct sockaddr_ll));

    if((sockfd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0){
        fprintf(stderr, "socket failed\n");
        exit(1);
    }

	sock_addr.sll_family = PF_PACKET;
	sock_addr.sll_protocol = htons(ETH_P_IP);
	sock_addr.sll_ifindex =  if_nametoindex(argv[1]);
	sock_addr.sll_halen = ETH_ALEN;

	while (true) {
		res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		pkt_parse(&op_hdr, packet);

		if(!check_pkt(&op_hdr, argv[2])){
			continue;
		}
		printf("malicious packet\n");

		memcpy(fp, packet, sizeof(struct ethernet_hdr)+(op_hdr.pIpv4->ip_hl<<2)+(op_hdr.pTcp->th_off<<2));
		memcpy(bp, packet, sizeof(struct ethernet_hdr)+(op_hdr.pIpv4->ip_hl<<2)+(op_hdr.pTcp->th_off<<2));

		pkt_parse(&fp_hdr, fp);
		pkt_parse(&bp_hdr, bp);

		//forward packet
		fp_hdr.pIpv4->ip_len = htons((op_hdr.pIpv4->ip_hl << 2) + (op_hdr.pTcp->th_off << 2));
		fp_hdr.pIpv4->ip_sum = 0;
		fp_hdr.pTcp->th_seq = htonl(ntohl(op_hdr.pTcp->th_seq) + op_hdr.data_len);
		fp_hdr.pTcp->th_flags = 0b00000100;		//RST
		fp_hdr.pTcp->th_sum = 0;
		fp_hdr.pTcp->th_urp = 0;

		//backward packet
		memcpy(bp_hdr.pEther->ether_dhost, op_hdr.pEther->ether_shost, sizeof(op_hdr.pEther->ether_shost));
		bp_hdr.pIpv4->ip_len = htons((op_hdr.pIpv4->ip_hl << 2) + (op_hdr.pTcp->th_off << 2) + strlen(redirect));
		bp_hdr.pIpv4->ip_ttl = 128;
		bp_hdr.pIpv4->ip_sum = 0;
		bp_hdr.pIpv4->ip_src = op_hdr.pIpv4->ip_dst;
		bp_hdr.pIpv4->ip_dst = op_hdr.pIpv4->ip_src;
		bp_hdr.pTcp->th_dport = op_hdr.pTcp->th_sport;
		bp_hdr.pTcp->th_sport = op_hdr.pTcp->th_dport;
		bp_hdr.pTcp->th_seq = fp_hdr.pTcp->th_ack;
		bp_hdr.pTcp->th_ack = fp_hdr.pTcp->th_seq;
		bp_hdr.pTcp->th_flags = 0b00010001;		//FIN + ACK
		bp_hdr.pTcp->th_sum = 0;
		bp_hdr.pTcp->th_urp = 0;
		pkt_parse(&bp_hdr, bp);
		memcpy(bp_hdr.pData, redirect, strlen(redirect));

		//calc checksum
		calc_checksum(&fp_hdr);
		calc_checksum(&bp_hdr);

		//send packet
		memcpy(sock_addr.sll_addr, fp_hdr.pEther->ether_dhost, sizeof(fp_hdr.pEther->ether_dhost));
		if(sendto(sockfd, fp, sizeof(struct ethernet_hdr)+ntohs(fp_hdr.pIpv4->ip_len), 0, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0){
			fprintf(stderr, "fp sendto failed\n");
			exit(1);
		}

		memcpy(sock_addr.sll_addr, bp_hdr.pEther->ether_dhost, sizeof(fp_hdr.pEther->ether_dhost));
		if(sendto(sockfd, bp, sizeof(struct ethernet_hdr)+ntohs(bp_hdr.pIpv4->ip_len), 0, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0){
			fprintf(stderr, "bp sendto failed\n");
			exit(1);
		}
	}
	pcap_close(pcap);
	return 0;
}