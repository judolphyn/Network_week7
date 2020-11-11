#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include "headers.h"

#include <string>
#include <string.h>
#include <set>
#include <iostream>

using namespace std;

void usage(){
	printf("syntax : 1m-block <site list file>");
	printf("sample : 1m-block top-1m.txt");
}

int check;

set<string> site_pot;

int blocking(char* data) { //return 1 if we have to block.
	//finding "Host: "
	int n =0;
	while(n<100){ //set the limit
		if(strncmp((char*)(data+n),"Host: ",6) == 0) break;
		n++;
	}
	if(n==100){ //if reach the limit?
		printf("\n\nCannot find Host: \n\n");
		return 0;
	}

	//cut the end point. "\r\n"
	char* host = (char *)(data + n + 6);
	char *real_host = new char[100];
	n = 0;
	while(n<100){
		if(host[n] == '\r' && host[n+1] == '\n') break;
		real_host[n] = host[n]; 
		n++;
	}
	real_host[n] = '\0';

	string host_name(real_host);
	if(site_pot.find(host_name) == site_pot.end()) return 0;
	return 1;
}


int parse(unsigned char* buf, int size) {
	int i;
	u_int size_ip;
	u_int size_tcp;

	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	char *payload; /* HTTP payload */

	/* ip header parse */
	ip = (struct sniff_ip*)buf;
	if (ip->ip_p != 6){
		printf("\n\n   * Not TCP Type\n\n");
		return 0;
	}
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("\n\n   * Invalid IP header length: %u bytes\n\n", size_ip);
		return 0;
	}
	/* tcp header parse */
	tcp = (struct sniff_tcp*)(buf + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("\n\n   * Invalid TCP header length: %u bytes\n\n", size_tcp);
		return 0;
	}
	/* HTTP header parse */
	payload = (char *)(buf + size_ip + size_tcp);
	if(blocking(payload)==1){
		printf("\n\n\n\n   * This Site is forbidden!\n\n\n\n");
		return 1;
	}
	return 0;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		printf("payload_len=%d\n", ret);
		check = parse(data,ret); //if 1, drop. if 0, accept.
	}
	
	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if (check==0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	else return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

int main(int argc, char *argv[])
{
	if(argc != 2)
		usage();


	/*input handling*/
	FILE *in = fopen(argv[1], "r");
	char* ban_site = new char[100];
	int i, temp;
	for(i=0;i<1000000;i++){
		fscanf(in,"%d,%s\n",&temp,ban_site);
		string site_string(ban_site);
		site_pot.insert(ban_site);	
	}

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
