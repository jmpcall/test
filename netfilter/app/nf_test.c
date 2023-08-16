#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#include "linux/netfilter.h"
#include "libnetfilter_queue/libnetfilter_queue.h"
#include "libnfnetlink/libnfnetlink.h"


struct nfq_info {
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
};

static pthread_t tid;
struct nfq_info q;


static int nfq_recv_callback(
	struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *data)
{
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);

	(void)nfmsg;
	(void)data;
	printf("%s(), %d\n", __FUNCTION__, __LINE__);

	if (ph != NULL)
		nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);

	return 0;
}
	
static void *nfq_recv_routine(void *arg)
{
	struct nfq_info *q = (struct nfq_info *)arg;
	char buf[4096];

	while (1) {
		int rv = recv(q->fd, buf, sizeof(buf), 0);
		if (rv >= 0) {
			printf("%s(), %d: rv = %d\n", __FUNCTION__, __LINE__, rv);
			nfq_handle_packet(q->h, buf, rv);
		}
	}

	return NULL;
}

static int nfq_rebind_pf(struct nfq_info *q)
{
	if (nfq_unbind_pf(q->h, AF_INET) < 0) {
		printf("%s(), %d: nfq_unbind_pf() failed\n", __FUNCTION__, __LINE__);
		return -1;
	}

	if (nfq_unbind_pf(q->h, AF_INET6) < 0) {
		printf("%s(), %d: nfq_unbind_pf() failed\n", __FUNCTION__, __LINE__);
		return -1;
	}

	if (nfq_unbind_pf(q->h, AF_BRIDGE) < 0) {
		printf("%s(), %d: nfq_unbind_pf() failed\n", __FUNCTION__, __LINE__);
		return -1;
	}

	if (nfq_bind_pf(q->h, AF_INET) < 0) {
		printf("%s(), %d: nfq_bind_pf() failed\n", __FUNCTION__, __LINE__);
		return -1;
	}

	if (nfq_bind_pf(q->h, AF_INET6) < 0) {
		printf("%s(), %d: nfq_bind_pf() failed\n", __FUNCTION__, __LINE__);
		return -1;
	}

	if (nfq_bind_pf(q->h, AF_BRIDGE) < 0) {
		printf("%s(), %d: nfq_bind_pf() failed\n", __FUNCTION__, __LINE__);
		return -1;
	}

	return 0;
}

static int nfq_create()
{
	if ((q.h = nfq_open()) == NULL) {
		printf("%s(), %d: nfq_open() failed\n", __FUNCTION__, __LINE__);
		goto err;
	}

	if (nfq_rebind_pf(&q) < 0)
		goto err;

	if ((q.qh = nfq_create_queue(q.h, 0, nfq_recv_callback, NULL)) == NULL) {
		printf("%s(), %d: nfq_create_queue() failed, %s\n", __FUNCTION__, __LINE__, strerror(errno));
		goto err;
	}

	if (nfq_set_mode(q.qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		printf("%s(), %d: nfq_set_mode() failed\n", __FUNCTION__, __LINE__);
		goto err;
	}

#if 0
	if ((q.nh = nfq_nfnlh(q.h)) == NULL) {
		printf("%s(), %d: nfq_nfnlh() failed\n", __FUNCTION__, __LINE__);
		goto err;
	}
#endif

	//if ((q.fd = nfnl_fd(q.nh)) < 0) {
	if ((q.fd = nfq_fd(q.h)) < 0) {
		printf("%s(), %d: nfnl_fd() failed\n", __FUNCTION__, __LINE__);
		goto err;
	}

	if (pthread_create(&tid, NULL, nfq_recv_routine, &q) != 0) {
		printf("%s(), %d: pthread_create() failed\n", __FUNCTION__, __LINE__);
		goto err;
	}

	return 0;
err:
	if (q.fd > 0)
		close(q.fd);
#if 0
	if (q.nh != NULL) {
	}
#endif
	if (q.qh != NULL)
		nfq_destroy_queue(q.qh);
	if (q.h != NULL)
		nfq_close(q.h);
	return -1;
}


int main()
{
	printf("%s(), %d\n", __FUNCTION__, __LINE__);

	if (nfq_create() < 0)
		return -1;

	pthread_join(tid, NULL);
	return 0;
}


