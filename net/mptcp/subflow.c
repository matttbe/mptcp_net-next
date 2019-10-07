// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include "protocol.h"

int mptcp_subflow_create_socket(struct sock *sk, struct socket **new_sock)
{
	struct mptcp_subflow_context *subflow;
	struct net *net = sock_net(sk);
	struct socket *sf;
	int err;

	err = sock_create_kern(net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sf);
	if (err)
		return err;

	lock_sock(sf->sk);
	err = tcp_set_ulp(sf->sk, "mptcp");
	release_sock(sf->sk);

	if (err)
		return err;

	subflow = mptcp_subflow_ctx(sf->sk);
	pr_debug("subflow=%p", subflow);

	*new_sock = sf;
	subflow->conn = sk;
	subflow->request_mptcp = 1; // @@ if MPTCP enabled
	subflow->request_version = 0; /* currently only v0 supported */

	return 0;
}

static struct mptcp_subflow_context *subflow_create_ctx(struct sock *sk,
							struct socket *sock)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct mptcp_subflow_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	pr_debug("subflow=%p", ctx);

	icsk->icsk_ulp_data = ctx;
	/* might be NULL */
	ctx->tcp_sock = sock;

	return ctx;
}

static int subflow_ulp_init(struct sock *sk)
{
	struct tcp_sock *tsk = tcp_sk(sk);
	struct mptcp_subflow_context *ctx;
	int err = 0;

	ctx = subflow_create_ctx(sk, sk->sk_socket);
	if (!ctx) {
		err = -ENOMEM;
		goto out;
	}

	pr_debug("subflow=%p", ctx);

	tsk->is_mptcp = 1;
out:
	return err;
}

static void subflow_ulp_release(struct sock *sk)
{
	struct mptcp_subflow_context *ctx = mptcp_subflow_ctx(sk);

	pr_debug("subflow=%p", ctx);

	kfree(ctx);
}

static struct tcp_ulp_ops subflow_ulp_ops __read_mostly = {
	.name		= "mptcp",
	.owner		= THIS_MODULE,
	.init		= subflow_ulp_init,
	.release	= subflow_ulp_release,
};

void mptcp_subflow_init(void)
{
	if (tcp_register_ulp(&subflow_ulp_ops) != 0)
		panic("MPTCP: failed to register subflows to ULP\n");
}
