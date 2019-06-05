// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018 Facebook
// Copyright (c) 2019 Cloudflare

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_rlimit.h"
#include "cgroup_helpers.h"

static int start_server(const struct sockaddr *addr, socklen_t len)
{
	int fd;

	fd = socket(addr->sa_family, SOCK_STREAM, 0);
	if (fd == -1) {
		log_err("Failed to create server socket");
		goto out;
	}

	if (bind(fd, addr, len) == -1) {
		log_err("Failed to bind server socket");
		goto close_out;
	}

	if (listen(fd, 128) == -1) {
		log_err("Failed to listen on server socket");
		goto close_out;
	}

	goto out;

close_out:
	close(fd);
	fd = -1;
out:
	return fd;
}

static int connect_to_server(const struct sockaddr *addr, socklen_t len)
{
	int fd = -1;

	fd = socket(addr->sa_family, SOCK_STREAM, 0);
	if (fd == -1) {
		log_err("Failed to create client socket");
		goto out;
	}

	if (connect(fd, addr, len) == -1) {
		log_err("Fail to connect to server");
		goto close_out;
	}

	goto out;

close_out:
	close(fd);
	fd = -1;
out:
	return fd;
}

static int run_test(int server_fd, const struct sockaddr *addr, socklen_t len)
{
	int client = -1, srv_client = -1;
	struct sockaddr_storage name;
	char buf[] = "testing";
	in_port_t port;
	int ret = 1;

	client = connect_to_server(addr, len);
	if (client == -1)
		goto out;

	srv_client = accept(server_fd, NULL, NULL);
	if (srv_client == -1) {
		log_err("Can't accept connection");
		goto out;
	}

	if (write(client, buf, sizeof(buf)) != sizeof(buf)) {
		log_err("Can't write on client");
		goto out;
	}

	if (read(srv_client, buf, sizeof(buf)) != sizeof(buf)) {
		log_err("Can't read on server");
		goto out;
	}

	len = sizeof(name);
	if (getsockname(srv_client, (struct sockaddr *)&name, &len)) {
		log_err("Can't getsockname");
		goto out;
	}

	switch (name.ss_family) {
	case AF_INET:
		port = ((struct sockaddr_in *)&name)->sin_port;
		break;

	case AF_INET6:
		port = ((struct sockaddr_in6 *)&name)->sin6_port;
		break;

	default:
		log_err("Invalid address family");
		goto out;
	}

	if (port != htons(4321)) {
		log_err("Expected port 4321, got %u", ntohs(port));
		goto out;
	}

	ret = 0;
out:
	close(client);
	close(srv_client);
	return ret;
}

int main(int argc, char **argv)
{
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	int server = -1;
	int server_v6 = -1;
	int err = 1;

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr4.sin_port = htons(1234);

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = in6addr_loopback;
	addr6.sin6_port = htons(1234);

	server = start_server((const struct sockaddr *)&addr4, sizeof(addr4));
	if (server == -1)
		goto out;

	server_v6 = start_server((const struct sockaddr *)&addr6,
				 sizeof(addr6));
	if (server_v6 == -1)
		goto out;

	/* Connect to unbound ports */
	addr4.sin_port = htons(4321);
	addr6.sin6_port = htons(4321);

	if (run_test(server, (const struct sockaddr *)&addr4, sizeof(addr4)))
		goto out;

	if (run_test(server_v6, (const struct sockaddr *)&addr6, sizeof(addr6)))
		goto out;

	printf("ok\n");
	err = 0;
out:
	close(server);
	close(server_v6);
	return err;
}
