// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/select.h>
#include <signal.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static volatile sig_atomic_t linux_ssh_stop_requested;

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <client|copy|tunnel|socks> [options]\n"
		"  client <host> [--port <tcp-port>]\n"
		"  copy <host> --local-path <path> --remote-path <path> [--port <tcp-port>] [--recursive]\n"
		"  tunnel <host> [--port <tcp-port>]\n"
		"  socks <host> --remote-host <host> --remote-port <tcp-port> --local-port <tcp-port> [--port <tcp-port>]\n"
		"\n"
		"client: connect and authenticate to an SSH server\n"
		"copy: upload a file or directory to the SSH server using SFTP\n"
		"tunnel: create a reverse SSH tunnel that forwards the remote listener back to 127.0.0.1:22\n"
		"socks: listen on a local TCP port and forward each accepted connection to a fixed remote host:port over SSH\n",
		prog);
}

static void linux_ssh_sigint_handler(int signum)
{
	(void)signum;
	linux_ssh_stop_requested = 1;
}

static const char *linux_ssh_default_user(void)
{
	const char *user = getenv("USER");
	struct passwd *pw;

	if (user && *user)
		return user;
	pw = getpwuid(getuid());
	return (pw && pw->pw_name && *pw->pw_name) ? pw->pw_name : "root";
}

static int linux_ssh_connect_session(const char *host, uint16_t port, ssh_session *session_out)
{
	ssh_session session;
	const char *user;
	unsigned int port_ui;
	int auth_rc;

	if (!host || !*host || !session_out)
		return -1;

	session = ssh_new();
	if (!session) {
		fprintf(stderr, "ssh: failed to allocate session\n");
		return -1;
	}

	user = linux_ssh_default_user();
	port_ui = port;
	ssh_options_set(session, SSH_OPTIONS_HOST, host);
	ssh_options_set(session, SSH_OPTIONS_PORT, &port_ui);
	ssh_options_set(session, SSH_OPTIONS_USER, user);

	if (ssh_connect(session) != SSH_OK) {
		fprintf(stderr, "ssh: connect to %s:%u failed: %s\n",
			host, (unsigned int)port, ssh_get_error(session));
		ssh_free(session);
		return -1;
	}

	auth_rc = ssh_userauth_publickey_auto(session, NULL, NULL);
	if (auth_rc != SSH_AUTH_SUCCESS) {
		auth_rc = ssh_userauth_none(session, NULL);
	}
	if (auth_rc != SSH_AUTH_SUCCESS) {
		fprintf(stderr, "ssh: authentication failed for %s@%s:%u: %s\n",
			user, host, (unsigned int)port, ssh_get_error(session));
		ssh_disconnect(session);
		ssh_free(session);
		return -1;
	}

	*session_out = session;
	return 0;
}

static int linux_ssh_ensure_remote_dir(sftp_session sftp, const char *dir)
{
	char tmp[PATH_MAX];
	char *p;

	if (!dir || !*dir)
		return 0;
	if (strlen(dir) >= sizeof(tmp))
		return -1;
	snprintf(tmp, sizeof(tmp), "%s", dir);

	for (p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (sftp_mkdir(sftp, tmp, 0755) < 0 && sftp_get_error(sftp) != SSH_FX_FILE_ALREADY_EXISTS) {
			fprintf(stderr, "ssh copy: failed to create remote directory %s\n", tmp);
			return -1;
		}
		*p = '/';
	}
	if (sftp_mkdir(sftp, tmp, 0755) < 0 && sftp_get_error(sftp) != SSH_FX_FILE_ALREADY_EXISTS)
		return 0;
	return 0;
}

static int linux_ssh_parent_dir(const char *path, char *out, size_t out_sz)
{
	const char *slash;
	size_t len;

	if (!path || !*path || !out || out_sz < 2)
		return -1;
	slash = strrchr(path, '/');
	if (!slash) {
		snprintf(out, out_sz, ".");
		return 0;
	}
	len = (size_t)(slash - path);
	if (len == 0) {
		snprintf(out, out_sz, "/");
		return 0;
	}
	if (len + 1 > out_sz)
		return -1;
	memcpy(out, path, len);
	out[len] = '\0';
	return 0;
}

static int linux_ssh_copy_file(sftp_session sftp, const char *local_path, const char *remote_path)
{
	char parent[PATH_MAX];
	int fd;
	sftp_file remote;
	char buf[4096];

	if (linux_ssh_parent_dir(remote_path, parent, sizeof(parent)) == 0) {
		if (linux_ssh_ensure_remote_dir(sftp, parent) != 0)
			return -1;
	}

	fd = open(local_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "ssh copy: cannot open %s: %s\n", local_path, strerror(errno));
		return -1;
	}

	remote = sftp_open(sftp, remote_path, SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC, 0644);
	if (!remote) {
		fprintf(stderr, "ssh copy: cannot open remote file %s: %s\n", remote_path, ssh_get_error(sftp));
		close(fd);
		return -1;
	}

	for (;;) {
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			fprintf(stderr, "ssh copy: read failure on %s: %s\n", local_path, strerror(errno));
			sftp_close(remote);
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		if (sftp_write(remote, buf, (size_t)n) != n) {
			fprintf(stderr, "ssh copy: write failure for %s\n", remote_path);
			sftp_close(remote);
			close(fd);
			return -1;
		}
	}

	sftp_close(remote);
	close(fd);
	return 0;
}

static int linux_ssh_copy_path(sftp_session sftp,
			       const char *local_path,
			       const char *remote_path,
			       bool recursive)
{
	struct stat st;

	if (lstat(local_path, &st) != 0) {
		fprintf(stderr, "ssh copy: cannot stat %s: %s\n", local_path, strerror(errno));
		return -1;
	}

	if (S_ISDIR(st.st_mode)) {
		DIR *dir;
		struct dirent *de;
		if (!recursive) {
			fprintf(stderr, "ssh copy: directory upload requires --recursive\n");
			return -1;
		}
		if (linux_ssh_ensure_remote_dir(sftp, remote_path) != 0)
			return -1;
		dir = opendir(local_path);
		if (!dir)
			return -1;
		while ((de = readdir(dir)) != NULL) {
			char child_local[PATH_MAX];
			char child_remote[PATH_MAX];
			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;
			snprintf(child_local, sizeof(child_local), "%s/%s", local_path, de->d_name);
			snprintf(child_remote, sizeof(child_remote), "%s/%s", remote_path, de->d_name);
			if (linux_ssh_copy_path(sftp, child_local, child_remote, recursive) != 0) {
				closedir(dir);
				return -1;
			}
		}
		closedir(dir);
		return 0;
	}

	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "ssh copy: unsupported file type for %s\n", local_path);
		return -1;
	}

	return linux_ssh_copy_file(sftp, local_path, remote_path);
}

static int linux_ssh_write_all_fd(int fd, const char *what, const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;

	while (len > 0) {
		ssize_t written = write(fd, p, len);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "ssh socks: failed writing %s: %s\n", what, strerror(errno));
			return -1;
		}
		p += (size_t)written;
		len -= (size_t)written;
	}

	return 0;
}

static int linux_ssh_write_all_channel(ssh_channel channel, const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;

	while (len > 0) {
		int written = ssh_channel_write(channel, p, len);
		if (written == SSH_ERROR) {
			fprintf(stderr, "ssh socks: failed writing SSH channel: %s\n",
				ssh_get_error(ssh_channel_get_session(channel)));
			return -1;
		}
		if (written <= 0)
			return -1;
		p += (size_t)written;
		len -= (size_t)written;
	}

	return 0;
}

static int linux_ssh_create_listener(uint16_t local_port)
{
	int listen_fd;
	int one = 1;
	struct sockaddr_in addr;

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		fprintf(stderr, "ssh socks: socket failed: %s\n", strerror(errno));
		return -1;
	}

	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
		fprintf(stderr, "ssh socks: setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno));
		close(listen_fd);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(local_port);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		fprintf(stderr, "ssh socks: bind to 127.0.0.1:%u failed: %s\n",
			(unsigned int)local_port, strerror(errno));
		close(listen_fd);
		return -1;
	}

	if (listen(listen_fd, 16) != 0) {
		fprintf(stderr, "ssh socks: listen failed: %s\n", strerror(errno));
		close(listen_fd);
		return -1;
	}

	return listen_fd;
}

static int linux_ssh_bridge_client_to_remote(ssh_channel channel, int client_fd)
{
	char buf[4096];
	ssize_t nread;

	nread = read(client_fd, buf, sizeof(buf));
	if (nread < 0) {
		if (errno == EINTR)
			return 0;
		fprintf(stderr, "ssh socks: client read failed: %s\n", strerror(errno));
		return -1;
	}

	if (nread == 0) {
		ssh_channel_send_eof(channel);
		return 1;
	}

	if (linux_ssh_write_all_channel(channel, buf, (size_t)nread) != 0)
		return -1;

	return 0;
}

static int linux_ssh_bridge_remote_to_client(ssh_channel channel, int client_fd)
{
	char buf[4096];
	int nread;

	for (;;) {
		nread = ssh_channel_read_nonblocking(channel, buf, sizeof(buf), 0);
		if (nread == SSH_ERROR) {
			fprintf(stderr, "ssh socks: SSH channel read failed: %s\n",
				ssh_get_error(ssh_channel_get_session(channel)));
			return -1;
		}
		if (nread <= 0)
			return 0;
		if (linux_ssh_write_all_fd(client_fd, "client socket", buf, (size_t)nread) != 0)
			return -1;
	}
}

static int linux_ssh_bridge_connection(ssh_session session,
				       int client_fd,
				       const char *remote_host,
				       uint16_t remote_port,
				       uint16_t local_port)
{
	ssh_channel channel;
	fd_set rfds;
	struct timeval tv;
	int select_rc;
	int forward_rc;
	int client_done = 0;
	int remote_done = 0;

	channel = ssh_channel_new(session);
	if (!channel) {
		fprintf(stderr, "ssh socks: failed to allocate SSH channel\n");
		return -1;
	}

	forward_rc = ssh_channel_open_forward(channel,
					      remote_host,
					      remote_port,
					      "127.0.0.1",
					      local_port);
	if (forward_rc != SSH_OK) {
		fprintf(stderr, "ssh socks: failed to open SSH forward to %s:%u: %s\n",
			remote_host, (unsigned int)remote_port, ssh_get_error(session));
		ssh_channel_free(channel);
		return -1;
	}

	while (!linux_ssh_stop_requested && !remote_done) {
		FD_ZERO(&rfds);
		if (!client_done)
			FD_SET(client_fd, &rfds);
		tv.tv_sec = 0;
		tv.tv_usec = 200000;
		select_rc = select(client_fd + 1, &rfds, NULL, NULL, &tv);
		if (select_rc < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "ssh socks: select failed: %s\n", strerror(errno));
			ssh_channel_close(channel);
			ssh_channel_free(channel);
			return -1;
		}

		if (!client_done && select_rc > 0 && FD_ISSET(client_fd, &rfds)) {
			int bridge_rc = linux_ssh_bridge_client_to_remote(channel, client_fd);
			if (bridge_rc < 0) {
				ssh_channel_close(channel);
				ssh_channel_free(channel);
				return -1;
			}
			if (bridge_rc > 0)
				client_done = 1;
		}

		if (linux_ssh_bridge_remote_to_client(channel, client_fd) != 0) {
			ssh_channel_close(channel);
			ssh_channel_free(channel);
			return -1;
		}

		if (ssh_channel_is_eof(channel) || ssh_channel_is_closed(channel))
			remote_done = 1;
	}

	ssh_channel_close(channel);
	ssh_channel_free(channel);
	return 0;
}

static int linux_ssh_socks_main(int argc, char **argv)
{
	uint16_t port = 22;
	uint16_t remote_port = 0;
	uint16_t local_port = 0;
	const char *host = NULL;
	const char *remote_host = NULL;
	int listen_fd = -1;
	int opt;
	ssh_session session;
	struct sigaction sa;
	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "port", required_argument, NULL, 'p' },
		{ "remote-host", required_argument, NULL, 'r' },
		{ "remote-port", required_argument, NULL, 't' },
		{ "local-port", required_argument, NULL, 'l' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hp:r:t:l:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'p':
			port = (uint16_t)strtoul(optarg, NULL, 10);
			break;
		case 'r':
			remote_host = optarg;
			break;
		case 't':
			remote_port = (uint16_t)strtoul(optarg, NULL, 10);
			break;
		case 'l':
			local_port = (uint16_t)strtoul(optarg, NULL, 10);
			break;
		default:
			return 2;
		}
	}

	if (optind >= argc || !remote_host || remote_port == 0 || local_port == 0)
		return 2;

	host = argv[optind];
	if (optind + 1 != argc)
		return 2;

	if (linux_ssh_connect_session(host, port, &session) != 0)
		return 1;

	listen_fd = linux_ssh_create_listener(local_port);
	if (listen_fd < 0) {
		ssh_disconnect(session);
		ssh_free(session);
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = linux_ssh_sigint_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	printf("ssh socks listening on 127.0.0.1:%u and forwarding to %s via %s:%u -> %s:%u; press Ctrl+C to stop\n",
	       (unsigned int)local_port,
	       remote_host,
	       host,
	       (unsigned int)port,
	       remote_host,
	       (unsigned int)remote_port);

	while (!linux_ssh_stop_requested) {
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);

		if (client_fd < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "ssh socks: accept failed: %s\n", strerror(errno));
			close(listen_fd);
			ssh_disconnect(session);
			ssh_free(session);
			return 1;
		}

		if (linux_ssh_bridge_connection(session, client_fd, remote_host, remote_port, local_port) != 0) {
			close(client_fd);
			close(listen_fd);
			ssh_disconnect(session);
			ssh_free(session);
			return 1;
		}

		close(client_fd);
	}

	close(listen_fd);
	ssh_disconnect(session);
	ssh_free(session);
	return 0;
}

static int linux_ssh_client_main(int argc, char **argv)
{
	uint16_t port = 22;
	const char *host = NULL;
	int opt;
	ssh_session session;
	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "port", required_argument, NULL, 'p' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hp:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h': usage(argv[0]); return 0;
		case 'p': port = (uint16_t)strtoul(optarg, NULL, 10); break;
		default: return 2;
		}
	}
	if (optind >= argc)
		return 2;
	host = argv[optind];
	if (optind + 1 != argc)
		return 2;
	if (linux_ssh_connect_session(host, port, &session) != 0)
		return 1;
	printf("ssh client connected to %s:%u\n", host, (unsigned int)port);
	ssh_disconnect(session);
	ssh_free(session);
	return 0;
}

static int linux_ssh_copy_main(int argc, char **argv)
{
	uint16_t port = 22;
	const char *host = NULL;
	const char *local_path = NULL;
	const char *remote_path = NULL;
	bool recursive = false;
	int opt;
	ssh_session session;
	sftp_session sftp;
	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "port", required_argument, NULL, 'p' },
		{ "local-path", required_argument, NULL, 'l' },
		{ "remote-path", required_argument, NULL, 'o' },
		{ "recursive", no_argument, NULL, 'r' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hp:l:o:r", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h': usage(argv[0]); return 0;
		case 'p': port = (uint16_t)strtoul(optarg, NULL, 10); break;
		case 'l': local_path = optarg; break;
		case 'o': remote_path = optarg; break;
		case 'r': recursive = true; break;
		default: return 2;
		}
	}
	if (optind >= argc || !local_path || !remote_path)
		return 2;
	host = argv[optind];
	if (optind + 1 != argc)
		return 2;
	if (linux_ssh_connect_session(host, port, &session) != 0)
		return 1;
	sftp = sftp_new(session);
	if (!sftp || sftp_init(sftp) != SSH_OK) {
		fprintf(stderr, "ssh copy: failed to initialize sftp\n");
		if (sftp)
			sftp_free(sftp);
		ssh_disconnect(session);
		ssh_free(session);
		return 1;
	}
	if (linux_ssh_copy_path(sftp, local_path, remote_path, recursive) != 0) {
		sftp_free(sftp);
		ssh_disconnect(session);
		ssh_free(session);
		return 1;
	}
	printf("ssh copy uploaded %s -> %s:%s\n", local_path, host, remote_path);
	sftp_free(sftp);
	ssh_disconnect(session);
	ssh_free(session);
	return 0;
}

static int linux_ssh_tunnel_main(int argc, char **argv)
{
	uint16_t port = 22;
	const char *host = NULL;
	int bound_port = 0;
	int opt;
	ssh_session session;
	struct sigaction sa;
	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "port", required_argument, NULL, 'p' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hp:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h': usage(argv[0]); return 0;
		case 'p': port = (uint16_t)strtoul(optarg, NULL, 10); break;
		default: return 2;
		}
	}
	if (optind >= argc)
		return 2;
	host = argv[optind];
	if (optind + 1 != argc)
		return 2;
	if (linux_ssh_connect_session(host, port, &session) != 0)
		return 1;
	if (ssh_channel_listen_forward(session, NULL, 0, &bound_port) != SSH_OK) {
		fprintf(stderr, "ssh tunnel: failed to create reverse tunnel: %s\n", ssh_get_error(session));
		ssh_disconnect(session);
		ssh_free(session);
		return 1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = linux_ssh_sigint_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	printf("ssh tunnel listening on remote port %d and forwarding to 127.0.0.1:22; press Ctrl+C to stop\n", bound_port);
	while (!linux_ssh_stop_requested)
		sleep(1);
	ssh_channel_cancel_forward(session, NULL, bound_port);
	ssh_disconnect(session);
	ssh_free(session);
	return 0;
}

int linux_ssh_scan_main(int argc, char **argv)
{
	if (argc >= 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "help"))) {
		usage(argv[0]);
		return 0;
	}

	if (argc < 2) {
		usage(argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "client"))
		return linux_ssh_client_main(argc - 1, argv + 1);
	if (!strcmp(argv[1], "copy"))
		return linux_ssh_copy_main(argc - 1, argv + 1);
	if (!strcmp(argv[1], "tunnel"))
		return linux_ssh_tunnel_main(argc - 1, argv + 1);
	if (!strcmp(argv[1], "socks"))
		return linux_ssh_socks_main(argc - 1, argv + 1);
	usage(argv[0]);
	return 2;
}
