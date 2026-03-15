// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "http_client.h"
#include "api_key.h"
#include "tcp_util.h"
#include "../util/str_util.h"
#include "../util/isa_util.h"
#include "../embedded_linux_audit_cmd.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <curl/curl.h>

#ifdef ELA_HAS_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#endif
#ifdef SHA256
#undef SHA256
#endif
#ifdef SHA224
#undef SHA224
#endif
#ifdef SHA384
#undef SHA384
#endif
#ifdef SHA512
#undef SHA512
#endif
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#ifdef __linux__
#include <linux/if_arp.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int parse_status_code_from_headers(const char *headers);

int parse_http_uri(const char *uri, struct parsed_http_uri *parsed)
{
	const char *scheme_end;
	const char *authority;
	const char *authority_end;
	const char *host_start;
	const char *host_end;
	const char *path_start;
	const char *at;
	const char *port_sep = NULL;
	char port_buf[8];
	size_t host_len;
	size_t path_len;

	if (!uri || !parsed)
		return -1;

	memset(parsed, 0, sizeof(*parsed));
	scheme_end = strstr(uri, "://");
	if (!scheme_end)
		return -1;

	if ((size_t)(scheme_end - uri) == 4 && !strncmp(uri, "http", 4)) {
		parsed->https = false;
		parsed->port = 80;
	} else if ((size_t)(scheme_end - uri) == 5 && !strncmp(uri, "https", 5)) {
		parsed->https = true;
		parsed->port = 443;
	} else {
		return -1;
	}

	authority = scheme_end + 3;
	authority_end = authority;
	while (*authority_end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#')
		authority_end++;
	path_start = authority_end;

	at = memchr(authority, '@', (size_t)(authority_end - authority));
	host_start = at ? (at + 1) : authority;
	if (host_start >= authority_end)
		return -1;

	if (*host_start == '[')
		return -1;

	host_end = host_start;
	while (host_end < authority_end && *host_end != ':')
		host_end++;
	if (host_end < authority_end && *host_end == ':')
		port_sep = host_end;

	host_len = (size_t)(host_end - host_start);
	if (!host_len || host_len >= sizeof(parsed->host))
		return -1;
	memcpy(parsed->host, host_start, host_len);
	parsed->host[host_len] = '\0';

	if (port_sep) {
		char *end;
		unsigned long port_ul;
		size_t port_len = (size_t)(authority_end - (port_sep + 1));
		if (!port_len || port_len >= sizeof(port_buf))
			return -1;
		memcpy(port_buf, port_sep + 1, port_len);
		port_buf[port_len] = '\0';
		errno = 0;
		port_ul = strtoul(port_buf, &end, 10);
		if (errno || !end || *end || port_ul == 0 || port_ul > 65535)
			return -1;
		parsed->port = (uint16_t)port_ul;
	}

	if (!*path_start) {
		parsed->path[0] = '/';
		parsed->path[1] = '\0';
		return 0;
	}

	path_len = strlen(path_start);
	if (path_len >= sizeof(parsed->path))
		return -1;
	memcpy(parsed->path, path_start, path_len + 1);
	return 0;
}

static int ssl_ctx_add_embedded_ca_store(X509_STORE *store, char *errbuf, size_t errbuf_len)
{
	BIO *bio;
	bool loaded_any = false;

	if (!store) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to access OpenSSL certificate store");
		return -1;
	}

	if (ela_default_ca_bundle_pem_len == 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "embedded CA bundle is empty");
		return -1;
	}

	bio = BIO_new_mem_buf((const void *)ela_default_ca_bundle_pem,
			     (int)ela_default_ca_bundle_pem_len);
	if (!bio) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to create OpenSSL BIO for embedded CA bundle");
		return -1;
	}

	for (;;) {
		X509 *cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
		if (!cert)
			break;
		loaded_any = true;
		if (X509_STORE_add_cert(store, cert) != 1) {
			unsigned long ssl_err = ERR_peek_last_error();
			if (ERR_GET_REASON(ssl_err) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
				if (errbuf && errbuf_len)
					snprintf(errbuf, errbuf_len, "failed to add embedded CA certificate to OpenSSL store");
				X509_free(cert);
				BIO_free(bio);
				return -1;
			}
			ERR_clear_error();
		}
		X509_free(cert);
	}

	BIO_free(bio);
	if (!loaded_any) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "embedded CA bundle did not contain any readable certificates");
		ERR_clear_error();
		return -1;
	}

	ERR_clear_error();
	return 0;
}

static int read_http_status_and_headers(int sock, int *status_out)
{
	char headers[8192];
	size_t used = 0;
	char *line_end;
	char *status_line_end;

	if (!status_out)
		return -1;

	for (;;) {
		ssize_t n;

		if (used >= sizeof(headers) - 1)
			return -1;
		n = recv(sock, headers + used, sizeof(headers) - 1 - used, MSG_PEEK);
		if (n <= 0)
			return -1;
		used += (size_t)n;
		headers[used] = '\0';
		line_end = strstr(headers, "\r\n\r\n");
		if (line_end)
			break;
		if (used == sizeof(headers) - 1)
			return -1;
		if (recv(sock, headers, (size_t)n, 0) != n)
			return -1;
		used = 0;
	}

	status_line_end = strstr(headers, "\r\n");
	if (!status_line_end)
		return -1;
	*status_line_end = '\0';
	if (sscanf(headers, "HTTP/%*u.%*u %d", status_out) != 1)
		return -1;

	used = (size_t)((line_end + 4) - headers);
	while (used) {
		ssize_t n = recv(sock, headers, used, 0);
		if (n <= 0)
			return -1;
		used -= (size_t)n;
	}

	return 0;
}

static int simple_http_post(const char *uri,
			    const uint8_t *data,
			    size_t len,
			    const char *content_type,
			    const char *auth_key,
			    bool verbose,
			    char *errbuf,
			    size_t errbuf_len,
			    int *status_out)
{
	struct parsed_http_uri parsed;
	char *request = NULL;
	size_t request_len = 0;
	size_t request_cap = 0;
	char content_len_buf[32];
	int sock;
	int status_code;

	if (status_out)
		*status_out = 0;

	if (parse_http_uri(uri, &parsed) != 0 || parsed.https) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "unsupported or invalid HTTP URI");
		return -1;
	}

	sock = connect_tcp_host_port(parsed.host, parsed.port);
	if (sock < 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to connect to %s:%u", parsed.host, (unsigned int)parsed.port);
		return -1;
	}

	snprintf(content_len_buf, sizeof(content_len_buf), "%zu", len);
	if (append_text(&request, &request_len, &request_cap, "POST ") != 0 ||
	    append_text(&request, &request_len, &request_cap, parsed.path) != 0 ||
	    append_text(&request, &request_len, &request_cap, " HTTP/1.1\r\nHost: ") != 0 ||
	    append_text(&request, &request_len, &request_cap, parsed.host) != 0 ||
	    append_text(&request, &request_len, &request_cap, "\r\nConnection: close\r\nContent-Type: ") != 0 ||
	    append_text(&request, &request_len, &request_cap, content_type) != 0 ||
	    append_text(&request, &request_len, &request_cap, "\r\nContent-Length: ") != 0 ||
	    append_text(&request, &request_len, &request_cap, content_len_buf) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build HTTP request");
		free(request);
		close(sock);
		return -1;
	}

	if (auth_key && *auth_key) {
		if (append_text(&request, &request_len, &request_cap, "\r\nAuthorization: Bearer ") != 0 ||
		    append_text(&request, &request_len, &request_cap, auth_key) != 0) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "failed to build HTTP request");
			free(request);
			close(sock);
			return -1;
		}
	}

	if (append_text(&request, &request_len, &request_cap, "\r\n\r\n") != 0 ||
	    append_bytes(&request, &request_len, &request_cap, (const char *)data, len) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build HTTP request");
		free(request);
		close(sock);
		return -1;
	}

	if (verbose) {
		fprintf(stderr, "HTTP POST request uri=%s bytes=%zu content-type=%s insecure=false (socket)\n",
			uri, len, content_type);
	}

	if (ela_send_all(sock, (const uint8_t *)request, request_len) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to send HTTP request");
		free(request);
		close(sock);
		return -1;
	}
	free(request);

	if (read_http_status_and_headers(sock, &status_code) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to read HTTP response");
		close(sock);
		return -1;
	}
	close(sock);

	if (status_out)
		*status_out = status_code;

	if (status_code < 200 || status_code >= 300) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP status %d", status_code);
		if (verbose)
			fprintf(stderr, "HTTP POST response failure uri=%s status=%d\n", uri, status_code);
		return -1;
	}

	if (verbose)
		fprintf(stderr, "HTTP POST success uri=%s status=%d\n", uri, status_code);

	return 0;
}

static int simple_http_get_to_file(const char *uri,
				   const char *output_path,
				   bool verbose,
				   char *errbuf,
				   size_t errbuf_len)
{
	struct parsed_http_uri parsed;
	char *request = NULL;
	size_t request_len = 0;
	size_t request_cap = 0;
	FILE *fp = NULL;
	int sock = -1;
	int status_code;
	char buf[4096];

	if (parse_http_uri(uri, &parsed) != 0 || parsed.https) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "unsupported or invalid HTTP URI");
		return -1;
	}

	sock = connect_tcp_host_port(parsed.host, parsed.port);
	if (sock < 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to connect to %s:%u", parsed.host, (unsigned int)parsed.port);
		return -1;
	}

	fp = fopen(output_path, "wb");
	if (!fp) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "cannot open output file %s: %s", output_path, strerror(errno));
		close(sock);
		return -1;
	}

	if (append_text(&request, &request_len, &request_cap, "GET ") != 0 ||
	    append_text(&request, &request_len, &request_cap, parsed.path) != 0 ||
	    append_text(&request, &request_len, &request_cap, " HTTP/1.1\r\nHost: ") != 0 ||
	    append_text(&request, &request_len, &request_cap, parsed.host) != 0 ||
	    append_text(&request, &request_len, &request_cap, "\r\nConnection: close\r\n\r\n") != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build HTTP request");
		goto fail;
	}

	if (verbose)
		fprintf(stderr, "HTTP GET request uri=%s -> file=%s insecure=false (socket)\n", uri, output_path);

	if (ela_send_all(sock, (const uint8_t *)request, request_len) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to send HTTP request");
		goto fail;
	}
	free(request);
	request = NULL;

	if (read_http_status_and_headers(sock, &status_code) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to read HTTP response");
		goto fail;
	}

	if (status_code < 200 || status_code >= 300) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP status %d", status_code);
		if (verbose)
			fprintf(stderr, "HTTP GET response failure uri=%s status=%d\n", uri, status_code);
		goto fail;
	}

	for (;;) {
		ssize_t n = recv(sock, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "failed while reading HTTP response body");
			goto fail;
		}
		if (n == 0)
			break;
		if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "failed writing to output file %s", output_path);
			goto fail;
		}
	}

	if (fclose(fp) != 0) {
		fp = NULL;
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to finalize output file %s", output_path);
		goto fail;
	}
	fp = NULL;
	close(sock);

	if (verbose)
		fprintf(stderr, "HTTP GET success uri=%s status=%d\n", uri, status_code);

	return 0;

fail:
	if (request)
		free(request);
	if (fp)
		fclose(fp);
	if (sock >= 0)
		close(sock);
	unlink(output_path);
	return -1;
}

#ifdef ELA_HAS_WOLFSSL
static int wolfssl_read_headers(WOLFSSL *ssl, char **headers_out)
{
	char *headers = NULL;
	size_t len = 0, cap = 0;
	char ch;

	while (1) {
		int n = wolfSSL_read(ssl, &ch, 1);
		if (n <= 0)
			goto fail;
		if (append_bytes(&headers, &len, &cap, &ch, 1) != 0)
			goto fail;
		if (len >= 4 && !memcmp(headers + len - 4, "\r\n\r\n", 4))
			break;
	}
	*headers_out = headers;
	return 0;
fail:
	free(headers);
	return -1;
}

static int wolfssl_copy_response_body_to_file(WOLFSSL *ssl, FILE *fp)
{
	char buf[4096];
	for (;;) {
		int n = wolfSSL_read(ssl, buf, sizeof(buf));
		if (n == 0)
			break;
		if (n < 0)
			return -1;
		if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n)
			return -1;
	}
	return 0;
}

static int simple_wolfssl_https_get_to_file(const struct parsed_http_uri *parsed,
					    const char *uri,
					    const char *output_path,
					    bool insecure,
					    bool verbose,
					    char *errbuf,
					    size_t errbuf_len)
{
	WOLFSSL_CTX *ctx = NULL;
	WOLFSSL *ssl = NULL;
	int sock = -1;
	FILE *fp = NULL;
	char *headers = NULL, *request = NULL;
	size_t request_len = 0, request_cap = 0;
	int status;
	int rc;

	ela_set_sigill_stage("https:wolfssl_init");
	if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_Init failed");
		goto cleanup;
	}

	ela_set_sigill_stage("https:wolfssl_ctx_new");
	ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	if (!ctx) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_CTX_new failed");
		goto cleanup;
	}
	wolfSSL_CTX_set_verify(ctx, insecure ? WOLFSSL_VERIFY_NONE : WOLFSSL_VERIFY_PEER, NULL);
	if (!insecure) {
		ela_set_sigill_stage("https:wolfssl_load_ca");
		if (wolfSSL_CTX_load_verify_buffer(ctx,
				(const unsigned char *)ela_default_ca_bundle_pem,
				(long)ela_default_ca_bundle_pem_len,
				WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "wolfSSL_CTX_load_verify_buffer failed");
			goto cleanup;
		}
	}

	ela_set_sigill_stage("https:wolfssl_tcp_connect");
	sock = connect_tcp_host_port_any(parsed->host, parsed->port);
	if (sock < 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to connect to %s:%u", parsed->host, (unsigned int)parsed->port);
		goto cleanup;
	}

	ela_set_sigill_stage("https:wolfssl_new");
	ssl = wolfSSL_new(ctx);
	if (!ssl) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_new failed");
		goto cleanup;
	}
	if (wolfSSL_set_fd(ssl, sock) != WOLFSSL_SUCCESS) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_set_fd failed");
		goto cleanup;
	}
	if (!insecure)
		wolfSSL_check_domain_name(ssl, parsed->host);

	ela_set_sigill_stage("https:wolfssl_connect");
	while ((rc = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
		int err = wolfSSL_get_error(ssl, rc);
		if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE &&
		    err != WANT_READ && err != WANT_WRITE) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "wolfSSL_connect failed: %d", err);
			goto cleanup;
		}
	}

	fp = fopen(output_path, "wb");
	if (!fp) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "cannot open output file %s: %s", output_path, strerror(errno));
		goto cleanup;
	}

	if (append_text(&request, &request_len, &request_cap, "GET ") != 0 ||
	    append_text(&request, &request_len, &request_cap, parsed->path) != 0 ||
	    append_text(&request, &request_len, &request_cap, " HTTP/1.1\r\nHost: ") != 0 ||
	    append_text(&request, &request_len, &request_cap, parsed->host) != 0 ||
	    append_text(&request, &request_len, &request_cap, "\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n") != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build HTTPS request");
		goto cleanup;
	}

	if (verbose)
		fprintf(stderr, "HTTPS GET request uri=%s -> file=%s insecure=%s (wolfssl)\n",
			uri, output_path, insecure ? "true" : "false");

	ela_set_sigill_stage("https:wolfssl_write_request");
	if ((rc = wolfSSL_write(ssl, request, (int)request_len)) <= 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_write failed: %d", wolfSSL_get_error(ssl, rc));
		goto cleanup;
	}

	ela_set_sigill_stage("https:wolfssl_read_headers");
	if (wolfssl_read_headers(ssl, &headers) != 0)
		goto cleanup;
	status = parse_status_code_from_headers(headers);
	if (status < 200 || status >= 300) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP status %d", status);
		goto cleanup;
	}

	ela_set_sigill_stage("https:wolfssl_read_body");
	if (wolfssl_copy_response_body_to_file(ssl, fp) != 0)
		goto cleanup;

	free(headers);
	free(request);
	wolfSSL_shutdown(ssl);
	wolfSSL_free(ssl);
	wolfSSL_CTX_free(ctx);
	if (sock >= 0)
		close(sock);
	if (fclose(fp) != 0) {
		unlink(output_path);
		return -1;
	}
	return 0;

cleanup:
	free(headers);
	free(request);
	if (fp)
		fclose(fp);
	unlink(output_path);
	if (ssl) {
		wolfSSL_shutdown(ssl);
		wolfSSL_free(ssl);
	}
	if (ctx)
		wolfSSL_CTX_free(ctx);
	if (sock >= 0)
		close(sock);
	return -1;
}
#endif

static int parse_status_code_from_headers(const char *headers)
{
	int status = 0;
	if (!headers)
		return -1;
	if (sscanf(headers, "HTTP/%*u.%*u %d", &status) != 1)
		return -1;
	return status;
}

static bool headers_have_chunked_encoding(const char *headers)
{
	return headers && strstr(headers, "\nTransfer-Encoding: chunked\r") != NULL;
}

static int ssl_readline(SSL *ssl, char *buf, size_t buf_sz)
{
	size_t len = 0;
	char ch;
	if (!buf || buf_sz < 2)
		return -1;
	while (len + 1 < buf_sz) {
		int n = SSL_read(ssl, &ch, 1);
		if (n <= 0)
			return -1;
		buf[len++] = ch;
		if (ch == '\n')
			break;
	}
	buf[len] = '\0';
	return (int)len;
}

static int ssl_copy_response_body_to_file(SSL *ssl, const char *headers, FILE *fp)
{
	char buf[4096];
	if (headers_have_chunked_encoding(headers)) {
		for (;;) {
			char line[128];
			unsigned long chunk_len;
			char *end;
			if (ssl_readline(ssl, line, sizeof(line)) < 0)
				return -1;
			chunk_len = strtoul(line, &end, 16);
			if (end == line)
				return -1;
			if (chunk_len == 0) {
				if (ssl_readline(ssl, line, sizeof(line)) < 0)
					return -1;
				break;
			}
			while (chunk_len) {
				int want = (int)(chunk_len > sizeof(buf) ? sizeof(buf) : chunk_len);
				int n = SSL_read(ssl, buf, want);
				if (n <= 0)
					return -1;
				if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n)
					return -1;
				chunk_len -= (unsigned long)n;
			}
			if (SSL_read(ssl, buf, 2) != 2)
				return -1;
		}
		return 0;
	}

	for (;;) {
		int n = SSL_read(ssl, buf, sizeof(buf));
		if (n < 0)
			return -1;
		if (n == 0)
			break;
		if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n)
			return -1;
	}
	return 0;
}

static int ssl_read_headers(SSL *ssl, char **headers_out)
{
	char *headers = NULL;
	size_t len = 0;
	size_t cap = 0;
	char ch;

	while (1) {
		int n = SSL_read(ssl, &ch, 1);
		if (n <= 0)
			goto fail;
		if (append_bytes(&headers, &len, &cap, &ch, 1) != 0)
			goto fail;
		if (len >= 4 && !memcmp(headers + len - 4, "\r\n\r\n", 4))
			break;
	}

	*headers_out = headers;
	return 0;

fail:
	free(headers);
	return -1;
}

static int ssl_write_all(SSL *ssl, const uint8_t *buf, size_t len)
{
	while (len) {
		int n = SSL_write(ssl, buf, (int)len);
		if (n <= 0)
			return -1;
		buf += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

static int ssl_connect_with_embedded_ca(const struct parsed_http_uri *parsed,
					 bool insecure,
					 SSL_CTX **ctx_out,
					 SSL **ssl_out,
					 int *sock_out,
					 char *errbuf,
					 size_t errbuf_len)
{
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	X509_VERIFY_PARAM *vpm;
	int sock = -1;

	if (!parsed || !ctx_out || !ssl_out || !sock_out)
		return -1;

	ela_install_sigill_debug_handler();
	ela_set_sigill_stage("https:openssl_init");
	ela_force_conservative_crypto_caps();

	if (OPENSSL_init_ssl(0, NULL) != 1) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to initialize OpenSSL");
		return -1;
	}

	ela_set_sigill_stage("https:ssl_ctx_new");
	ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to create OpenSSL TLS context");
		goto fail;
	}

	SSL_CTX_set_verify(ctx, insecure ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, NULL);
	ela_set_sigill_stage("https:set_tls12_only");
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
	/*
	 * Further narrow the handshake for PowerPC troubleshooting: avoid TLS 1.3
	 * key share and signature negotiation, and prefer older broadly-supported
	 * TLS 1.2 ciphers/curves so we can determine whether the SIGILL is in a
	 * newer handshake primitive such as X25519/ChaCha20 or related code.
	 */
	SSL_CTX_set_cipher_list(ctx,
		"ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-SHA");
	SSL_CTX_set1_groups_list(ctx, "P-256");
	if (!insecure) {
		ela_set_sigill_stage("https:load_ca_store");
		if (ssl_ctx_add_embedded_ca_store(SSL_CTX_get_cert_store(ctx), errbuf, errbuf_len) < 0)
			goto fail;
	}

	ela_set_sigill_stage("https:tcp_connect");
	sock = connect_tcp_host_port_any(parsed->host, parsed->port);
	if (sock < 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to connect to %s:%u", parsed->host, (unsigned int)parsed->port);
		goto fail;
	}

	ela_set_sigill_stage("https:ssl_new");
	ssl = SSL_new(ctx);
	if (!ssl) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to create OpenSSL SSL session");
		goto fail;
	}

	ela_set_sigill_stage("https:set_sni");
	if (SSL_set_tlsext_host_name(ssl, parsed->host) != 1) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to set TLS SNI hostname");
		goto fail;
	}

	vpm = SSL_get0_param(ssl);
	if (!insecure) {
		ela_set_sigill_stage("https:set_verify_host");
		X509_VERIFY_PARAM_set_hostflags(vpm, 0);
		if (X509_VERIFY_PARAM_set1_host(vpm, parsed->host, 0) != 1) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "failed to set TLS certificate hostname verification");
			goto fail;
		}
	}

	SSL_set_fd(ssl, sock);
	ela_set_sigill_stage("https:ssl_connect");
	if (SSL_connect(ssl) != 1) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "TLS handshake failed");
		goto fail;
	}

	if (!insecure) {
		ela_set_sigill_stage("https:verify_peer");
		if (SSL_get_verify_result(ssl) != X509_V_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "TLS peer certificate verification failed");
			goto fail;
		}
	}

	*ctx_out = ctx;
	*ssl_out = ssl;
	*sock_out = sock;
	ela_set_sigill_stage("https:connected");
	return 0;

fail:
	if (ssl)
		SSL_free(ssl);
	if (sock >= 0)
		close(sock);
	if (ctx)
		SSL_CTX_free(ctx);
	return -1;
}

static int simple_https_get_to_file(const char *uri,
				    const char *output_path,
				    bool insecure,
				    bool verbose,
				    char *errbuf,
				    size_t errbuf_len)
{
	struct parsed_http_uri parsed;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int sock = -1;
	FILE *fp = NULL;
	char *headers = NULL;
	char *request = NULL;
	size_t request_len = 0;
	size_t request_cap = 0;
	int status;

	if (parse_http_uri(uri, &parsed) != 0 || !parsed.https) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "unsupported or invalid HTTPS URI");
		return -1;
	}

	#ifdef ELA_HAS_WOLFSSL
	if (isa_is_powerpc_family(ela_detect_isa())) {
		ela_set_sigill_stage("https:wolfssl_fallback");
		return simple_wolfssl_https_get_to_file(&parsed, uri, output_path, insecure,
			verbose, errbuf, errbuf_len);
	}
	#endif

	ela_install_sigill_debug_handler();
	ela_set_sigill_stage("https:get:start");
	if (ssl_connect_with_embedded_ca(&parsed, insecure, &ctx, &ssl, &sock, errbuf, errbuf_len) < 0)
		return -1;

	ela_set_sigill_stage("https:get:fopen");
	fp = fopen(output_path, "wb");
	if (!fp) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "cannot open output file %s: %s", output_path, strerror(errno));
		goto fail;
	}

	ela_set_sigill_stage("https:get:build_request");
	if (append_text(&request, &request_len, &request_cap, "GET ") != 0 ||
	    append_text(&request, &request_len, &request_cap, parsed.path) != 0 ||
	    append_text(&request, &request_len, &request_cap, " HTTP/1.1\r\nHost: ") != 0 ||
	    append_text(&request, &request_len, &request_cap, parsed.host) != 0 ||
	    append_text(&request, &request_len, &request_cap, "\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n") != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build HTTPS request");
		goto fail;
	}

	if (verbose)
		fprintf(stderr, "HTTPS GET request uri=%s -> file=%s insecure=%s (openssl)\n",
			uri, output_path, insecure ? "true" : "false");

	ela_set_sigill_stage("https:get:write_request");
	if (ssl_write_all(ssl, (const uint8_t *)request, request_len) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to send HTTPS request");
		goto fail;
	}

	ela_set_sigill_stage("https:get:read_headers");
	if (ssl_read_headers(ssl, &headers) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to read HTTPS response headers");
		goto fail;
	}

	status = parse_status_code_from_headers(headers);
	ela_set_sigill_stage("https:get:read_body");
	if (status < 200 || status >= 300) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP status %d", status);
		goto fail;
	}

	if (ssl_copy_response_body_to_file(ssl, headers, fp) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed while reading HTTPS response body");
		goto fail;
	}

	ela_set_sigill_stage("https:get:done");
	free(headers);
	free(request);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sock);
	SSL_CTX_free(ctx);
	if (fclose(fp) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to finalize output file %s", output_path);
		unlink(output_path);
		return -1;
	}
	return 0;

fail:
	free(headers);
	free(request);
	if (fp)
		fclose(fp);
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (sock >= 0)
		close(sock);
	if (ctx)
		SSL_CTX_free(ctx);
	unlink(output_path);
	return -1;
}

static size_t curl_write_to_fp(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	FILE *fp = (FILE *)userdata;
	if (!fp)
		return 0;
	return fwrite(ptr, size, nmemb, fp);
}

struct curl_ssl_ctx_error_data {
	char *errbuf;
	size_t errbuf_len;
};

static CURLcode curl_ssl_ctx_load_embedded_ca(CURL *curl, void *sslctx, void *parm)
{
	struct curl_ssl_ctx_error_data *err = (struct curl_ssl_ctx_error_data *)parm;
	SSL_CTX *ctx = (SSL_CTX *)sslctx;
	X509_STORE *store;

	(void)curl;

	if (!ctx) {
		if (err && err->errbuf && err->errbuf_len)
			snprintf(err->errbuf, err->errbuf_len, "libcurl did not provide an SSL_CTX");
		return CURLE_SSL_CERTPROBLEM;
	}

	store = SSL_CTX_get_cert_store(ctx);
	if (ssl_ctx_add_embedded_ca_store(store,
				      err ? err->errbuf : NULL,
				      err ? err->errbuf_len : 0) < 0)
		return CURLE_SSL_CERTPROBLEM;

	return CURLE_OK;
}

static int parse_http_uri_host(const char *uri, char *host_buf, size_t host_buf_len)
{
	const char *scheme_end;
	const char *authority;
	const char *authority_end;
	const char *host_start;
	const char *host_end;
	const char *at;
	size_t host_len;

	if (!uri || !*uri || !host_buf || host_buf_len < 2)
		return -1;

	scheme_end = strstr(uri, "://");
	if (!scheme_end)
		return -1;

	authority = scheme_end + 3;
	authority_end = authority;
	while (*authority_end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#')
		authority_end++;

	at = memchr(authority, '@', (size_t)(authority_end - authority));
	host_start = at ? (at + 1) : authority;
	if (host_start >= authority_end)
		return -1;

	if (*host_start == '[') {
		host_start++;
		host_end = memchr(host_start, ']', (size_t)(authority_end - host_start));
		if (!host_end)
			return -1;
	} else {
		host_end = host_start;
		while (host_end < authority_end && *host_end != ':')
			host_end++;
	}

	host_len = (size_t)(host_end - host_start);
	if (host_len == 0 || host_len >= host_buf_len)
		return -1;

	memcpy(host_buf, host_start, host_len);
	host_buf[host_len] = '\0';
	return 0;
}

static bool is_valid_mac_address_string(const char *value)
{
	int i;

	if (!value)
		return false;

	for (i = 0; i < 17; i++) {
		char ch = value[i];

		if (i % 3 == 2) {
			if (ch != ':')
				return false;
		} else if (!isxdigit((unsigned char)ch)) {
			return false;
		}
	}

	return value[17] == '\0';
}

static bool is_zero_mac_address_string(const char *value)
{
	return value && !strcmp(value, "00:00:00:00:00:00");
}

static int __attribute__((unused)) resolve_uri_ipv4(const char *base_uri, struct in_addr *addr_out)
{
	char host[256];
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	int rc;

	if (!addr_out)
		return -1;
	if (parse_http_uri_host(base_uri, host, sizeof(host)) < 0)
		return -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	rc = getaddrinfo(host, NULL, &hints, &res);
	if (rc != 0 || !res)
		return -1;

	*addr_out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
	freeaddrinfo(res);
	return 0;
}

static int __attribute__((unused)) route_iface_for_ipv4(struct in_addr dest_addr, char *ifname_buf, size_t ifname_buf_len)
{
	FILE *fp;
	char line[512];
	uint32_t best_mask = 0;
	bool found = false;

	if (!ifname_buf || ifname_buf_len < IF_NAMESIZE)
		return -1;

	fp = fopen("/proc/net/route", "r");
	if (!fp)
		return -1;

	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		char iface[IF_NAMESIZE];
		unsigned long destination;
		unsigned long gateway;
		unsigned long flags;
		unsigned long refcnt;
		unsigned long use;
		unsigned long metric;
		unsigned long mask;
		unsigned long mtu;
		unsigned long window;
		unsigned long irtt;
		uint32_t dest_host;
		uint32_t mask_host;
		uint32_t target_host;

		if (sscanf(line, "%15s %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx",
			   iface, &destination, &gateway, &flags, &refcnt, &use,
			   &metric, &mask, &mtu, &window, &irtt) != 11)
			continue;

		if (!(flags & 0x1UL))
			continue;

		dest_host = ntohl((uint32_t)destination);
		mask_host = ntohl((uint32_t)mask);
		target_host = ntohl(dest_addr.s_addr);

		if ((target_host & mask_host) != (dest_host & mask_host))
			continue;

		if (!found || mask_host > best_mask) {
			strncpy(ifname_buf, iface, ifname_buf_len - 1);
			ifname_buf[ifname_buf_len - 1] = '\0';
			best_mask = mask_host;
			found = true;
		}
	}

	fclose(fp);
	return found ? 0 : -1;
}

static int __attribute__((unused)) mac_for_interface(const char *ifname, char *mac_buf, size_t mac_buf_len)
{
	int fd;
	struct ifreq ifr;
	unsigned char *hwaddr;

	if (!ifname || !*ifname || !mac_buf || mac_buf_len < 18)
		return -1;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	close(fd);

#ifdef __linux__
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
		return -1;
#endif

	hwaddr = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	snprintf(mac_buf, mac_buf_len,
		 "%02x:%02x:%02x:%02x:%02x:%02x",
		 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	return 0;
}

static int first_non_loopback_mac(char *mac_buf, size_t mac_buf_len)
{
	DIR *dir;
	struct dirent *de;
	char path[PATH_MAX];
	char addr[32];
	FILE *fp;

	if (!mac_buf || mac_buf_len < 18)
		return -1;

	dir = opendir("/sys/class/net");
	if (!dir)
		return -1;

	while ((de = readdir(dir)) != NULL) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..") || !strcmp(de->d_name, "lo"))
			continue;

		snprintf(path, sizeof(path), "/sys/class/net/%s/address", de->d_name);
		fp = fopen(path, "r");
		if (!fp)
			continue;

		if (!fgets(addr, sizeof(addr), fp)) {
			fclose(fp);
			continue;
		}
		fclose(fp);

		addr[strcspn(addr, "\r\n")] = '\0';
		if (is_zero_mac_address_string(addr))
			continue;
		if (!is_valid_mac_address_string(addr))
			continue;

		snprintf(mac_buf, mac_buf_len, "%s", addr);
		closedir(dir);
		return 0;
	}

	closedir(dir);
	return -1;
}

int ela_http_get_upload_mac(const char *base_uri, char *mac_buf, size_t mac_buf_len)
{
	struct in_addr dest_addr;
	char ifname[IF_NAMESIZE];
	char routed_mac[18];

	if (!mac_buf || mac_buf_len < 18)
		return -1;
	mac_buf[0] = '\0';

	/*
	 * Prefer the MAC address from the routed egress interface for the upload
	 * destination when we can resolve it. This handles systems with multiple
	 * interfaces, including VLAN subinterfaces such as eth1.70, more reliably
	 * than a simple first-entry scan of /sys/class/net.
	 */
	if (base_uri && *base_uri &&
	    resolve_uri_ipv4(base_uri, &dest_addr) == 0 &&
	    route_iface_for_ipv4(dest_addr, ifname, sizeof(ifname)) == 0 &&
	    mac_for_interface(ifname, routed_mac, sizeof(routed_mac)) == 0 &&
	    is_valid_mac_address_string(routed_mac) &&
	    !is_zero_mac_address_string(routed_mac)) {
		snprintf(mac_buf, mac_buf_len, "%s", routed_mac);
		return 0;
	}

	/*
	 * Prefer a simple sysfs lookup over route/interface resolution. This keeps
	 * the upload path away from heavier libc/network helper code on older
	 * compatibility targets where we've seen runtime CPU faults.
	 */
	if (first_non_loopback_mac(mac_buf, mac_buf_len) == 0)
		return 0;

	/*
	 * Final fallback: use a deterministic placeholder rather than invoking more
	 * network stack helpers. The API accepts any syntactically valid MAC path.
	 */
	snprintf(mac_buf, mac_buf_len, "%s", "00:00:00:00:00:00");
	return 0;
}

char *ela_http_uri_normalize_default_port(const char *uri, uint16_t default_port)
{
	const char *scheme_end;
	const char *authority;
	const char *authority_end;
	const char *path;
	const char *host_start;
	const char *at;
	const char *port_sep = NULL;
	char port_buf[8];
	char *out;
	size_t prefix_len;
	size_t suffix_len;
	size_t port_len;

	if (!uri || !*uri)
		return NULL;

	scheme_end = strstr(uri, "://");
	if (!scheme_end)
		return strdup(uri);

	authority = scheme_end + 3;
	authority_end = authority;
	while (*authority_end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#')
		authority_end++;

	if (authority == authority_end)
		return strdup(uri);

	path = authority_end;
	at = memchr(authority, '@', (size_t)(authority_end - authority));
	host_start = at ? (at + 1) : authority;

	if (host_start >= authority_end)
		return strdup(uri);

	if (*host_start == '[') {
		const char *host_end = memchr(host_start, ']', (size_t)(authority_end - host_start));
		if (!host_end)
			return strdup(uri);
		if (host_end + 1 < authority_end && *(host_end + 1) == ':')
			port_sep = host_end + 1;
	} else {
		for (const char *p = host_start; p < authority_end; p++) {
			if (*p == ':')
				port_sep = p;
		}
	}

	if (port_sep)
		return strdup(uri);

	snprintf(port_buf, sizeof(port_buf), ":%u", (unsigned int)default_port);
	port_len = strlen(port_buf);
	prefix_len = (size_t)(authority_end - uri);
	suffix_len = strlen(path);

	out = malloc(prefix_len + port_len + suffix_len + 1);
	if (!out)
		return NULL;

	memcpy(out, uri, prefix_len);
	memcpy(out + prefix_len, port_buf, port_len);
	memcpy(out + prefix_len + port_len, path, suffix_len + 1);
	return out;
}

int ela_parse_http_output_uri(const char *uri,
				  const char **output_http,
				  const char **output_https,
				  char *errbuf,
				  size_t errbuf_len)
{
	if (output_http)
		*output_http = NULL;
	if (output_https)
		*output_https = NULL;
	if (errbuf && errbuf_len)
		errbuf[0] = '\0';

	if (!uri || !*uri)
		return 0;

	if (!strncmp(uri, "http://", 7)) {
		if (output_http)
			*output_http = uri;
		return 0;
	}

	if (!strncmp(uri, "https://", 8)) {
		if (output_https)
			*output_https = uri;
		return 0;
	}

	if (errbuf && errbuf_len)
		snprintf(errbuf,
			 errbuf_len,
			 "Invalid --output-http URI (expected http://host:port/... or https://host:port/...): %s",
			 uri);
	return -1;
}

char *ela_http_build_upload_uri(const char *base_uri, const char *upload_type, const char *file_path)
{
	const char *scheme_end;
	const char *authority;
	const char *authority_end;
	const char *query = "";
	char mac_addr[18];
	char *out;
	char *escaped_file = NULL;
	size_t prefix_len;
	size_t query_len;
	size_t mac_len;
	size_t type_len;

	if (!base_uri || !*base_uri || !upload_type || !*upload_type)
		return NULL;

	scheme_end = strstr(base_uri, "://");
	if (!scheme_end)
		return strdup(base_uri);

	authority = scheme_end + 3;
	authority_end = authority;
	while (*authority_end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#')
		authority_end++;

	if (ela_http_get_upload_mac(base_uri, mac_addr, sizeof(mac_addr)) < 0)
		return NULL;

	if (file_path && *file_path) {
		escaped_file = url_percent_encode(file_path);
		if (!escaped_file)
			return NULL;
		query = "?filePath=";
	}

	prefix_len = (size_t)(authority_end - base_uri);
	mac_len = strlen(mac_addr);
	type_len = strlen(upload_type);
	query_len = strlen(query) + (escaped_file ? strlen(escaped_file) : 0);
	out = malloc(prefix_len + 1 + mac_len + strlen("/upload/") + type_len + query_len + 1);
	if (!out) {
		if (escaped_file)
			free(escaped_file);
		return NULL;
	}

	memcpy(out, base_uri, prefix_len);
	out[prefix_len] = '/';
	memcpy(out + prefix_len + 1, mac_addr, mac_len);
	memcpy(out + prefix_len + 1 + mac_len, "/upload/", strlen("/upload/"));
	memcpy(out + prefix_len + 1 + mac_len + strlen("/upload/"), upload_type, type_len);
	memcpy(out + prefix_len + 1 + mac_len + strlen("/upload/") + type_len, query, strlen(query));
	if (escaped_file)
		memcpy(out + prefix_len + 1 + mac_len + strlen("/upload/") + type_len + strlen(query), escaped_file, strlen(escaped_file));
	out[prefix_len + 1 + mac_len + strlen("/upload/") + type_len + query_len] = '\0';

	if (escaped_file)
		free(escaped_file);
	return out;
}

int ela_http_post_log_message(const char *base_uri, const char *message,
				bool insecure, bool verbose,
				char *errbuf, size_t errbuf_len)
{
	char *upload_uri;
	int rc;

	if (errbuf && errbuf_len)
		errbuf[0] = '\0';

	if (!base_uri || !*base_uri || !message || !*message) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "log upload requires base URI and message");
		return -1;
	}

	upload_uri = ela_http_build_upload_uri(base_uri, "log", NULL);
	if (!upload_uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build log upload URI");
		return -1;
	}

	rc = ela_http_post(upload_uri,
		(const uint8_t *)message,
		strlen(message),
		"text/plain; charset=utf-8",
		insecure,
		verbose,
		errbuf,
		errbuf_len);
	free(upload_uri);
	return rc;
}

/*
 * Single HTTPS POST attempt via curl.  Returns 0 on success, -1 on failure.
 * *status_out is set to the HTTP response code when a response is received.
 */
static int ela_http_post_https_once(const char *effective_uri,
				    const uint8_t *data, size_t len,
				    const char *content_type,
				    const char *auth_key,
				    bool insecure, bool verbose,
				    char *errbuf, size_t errbuf_len,
				    int *status_out)
{
	CURL *curl;
	CURLcode rc;
	long http_code = 0;
	struct curl_slist *headers = NULL;
	char header_line[256 + ELA_API_KEY_MAX_LEN];
	static bool curl_global_ready;
	struct curl_ssl_ctx_error_data ssl_ctx_err = { errbuf, errbuf_len };

	if (status_out)
		*status_out = 0;

	ela_force_conservative_crypto_caps();

	if (!curl_global_ready) {
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "curl_global_init failed");
			return -1;
		}
		curl_global_ready = true;
	}

	curl = curl_easy_init();
	if (!curl) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "curl_easy_init failed");
		return -1;
	}

	if (verbose) {
		fprintf(stderr,
			"HTTP POST request uri=%s bytes=%zu content-type=%s insecure=%s\n",
			effective_uri, len, content_type, insecure ? "true" : "false");
	}

	snprintf(header_line, sizeof(header_line), "Content-Type: %s", content_type);
	headers = curl_slist_append(headers, header_line);
	if (!headers) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to prepare HTTP headers");
		curl_easy_cleanup(curl);
		return -1;
	}

	if (auth_key && *auth_key) {
		snprintf(header_line, sizeof(header_line), "Authorization: Bearer %s", auth_key);
		headers = curl_slist_append(headers, header_line);
		if (!headers) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "failed to prepare auth header");
			curl_easy_cleanup(curl);
			return -1;
		}
	}

	curl_easy_setopt(curl, CURLOPT_URL, effective_uri);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)data);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)len);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

	if (insecure) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	} else {
		rc = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, curl_ssl_ctx_load_embedded_ca);
		if (rc == CURLE_OK)
			rc = curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, &ssl_ctx_err);
		if (rc != CURLE_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "failed to configure HTTPS CA bundle: %s",
					 curl_easy_strerror(rc));
			curl_slist_free_all(headers);
			curl_easy_cleanup(curl);
			return -1;
		}
	}

	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		if (verbose)
			fprintf(stderr, "HTTP POST transport failure uri=%s error=%s\n",
				effective_uri, curl_easy_strerror(rc));
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "curl perform failed: %s", curl_easy_strerror(rc));
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		return -1;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	if (status_out)
		*status_out = (int)http_code;

	if (http_code < 200 || http_code >= 300) {
		if (verbose)
			fprintf(stderr, "HTTP POST response failure uri=%s status=%ld\n",
				effective_uri, http_code);
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP status %ld", http_code);
		return -1;
	}

	if (verbose)
		fprintf(stderr, "HTTP POST success uri=%s status=%ld\n", effective_uri, http_code);

	return 0;
}

int ela_http_post(const char *uri, const uint8_t *data, size_t len,
		 const char *content_type, bool insecure, bool verbose,
		 char *errbuf, size_t errbuf_len)
{
	bool is_https;
	char *normalized_uri = NULL;
	const char *effective_uri = uri;
	const char *ct;
	const char *key;
	int status = 0;
	int ret;

	if (errbuf && errbuf_len)
		errbuf[0] = '\0';

	if (!uri || !*uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP URI is empty");
		return -1;
	}

	is_https = !strncmp(uri, "https://", 8);
	if (!strncmp(uri, "http://", 7))
		normalized_uri = ela_http_uri_normalize_default_port(uri, 80);
	else if (is_https)
		normalized_uri = ela_http_uri_normalize_default_port(uri, 443);

	if ((!strncmp(uri, "http://", 7) || is_https) && !normalized_uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to normalize HTTP URI");
		return -1;
	}
	if (normalized_uri)
		effective_uri = normalized_uri;

	ct = (content_type && *content_type)
	     ? content_type : "text/plain; charset=utf-8";

	key = ela_api_key_get();
	do {
		if (is_https) {
			ret = ela_http_post_https_once(effective_uri, data, len,
						       ct, key, insecure, verbose,
						       errbuf, errbuf_len, &status);
		} else {
			/*
			 * For plain http://, use the lightweight socket-based POST
			 * to avoid curl / OpenSSL initialisation on architectures
			 * where curl_global_init is unreliable under QEMU.
			 */
			ret = simple_http_post(effective_uri, data, len, ct,
					       key, verbose, errbuf, errbuf_len,
					       &status);
		}
		if (ret == 0) {
			ela_api_key_confirm();
			free(normalized_uri);
			return 0;
		}
		/* Retry with the next candidate key only on 401 */
		if (status == 401)
			key = ela_api_key_next();
		else
			break;
	} while (key);

	if (status == 401)
		fprintf(stderr,
			"warning: server returned 401 Unauthorized\n"
			"  Set a bearer token via --api-key, ELA_API_KEY, or /tmp/ela.key\n");

	free(normalized_uri);
	return -1;
}

int ela_http_get_to_file(const char *uri, const char *output_path,
			   bool insecure, bool verbose,
			   char *errbuf, size_t errbuf_len)
{
	CURL *curl;
	CURLcode rc;
	long http_code = 0;
	static bool curl_global_ready;
	bool is_https;
	char *normalized_uri = NULL;
	const char *effective_uri = uri;
	FILE *fp = NULL;
	struct curl_ssl_ctx_error_data ssl_ctx_err = { errbuf, errbuf_len };

	if (errbuf && errbuf_len)
		errbuf[0] = '\0';

	if (!uri || !*uri || !output_path || !*output_path) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP GET requires URI and output path");
		return -1;
	}

	ela_install_sigill_debug_handler();
	ela_set_sigill_stage("download-file:entry");

	if (!strncmp(uri, "http://", 7))
		return simple_http_get_to_file(uri, output_path, verbose, errbuf, errbuf_len);
	if (!strncmp(uri, "https://", 8))
		return simple_https_get_to_file(uri, output_path, insecure, verbose, errbuf, errbuf_len);

	is_https = !strncmp(uri, "https://", 8);
	if (!strncmp(uri, "http://", 7)) {
		normalized_uri = ela_http_uri_normalize_default_port(uri, 80);
	} else if (is_https) {
		normalized_uri = ela_http_uri_normalize_default_port(uri, 443);
	} else {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "unsupported URI scheme (expected http:// or https://)");
		return -1;
	}

	if (!normalized_uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to normalize HTTP URI");
		return -1;
	}
	effective_uri = normalized_uri;

	ela_set_sigill_stage("download-file:curl_global_init");
	ela_force_conservative_crypto_caps();

	if (!curl_global_ready) {
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "curl_global_init failed");
			free(normalized_uri);
			return -1;
		}
		curl_global_ready = true;
	}

	ela_set_sigill_stage("download-file:fopen");
	fp = fopen(output_path, "wb");
	if (!fp) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "cannot open output file %s: %s", output_path, strerror(errno));
		free(normalized_uri);
		return -1;
	}

	ela_set_sigill_stage("download-file:curl_easy_init");
	curl = curl_easy_init();
	if (!curl) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "curl_easy_init failed");
		fclose(fp);
		unlink(output_path);
		free(normalized_uri);
		return -1;
	}

	if (verbose) {
		fprintf(stderr, "HTTP GET request uri=%s -> file=%s insecure=%s\n",
			effective_uri,
			output_path,
			insecure ? "true" : "false");
	}

	ela_set_sigill_stage("download-file:curl_setopt");
	curl_easy_setopt(curl, CURLOPT_URL, effective_uri);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_to_fp);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

	if (is_https) {
		if (insecure) {
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		} else {
			rc = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, curl_ssl_ctx_load_embedded_ca);
			if (rc == CURLE_OK)
				rc = curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, &ssl_ctx_err);
			if (rc != CURLE_OK) {
				if (errbuf && errbuf_len)
					snprintf(errbuf, errbuf_len, "failed to configure HTTPS CA bundle: %s",
						 curl_easy_strerror(rc));
				curl_easy_cleanup(curl);
				fclose(fp);
				unlink(output_path);
				free(normalized_uri);
				return -1;
			}
		}
	}

	ela_set_sigill_stage("download-file:curl_perform");
	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		if (verbose)
			fprintf(stderr, "HTTP GET transport failure uri=%s error=%s\n",
				effective_uri, curl_easy_strerror(rc));
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "curl perform failed: %s", curl_easy_strerror(rc));
		curl_easy_cleanup(curl);
		fclose(fp);
		unlink(output_path);
		free(normalized_uri);
		return -1;
	}

	ela_set_sigill_stage("download-file:curl_getinfo");
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_easy_cleanup(curl);

	if (fclose(fp) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to finalize output file %s", output_path);
		unlink(output_path);
		free(normalized_uri);
		return -1;
	}
	fp = NULL;

	if (http_code < 200 || http_code >= 300) {
		if (verbose)
			fprintf(stderr, "HTTP GET response failure uri=%s status=%ld\n",
				effective_uri, http_code);
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP status %ld", http_code);
		unlink(output_path);
		free(normalized_uri);
		return -1;
	}

	if (verbose)
		fprintf(stderr, "HTTP GET success uri=%s status=%ld\n", effective_uri, http_code);

	ela_set_sigill_stage("download-file:success");
	free(normalized_uri);
	return 0;
}
