#include "embedded_linux_audit_cmd.h"

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
#include <time.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
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

#ifndef S_IFCHR
#define S_IFCHR 0020000
#endif

#ifndef S_IFBLK
#define S_IFBLK 0060000
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int append_text(char **buf, size_t *len, size_t *cap, const char *text)
{
	char *tmp;
	size_t text_len;
	size_t need;
	size_t new_cap;

	if (!buf || !len || !cap || !text)
		return -1;

	text_len = strlen(text);
	need = *len + text_len + 1;
	if (need > *cap) {
		new_cap = *cap ? *cap : 256;
		while (new_cap < need)
			new_cap *= 2;
		tmp = realloc(*buf, new_cap);
		if (!tmp)
			return -1;
		*buf = tmp;
		*cap = new_cap;
	}

	memcpy(*buf + *len, text, text_len);
	*len += text_len;
	(*buf)[*len] = '\0';
	return 0;
}

struct parsed_http_uri {
	bool https;
	char host[256];
	uint16_t port;
	char path[PATH_MAX];
};

static int parse_status_code_from_headers(const char *headers);

static int append_bytes(char **buf, size_t *len, size_t *cap, const char *data, size_t data_len)
{
	char *tmp;
	size_t need;
	size_t new_cap;

	if (!buf || !len || !cap || (!data && data_len))
		return -1;

	need = *len + data_len + 1;
	if (need > *cap) {
		new_cap = *cap ? *cap : 256;
		while (new_cap < need)
			new_cap *= 2;
		tmp = realloc(*buf, new_cap);
		if (!tmp)
			return -1;
		*buf = tmp;
		*cap = new_cap;
	}

	if (data_len)
		memcpy(*buf + *len, data, data_len);
	*len += data_len;
	(*buf)[*len] = '\0';
	return 0;
}

static char *url_percent_encode(const char *text)
{
	static const char hex[] = "0123456789ABCDEF";
	char *out = NULL;
	size_t len = 0;
	size_t cap = 0;
	const unsigned char *p = (const unsigned char *)text;

	if (!text)
		return NULL;

	while (*p) {
		if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~' || *p == '/') {
			if (append_bytes(&out, &len, &cap, (const char *)p, 1) != 0)
				goto fail;
		} else {
			char esc[3];
			esc[0] = '%';
			esc[1] = hex[*p >> 4];
			esc[2] = hex[*p & 0x0F];
			if (append_bytes(&out, &len, &cap, esc, sizeof(esc)) != 0)
				goto fail;
		}
		p++;
	}

	return out;

fail:
	free(out);
	return NULL;
}

static int parse_http_uri(const char *uri, struct parsed_http_uri *parsed)
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

static int connect_tcp_host_port(const char *host, uint16_t port)
{
	struct in_addr addr;
	struct sockaddr_in sa;
	int sock = -1;

	if (!host || !*host || !port)
		return -1;

	if (inet_pton(AF_INET, host, &addr) != 1)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr = addr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sock);
		return -1;
	}

	return sock;
}

static int connect_tcp_host_port_any(const char *host, uint16_t port)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	char portbuf[8];
	int sock = -1;
	int rc;

	if (!host || !*host || !port)
		return -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(portbuf, sizeof(portbuf), "%u", (unsigned int)port);
	rc = getaddrinfo(host, portbuf, &hints, &res);
	if (rc != 0 || !res)
		return -1;

	for (ai = res; ai; ai = ai->ai_next) {
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0)
			continue;
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		close(sock);
		sock = -1;
	}

	freeaddrinfo(res);
	return sock;
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

	if (uboot_default_ca_bundle_pem_len == 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "embedded CA bundle is empty");
		return -1;
	}

	bio = BIO_new_mem_buf((const void *)uboot_default_ca_bundle_pem,
			     (int)uboot_default_ca_bundle_pem_len);
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
			    bool verbose,
			    char *errbuf,
			    size_t errbuf_len)
{
	struct parsed_http_uri parsed;
	char *request = NULL;
	size_t request_len = 0;
	size_t request_cap = 0;
	char content_len_buf[32];
	int sock;
	int status_code;

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
	    append_text(&request, &request_len, &request_cap, content_len_buf) != 0 ||
	    append_text(&request, &request_len, &request_cap, "\r\n\r\n") != 0 ||
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

	if (uboot_send_all(sock, (const uint8_t *)request, request_len) != 0) {
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

	if (uboot_send_all(sock, (const uint8_t *)request, request_len) != 0) {
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

static const char *normalize_isa_name(const char *isa)
{
	if (!isa || !*isa)
		return NULL;

	if (!strcmp(isa, "x86") || !strcmp(isa, "i386") || !strcmp(isa, "i486") ||
	    !strcmp(isa, "i586") || !strcmp(isa, "i686"))
		return FW_AUDIT_ISA_X86;

	if (!strcmp(isa, "x86_64") || !strcmp(isa, "amd64"))
		return FW_AUDIT_ISA_X86_64;

	if (!strcmp(isa, "aarch64") || !strcmp(isa, "arm64") || !strcmp(isa, "aarch64le") ||
	    !strcmp(isa, "aarch64-le"))
		return FW_AUDIT_ISA_AARCH64_LE;

	if (!strcmp(isa, "aarch64_be") || !strcmp(isa, "aarch64be") || !strcmp(isa, "aarch64-be"))
		return FW_AUDIT_ISA_AARCH64_BE;

	return isa;
}

static bool isa_is_powerpc_family(const char *isa)
{
	const char *normalized = normalize_isa_name(isa);

	if (!normalized)
		return false;

	return !strcmp(normalized, "powerpc") ||
	       !strcmp(normalized, "ppc") ||
	       !strcmp(normalized, "powerpc64") ||
	       !strcmp(normalized, "ppc64") ||
	       !strcmp(normalized, "powerpc64le") ||
	       !strcmp(normalized, "ppc64le");
}

static const char *fw_audit_sigill_stage = "startup";

#ifdef DEBUG
static bool fw_audit_sigill_debug_enabled(void)
{
	const char *v = getenv("FW_AUDIT_SIGILL_DEBUG");
	return v && !strcmp(v, "1");
}
#endif

static void fw_audit_set_sigill_stage(const char *stage)
{
	if (stage && *stage)
		fw_audit_sigill_stage = stage;

#ifdef DEBUG
	if (fw_audit_sigill_debug_enabled())
		fprintf(stderr, "FW_AUDIT_SIGILL stage=%s\n", fw_audit_sigill_stage);
#endif
}

#ifdef DEBUG
static void fw_audit_sigill_handler(int signum)
{
	char buf[256];
	int len;
	(void)signum;
	len = snprintf(buf, sizeof(buf),
		"FW_AUDIT_SIGILL caught illegal instruction at stage=%s\n",
		fw_audit_sigill_stage ? fw_audit_sigill_stage : "unknown");
	if (len > 0)
		write(STDERR_FILENO, buf, (size_t)len);
	signal(SIGILL, SIG_DFL);
	raise(SIGILL);
}
#endif

static void fw_audit_install_sigill_debug_handler(void)
{
	#ifdef DEBUG
	static bool installed;
	struct sigaction sa;

	if (installed || !fw_audit_sigill_debug_enabled())
		return;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = fw_audit_sigill_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGILL, &sa, NULL) == 0)
		installed = true;
	#endif
}

static void fw_audit_force_conservative_powerpc_crypto_caps(void)
{
	const char *isa = fw_audit_detect_isa();
	const char *ppccap;

	if (!isa_is_powerpc_family(isa))
		return;

	/*
	 * For PowerPC troubleshooting builds, force OpenSSL onto its most
	 * conservative generic code paths unless the user explicitly overrides the
	 * capability mask. This helps isolate illegal-instruction faults caused by
	 * runtime CPU feature detection or optimized PowerPC crypto dispatch.
	 */
	ppccap = getenv("OPENSSL_ppccap");
	if (!ppccap || !*ppccap)
		setenv("OPENSSL_ppccap", "0", 0);
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

	fw_audit_set_sigill_stage("https:wolfssl_init");
	if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_Init failed");
		goto cleanup;
	}

	fw_audit_set_sigill_stage("https:wolfssl_ctx_new");
	ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	if (!ctx) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_CTX_new failed");
		goto cleanup;
	}
	wolfSSL_CTX_set_verify(ctx, insecure ? WOLFSSL_VERIFY_NONE : WOLFSSL_VERIFY_PEER, NULL);
	if (!insecure) {
		fw_audit_set_sigill_stage("https:wolfssl_load_ca");
		if (wolfSSL_CTX_load_verify_buffer(ctx,
				(const unsigned char *)uboot_default_ca_bundle_pem,
				(long)uboot_default_ca_bundle_pem_len,
				WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "wolfSSL_CTX_load_verify_buffer failed");
			goto cleanup;
		}
	}

	fw_audit_set_sigill_stage("https:wolfssl_tcp_connect");
	sock = connect_tcp_host_port_any(parsed->host, parsed->port);
	if (sock < 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to connect to %s:%u", parsed->host, (unsigned int)parsed->port);
		goto cleanup;
	}

	fw_audit_set_sigill_stage("https:wolfssl_new");
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

	fw_audit_set_sigill_stage("https:wolfssl_connect");
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

	fw_audit_set_sigill_stage("https:wolfssl_write_request");
	if ((rc = wolfSSL_write(ssl, request, (int)request_len)) <= 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_write failed: %d", wolfSSL_get_error(ssl, rc));
		goto cleanup;
	}

	fw_audit_set_sigill_stage("https:wolfssl_read_headers");
	if (wolfssl_read_headers(ssl, &headers) != 0)
		goto cleanup;
	status = parse_status_code_from_headers(headers);
	if (status < 200 || status >= 300) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP status %d", status);
		goto cleanup;
	}

	fw_audit_set_sigill_stage("https:wolfssl_read_body");
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

const char *fw_audit_detect_isa(void)
{
	static char detected_isa[32];
	static bool initialized;
	const char *override_isa;
	struct utsname uts;
	const char *normalized;

	if (initialized)
		return detected_isa[0] ? detected_isa : NULL;

	override_isa = getenv("FW_AUDIT_TEST_ISA");
	if (override_isa && *override_isa) {
		normalized = normalize_isa_name(override_isa);
		snprintf(detected_isa, sizeof(detected_isa), "%s", normalized ? normalized : override_isa);
		initialized = true;
		return detected_isa;
	}

	if (uname(&uts) == 0) {
		normalized = normalize_isa_name(uts.machine);
		if (normalized && *normalized)
			snprintf(detected_isa, sizeof(detected_isa), "%s", normalized);
	}

	initialized = true;
	return detected_isa[0] ? detected_isa : NULL;
}

bool fw_audit_isa_supported_for_efi_bios(const char *isa)
{
	const char *normalized = normalize_isa_name(isa);

	if (!normalized)
		return false;

	return !strcmp(normalized, FW_AUDIT_ISA_X86) ||
	       !strcmp(normalized, FW_AUDIT_ISA_X86_64) ||
	       !strcmp(normalized, FW_AUDIT_ISA_AARCH64_BE) ||
	       !strcmp(normalized, FW_AUDIT_ISA_AARCH64_LE);
}

static int append_json_escaped(char **buf, size_t *len, size_t *cap, const char *text)
{
	const unsigned char *p = (const unsigned char *)text;
	char esc[7];

	if (!buf || !len || !cap || !text)
		return -1;

	while (*p) {
		switch (*p) {
		case '\\':
			if (append_text(buf, len, cap, "\\\\") != 0)
				return -1;
			break;
		case '"':
			if (append_text(buf, len, cap, "\\\"") != 0)
				return -1;
			break;
		case '\b':
			if (append_text(buf, len, cap, "\\b") != 0)
				return -1;
			break;
		case '\f':
			if (append_text(buf, len, cap, "\\f") != 0)
				return -1;
			break;
		case '\n':
			if (append_text(buf, len, cap, "\\n") != 0)
				return -1;
			break;
		case '\r':
			if (append_text(buf, len, cap, "\\r") != 0)
				return -1;
			break;
		case '\t':
			if (append_text(buf, len, cap, "\\t") != 0)
				return -1;
			break;
		default:
			if (*p < 0x20) {
				int n = snprintf(esc, sizeof(esc), "\\u%04x", (unsigned int)*p);
				if (n < 0 || (size_t)n >= sizeof(esc) || append_text(buf, len, cap, esc) != 0)
					return -1;
			} else {
				char ch[2] = {(char)*p, '\0'};
				if (append_text(buf, len, cap, ch) != 0)
					return -1;
			}
			break;
		}
		p++;
	}

	return 0;
}

static int append_csv_field(char **buf, size_t *len, size_t *cap, const char *text)
{
	const char *p = text ? text : "";

	if (append_text(buf, len, cap, "\"") != 0)
		return -1;

	while (*p) {
		if (*p == '"') {
			if (append_text(buf, len, cap, "\"\"") != 0)
				return -1;
		} else {
			char ch[2] = {*p, '\0'};
			if (append_text(buf, len, cap, ch) != 0)
				return -1;
		}
		p++;
	}

	return append_text(buf, len, cap, "\"");
}

static int build_lifecycle_payload(const char *output_format,
				   const char *command,
				   const char *phase,
				   int rc,
				   char **payload_out)
{
	char *buf = NULL;
	size_t len = 0;
	size_t cap = 0;
	char rc_buf[32];
	char ts_buf[64];
	const char *fmt = output_format && *output_format ? output_format : "txt";
	time_t now;
	struct tm tm_now;

	if (!command || !phase || !payload_out)
		return -1;

	snprintf(rc_buf, sizeof(rc_buf), "%d", rc);
	now = time(NULL);
	if (localtime_r(&now, &tm_now) == NULL)
		return -1;
	if (strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%dT%H:%M:%S%z", &tm_now) == 0)
		return -1;

	if (!strcmp(fmt, "json")) {
		if (append_text(&buf, &len, &cap, "{\"record\":\"log\",\"agent_timestamp\":\"") != 0 ||
		    append_json_escaped(&buf, &len, &cap, ts_buf) != 0 ||
		    append_text(&buf, &len, &cap, "\",\"phase\":\"") != 0 ||
		    append_json_escaped(&buf, &len, &cap, phase) != 0 ||
		    append_text(&buf, &len, &cap, "\",\"command\":\"") != 0 ||
		    append_json_escaped(&buf, &len, &cap, command) != 0 ||
		    append_text(&buf, &len, &cap, "\",\"rc\":") != 0 ||
		    append_text(&buf, &len, &cap, rc_buf) != 0 ||
		    append_text(&buf, &len, &cap, "}\n") != 0)
			goto fail;
	} else if (!strcmp(fmt, "csv")) {
		if (append_csv_field(&buf, &len, &cap, "log") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, ts_buf) != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, phase) != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, command) != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, rc_buf) != 0 ||
		    append_text(&buf, &len, &cap, "\n") != 0)
			goto fail;
	} else {
		if (append_text(&buf, &len, &cap, "log agent_timestamp=") != 0 ||
		    append_text(&buf, &len, &cap, ts_buf) != 0 ||
		    append_text(&buf, &len, &cap, " phase=") != 0 ||
		    append_text(&buf, &len, &cap, phase) != 0 ||
		    append_text(&buf, &len, &cap, " command=") != 0 ||
		    append_text(&buf, &len, &cap, command) != 0 ||
		    append_text(&buf, &len, &cap, " rc=") != 0 ||
		    append_text(&buf, &len, &cap, rc_buf) != 0 ||
		    append_text(&buf, &len, &cap, "\n") != 0)
			goto fail;
	}

	*payload_out = buf;
	return 0;

fail:
	free(buf);
	return -1;
}

static const char *lifecycle_content_type(const char *output_format)
{
	if (output_format && !strcmp(output_format, "json"))
		return "application/json; charset=utf-8";
	if (output_format && !strcmp(output_format, "csv"))
		return "text/csv; charset=utf-8";
	return "text/plain; charset=utf-8";
}

static bool fw_audit_lifecycle_logging_enabled(void)
{
	const char *ela_debug = getenv("ELA_DEBUG");

	return ela_debug && !strcmp(ela_debug, "1");
}

int fw_audit_emit_lifecycle_event(const char *output_format,
				  const char *output_tcp,
				  const char *output_http,
				  const char *output_https,
				  bool insecure,
				  const char *command,
				  const char *phase,
				  int rc)
{
	char *payload = NULL;
	const char *output_uri = output_http && *output_http ? output_http : output_https;
	char errbuf[256];

	if (!fw_audit_lifecycle_logging_enabled())
		return 0;

	if (build_lifecycle_payload(output_format, command, phase, rc, &payload) != 0)
		return -1;

	fputs(payload, stderr);

	if (output_tcp && *output_tcp) {
		int sock = uboot_connect_tcp_ipv4(output_tcp);
		if (sock >= 0) {
			(void)uboot_send_all(sock, (const uint8_t *)payload, strlen(payload));
			close(sock);
		}
	}

	if (output_uri && *output_uri) {
		char *upload_uri = uboot_http_build_upload_uri(output_uri, "log", NULL);
		if (!upload_uri) {
			fprintf(stderr, "Failed to build HTTP(S) log upload URI for %s\n", output_uri);
		} else if (uboot_http_post(upload_uri,
					      (const uint8_t *)payload,
					      strlen(payload),
					      lifecycle_content_type(output_format),
					      insecure,
					      false,
					      errbuf,
					      sizeof(errbuf)) < 0) {
			fprintf(stderr, "Failed HTTP(S) POST log to %s: %s\n",
				upload_uri,
				errbuf[0] ? errbuf : "unknown error");
		}
		free(upload_uri);
	}

	free(payload);
	return 0;
}

static uint64_t read_u64_from_file(const char *path)
{
	char buf[64];
	int fd;
	ssize_t n;
	char *end;
	unsigned long long v;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;

	buf[n] = '\0';
	errno = 0;
	v = strtoull(buf, &end, 0);
	while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
		end++;
	if (errno || end == buf || *end != '\0')
		return 0;

	return (uint64_t)v;
}

int uboot_parse_u64(const char *s, uint64_t *out)
{
	char *end;
	unsigned long long v;

	if (!s || !out)
		return -1;

	errno = 0;
	v = strtoull(s, &end, 0);
	while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
		end++;
	if (errno || end == s || *end != '\0')
		return -1;

	*out = (uint64_t)v;
	return 0;
}

uint32_t uboot_read_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) |
	       ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) |
	       (uint32_t)p[3];
}

int uboot_connect_tcp_ipv4(const char *spec)
{
	char host[64];
	char *colon;
	char *end;
	unsigned long port_ul;
	int sock;
	struct sockaddr_in sa;

	if (!spec || !*spec)
		return -1;

	strncpy(host, spec, sizeof(host) - 1);
	host[sizeof(host) - 1] = '\0';
	colon = strrchr(host, ':');
	if (!colon || colon == host || *(colon + 1) == '\0')
		return -1;

	*colon = '\0';
	errno = 0;
	port_ul = strtoul(colon + 1, &end, 10);
	if (errno || *end || port_ul == 0 || port_ul > 65535)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port_ul);
	if (inet_pton(AF_INET, host, &sa.sin_addr) != 1)
		return -1;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sock);
		return -1;
	}

	return sock;
}

int uboot_send_all(int sock, const uint8_t *buf, size_t len)
{
	while (len) {
		ssize_t n = send(sock, buf, len, 0);
		if (n <= 0)
			return -1;
		buf += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
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

	fw_audit_install_sigill_debug_handler();
	fw_audit_set_sigill_stage("https:openssl_init");
	fw_audit_force_conservative_powerpc_crypto_caps();

	if (OPENSSL_init_ssl(0, NULL) != 1) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to initialize OpenSSL");
		return -1;
	}

	fw_audit_set_sigill_stage("https:ssl_ctx_new");
	ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to create OpenSSL TLS context");
		goto fail;
	}

	SSL_CTX_set_verify(ctx, insecure ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, NULL);
	fw_audit_set_sigill_stage("https:set_tls12_only");
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
		fw_audit_set_sigill_stage("https:load_ca_store");
		if (ssl_ctx_add_embedded_ca_store(SSL_CTX_get_cert_store(ctx), errbuf, errbuf_len) < 0)
			goto fail;
	}

	fw_audit_set_sigill_stage("https:tcp_connect");
	sock = connect_tcp_host_port_any(parsed->host, parsed->port);
	if (sock < 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to connect to %s:%u", parsed->host, (unsigned int)parsed->port);
		goto fail;
	}

	fw_audit_set_sigill_stage("https:ssl_new");
	ssl = SSL_new(ctx);
	if (!ssl) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to create OpenSSL SSL session");
		goto fail;
	}

	fw_audit_set_sigill_stage("https:set_sni");
	if (SSL_set_tlsext_host_name(ssl, parsed->host) != 1) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to set TLS SNI hostname");
		goto fail;
	}

	vpm = SSL_get0_param(ssl);
	if (!insecure) {
		fw_audit_set_sigill_stage("https:set_verify_host");
		X509_VERIFY_PARAM_set_hostflags(vpm, 0);
		if (X509_VERIFY_PARAM_set1_host(vpm, parsed->host, 0) != 1) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "failed to set TLS certificate hostname verification");
			goto fail;
		}
	}

	SSL_set_fd(ssl, sock);
	fw_audit_set_sigill_stage("https:ssl_connect");
	if (SSL_connect(ssl) != 1) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "TLS handshake failed");
		goto fail;
	}

	if (!insecure) {
		fw_audit_set_sigill_stage("https:verify_peer");
		if (SSL_get_verify_result(ssl) != X509_V_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "TLS peer certificate verification failed");
			goto fail;
		}
	}

	*ctx_out = ctx;
	*ssl_out = ssl;
	*sock_out = sock;
	fw_audit_set_sigill_stage("https:connected");
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
	if (isa_is_powerpc_family(fw_audit_detect_isa())) {
		fw_audit_set_sigill_stage("https:wolfssl_fallback");
		return simple_wolfssl_https_get_to_file(&parsed, uri, output_path, insecure,
			verbose, errbuf, errbuf_len);
	}
	#endif

	fw_audit_install_sigill_debug_handler();
	fw_audit_set_sigill_stage("https:get:start");
	if (ssl_connect_with_embedded_ca(&parsed, insecure, &ctx, &ssl, &sock, errbuf, errbuf_len) < 0)
		return -1;

	fw_audit_set_sigill_stage("https:get:fopen");
	fp = fopen(output_path, "wb");
	if (!fp) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "cannot open output file %s: %s", output_path, strerror(errno));
		goto fail;
	}

	fw_audit_set_sigill_stage("https:get:build_request");
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

	fw_audit_set_sigill_stage("https:get:write_request");
	if (ssl_write_all(ssl, (const uint8_t *)request, request_len) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to send HTTPS request");
		goto fail;
	}

	fw_audit_set_sigill_stage("https:get:read_headers");
	if (ssl_read_headers(ssl, &headers) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to read HTTPS response headers");
		goto fail;
	}

	status = parse_status_code_from_headers(headers);
	fw_audit_set_sigill_stage("https:get:read_body");
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

	fw_audit_set_sigill_stage("https:get:done");
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

char *uboot_http_uri_normalize_default_port(const char *uri, uint16_t default_port)
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

int fw_audit_parse_http_output_uri(const char *uri,
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

int uboot_http_get_upload_mac(const char *base_uri, char *mac_buf, size_t mac_buf_len)
{
	const char *override_mac;
	struct in_addr dest_addr;
	char ifname[IF_NAMESIZE];
	char routed_mac[18];

	if (!mac_buf || mac_buf_len < 18)
		return -1;
	mac_buf[0] = '\0';

	override_mac = getenv("FW_AUDIT_UPLOAD_MAC");
	if (override_mac && is_valid_mac_address_string(override_mac)) {
		snprintf(mac_buf, mac_buf_len, "%s", override_mac);
		return 0;
	}

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

char *uboot_http_build_upload_uri(const char *base_uri, const char *upload_type, const char *file_path)
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

	if (uboot_http_get_upload_mac(base_uri, mac_addr, sizeof(mac_addr)) < 0)
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

int uboot_http_post_log_message(const char *base_uri, const char *message,
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

	upload_uri = uboot_http_build_upload_uri(base_uri, "log", NULL);
	if (!upload_uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build log upload URI");
		return -1;
	}

	rc = uboot_http_post(upload_uri,
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

int uboot_http_post(const char *uri, const uint8_t *data, size_t len,
		 const char *content_type, bool insecure, bool verbose,
		 char *errbuf, size_t errbuf_len)
{
	CURL *curl;
	CURLcode rc;
	long http_code = 0;
	struct curl_slist *headers = NULL;
	char header_line[256];
	static bool curl_global_ready;
	bool is_https = false;
	char *normalized_uri = NULL;
	const char *effective_uri = uri;
	struct curl_ssl_ctx_error_data ssl_ctx_err = { errbuf, errbuf_len };

	if (errbuf && errbuf_len)
		errbuf[0] = '\0';

	if (!uri || !*uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP URI is empty");
		return -1;
	}

	is_https = !strncmp(uri, "https://", 8);
	if (!strncmp(uri, "http://", 7)) {
		normalized_uri = uboot_http_uri_normalize_default_port(uri, 80);
	} else if (is_https) {
		normalized_uri = uboot_http_uri_normalize_default_port(uri, 443);
	}
	if ((!strncmp(uri, "http://", 7) || is_https) && !normalized_uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to normalize HTTP URI");
		return -1;
	}
	if (normalized_uri)
		effective_uri = normalized_uri;

	fw_audit_force_conservative_powerpc_crypto_caps();

	if (!curl_global_ready) {
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "curl_global_init failed");
			free(normalized_uri);
			return -1;
		}
		curl_global_ready = true;
	}

	curl = curl_easy_init();
	if (!curl) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "curl_easy_init failed");
		free(normalized_uri);
		return -1;
	}

	if (!content_type || !*content_type)
		content_type = "text/plain; charset=utf-8";
	if (verbose) {
		fprintf(stderr,
			"HTTP POST request uri=%s bytes=%zu content-type=%s insecure=%s\n",
			effective_uri,
			len,
			content_type,
			insecure ? "true" : "false");
	}
	snprintf(header_line, sizeof(header_line), "Content-Type: %s", content_type);
	headers = curl_slist_append(headers, header_line);
	if (!headers) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to prepare HTTP headers");
		curl_easy_cleanup(curl);
		free(normalized_uri);
		return -1;
	}
	curl_easy_setopt(curl, CURLOPT_URL, effective_uri);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)data);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)len);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
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
				curl_slist_free_all(headers);
				curl_easy_cleanup(curl);
				free(normalized_uri);
				return -1;
			}
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
		free(normalized_uri);
		return -1;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	if (http_code < 200 || http_code >= 300) {
		if (verbose)
			fprintf(stderr, "HTTP POST response failure uri=%s status=%ld\n",
				effective_uri, http_code);
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP status %ld", http_code);
		free(normalized_uri);
		return -1;
	}

	if (verbose)
		fprintf(stderr, "HTTP POST success uri=%s status=%ld\n", effective_uri, http_code);

	free(normalized_uri);

	return 0;
}

int uboot_http_get_to_file(const char *uri, const char *output_path,
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

	fw_audit_install_sigill_debug_handler();
	fw_audit_set_sigill_stage("download-file:entry");

	if (!strncmp(uri, "http://", 7))
		return simple_http_get_to_file(uri, output_path, verbose, errbuf, errbuf_len);
	if (!strncmp(uri, "https://", 8))
		return simple_https_get_to_file(uri, output_path, insecure, verbose, errbuf, errbuf_len);

	is_https = !strncmp(uri, "https://", 8);
	if (!strncmp(uri, "http://", 7)) {
		normalized_uri = uboot_http_uri_normalize_default_port(uri, 80);
	} else if (is_https) {
		normalized_uri = uboot_http_uri_normalize_default_port(uri, 443);
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

	fw_audit_set_sigill_stage("download-file:curl_global_init");
	fw_audit_force_conservative_powerpc_crypto_caps();

	if (!curl_global_ready) {
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "curl_global_init failed");
			free(normalized_uri);
			return -1;
		}
		curl_global_ready = true;
	}

	fw_audit_set_sigill_stage("download-file:fopen");
	fp = fopen(output_path, "wb");
	if (!fp) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "cannot open output file %s: %s", output_path, strerror(errno));
		free(normalized_uri);
		return -1;
	}

	fw_audit_set_sigill_stage("download-file:curl_easy_init");
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

	fw_audit_set_sigill_stage("download-file:curl_setopt");
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

	fw_audit_set_sigill_stage("download-file:curl_perform");
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

	fw_audit_set_sigill_stage("download-file:curl_getinfo");
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

	fw_audit_set_sigill_stage("download-file:success");
	free(normalized_uri);
	return 0;
}

void uboot_crc32_init(uint32_t table[256])
{
	const uint32_t poly = 0xEDB88320U;

	if (!table)
		return;

	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int j = 0; j < 8; j++)
			c = (c & 1U) ? (poly ^ (c >> 1)) : (c >> 1);
		table[i] = c;
	}
}

uint32_t uboot_crc32_calc(const uint32_t table[256], const uint8_t *buf, size_t len)
{
	uint32_t c = 0xFFFFFFFFU;

	if (!table || !buf)
		return 0;

	for (size_t i = 0; i < len; i++)
		c = table[(c ^ buf[i]) & 0xFFU] ^ (c >> 8);

	return c ^ 0xFFFFFFFFU;
}

int uboot_get_mtd_index(const char *dev, char *idx, size_t idx_sz)
{
	const char *base = strrchr(dev, '/');
	const char *p;
	size_t j = 0;

	if (!idx || idx_sz < 2)
		return -1;

	base = base ? base + 1 : dev;
	if (!strncmp(base, "mtdblock", 8))
		p = base + 8;
	else if (!strncmp(base, "mtd", 3))
		p = base + 3;
	else
		return -1;

	while (*p >= '0' && *p <= '9' && j < idx_sz - 1)
		idx[j++] = *p++;

	if (!j)
		return -1;
	if (*p && strcmp(p, "ro"))
		return -1;

	idx[j] = '\0';
	return 0;
}

uint64_t uboot_guess_size_from_sysfs(const char *dev)
{
	char idx[32], path[256];

	if (uboot_get_mtd_index(dev, idx, sizeof(idx)))
		return 0;
	snprintf(path, sizeof(path), "/sys/class/mtd/mtd%s/size", idx);
	return read_u64_from_file(path);
}

uint64_t uboot_guess_erasesize_from_sysfs(const char *dev)
{
	char idx[32], path[256];

	if (uboot_get_mtd_index(dev, idx, sizeof(idx)))
		return 0;
	snprintf(path, sizeof(path), "/sys/class/mtd/mtd%s/erasesize", idx);
	return read_u64_from_file(path);
}

static void make_proc_mtd_name(const char *dev, char *out, size_t out_sz)
{
	char idx[32];
	size_t idx_len;

	if (!out || out_sz < 5) {
		if (out && out_sz)
			*out = '\0';
		return;
	}

	if (uboot_get_mtd_index(dev, idx, sizeof(idx))) {
		*out = '\0';
		return;
	}

	out[0] = 'm';
	out[1] = 't';
	out[2] = 'd';

	idx_len = strnlen(idx, out_sz - 4);
	memcpy(out + 3, idx, idx_len);
	out[3 + idx_len] = '\0';
}

uint64_t uboot_guess_size_from_proc_mtd(const char *dev)
{
	char want[32], line[256];
	FILE *fp;

	make_proc_mtd_name(dev, want, sizeof(want));
	if (!want[0])
		return 0;

	fp = fopen("/proc/mtd", "r");
	if (!fp)
		return 0;

	while (fgets(line, sizeof(line), fp)) {
		char name[32];
		unsigned long long size;
		if (sscanf(line, "%31[^:]: %llx", name, &size) == 2 && !strcmp(name, want)) {
			fclose(fp);
			return (uint64_t)size;
		}
	}

	fclose(fp);
	return 0;
}

uint64_t uboot_guess_erasesize_from_proc_mtd(const char *dev)
{
	char want[32], line[256];
	FILE *fp;

	make_proc_mtd_name(dev, want, sizeof(want));
	if (!want[0])
		return 0;

	fp = fopen("/proc/mtd", "r");
	if (!fp)
		return 0;

	while (fgets(line, sizeof(line), fp)) {
		char name[32];
		unsigned long long size, erase;
		if (sscanf(line, "%31[^:]: %llx %llx", name, &size, &erase) == 3 && !strcmp(name, want)) {
			fclose(fp);
			return (uint64_t)erase;
		}
	}

	fclose(fp);
	return 0;
}

static int get_ubi_indices(const char *dev, unsigned int *ubi, unsigned int *vol)
{
	const char *base = strrchr(dev, '/');
	char extra;

	if (!ubi || !vol)
		return -1;

	base = base ? base + 1 : dev;
	if (!strncmp(base, "ubiblock", 8))
		base += 8;
	else if (!strncmp(base, "ubi", 3))
		base += 3;
	else
		return -1;

	if (sscanf(base, "%u_%u%c", ubi, vol, &extra) != 2)
		return -1;

	return 0;
}

uint64_t uboot_guess_size_from_ubi_sysfs(const char *dev)
{
	unsigned int ubi, vol;
	char path[256];
	uint64_t data_bytes;
	uint64_t reserved_ebs;
	uint64_t usable_eb_size;

	if (get_ubi_indices(dev, &ubi, &vol))
		return 0;

	snprintf(path, sizeof(path), "/sys/class/ubi/ubi%u_%u/data_bytes", ubi, vol);
	data_bytes = read_u64_from_file(path);
	if (data_bytes)
		return data_bytes;

	snprintf(path, sizeof(path), "/sys/class/ubi/ubi%u_%u/reserved_ebs", ubi, vol);
	reserved_ebs = read_u64_from_file(path);
	if (!reserved_ebs)
		return 0;

	snprintf(path, sizeof(path), "/sys/class/ubi/ubi%u/usable_eb_size", ubi);
	usable_eb_size = read_u64_from_file(path);
	if (!usable_eb_size)
		return 0;

	return reserved_ebs * usable_eb_size;
}

uint64_t uboot_guess_step_from_ubi_sysfs(const char *dev)
{
	unsigned int ubi, vol;
	char path[256];
	uint64_t step;

	if (get_ubi_indices(dev, &ubi, &vol))
		return 0;

	snprintf(path, sizeof(path), "/sys/class/ubi/ubi%u/min_io_size", ubi);
	step = read_u64_from_file(path);
	if (step)
		return step;

	snprintf(path, sizeof(path), "/sys/class/ubi/ubi%u/usable_eb_size", ubi);
	return read_u64_from_file(path);
}

static const char *dev_basename(const char *dev)
{
	const char *base;

	if (!dev)
		return NULL;

	base = strrchr(dev, '/');
	return base ? base + 1 : dev;
}

uint64_t uboot_guess_size_from_block_sysfs(const char *dev)
{
	const char *base = dev_basename(dev);
	char path[PATH_MAX];
	uint64_t sectors;
	uint64_t logical_block_size;

	if (!base || !*base)
		return 0;

	snprintf(path, sizeof(path), "/sys/class/block/%s/size", base);
	sectors = read_u64_from_file(path);
	if (!sectors)
		return 0;

	snprintf(path, sizeof(path), "/sys/class/block/%s/queue/logical_block_size", base);
	logical_block_size = read_u64_from_file(path);
	if (!logical_block_size)
		logical_block_size = 512;

	return sectors * logical_block_size;
}

uint64_t uboot_guess_step_from_block_sysfs(const char *dev)
{
	const char *base = dev_basename(dev);
	char path[PATH_MAX];
	uint64_t step;

	if (!base || !*base)
		return 0;

	snprintf(path, sizeof(path), "/sys/class/block/%s/queue/minimum_io_size", base);
	step = read_u64_from_file(path);
	if (step)
		return step;

	snprintf(path, sizeof(path), "/sys/class/block/%s/queue/logical_block_size", base);
	step = read_u64_from_file(path);
	if (step)
		return step;

	return 512;
}

uint64_t uboot_guess_size_any(const char *dev)
{
	uint64_t sz = uboot_guess_size_from_sysfs(dev);

	if (!sz)
		sz = uboot_guess_size_from_proc_mtd(dev);
	if (!sz)
		sz = uboot_guess_size_from_ubi_sysfs(dev);
	if (!sz)
		sz = uboot_guess_size_from_block_sysfs(dev);

	return sz;
}

uint64_t uboot_guess_step_any(const char *dev)
{
	uint64_t step = uboot_guess_erasesize_from_sysfs(dev);

	if (!step)
		step = uboot_guess_erasesize_from_proc_mtd(dev);
	if (!step)
		step = uboot_guess_step_from_ubi_sysfs(dev);
	if (!step)
		step = uboot_guess_step_from_block_sysfs(dev);

	return step;
}

int uboot_glob_scan_devices(glob_t *out, unsigned int flags)
{
	const char *patterns[8];
	size_t n = 0;
	bool did_call = false;

	if (!out)
		return -1;

	memset(out, 0, sizeof(*out));

	if (flags & FW_SCAN_GLOB_MTDBLOCK)
		patterns[n++] = "/dev/mtdblock[0-9]*";
	if (flags & FW_SCAN_GLOB_MTDCHAR)
		patterns[n++] = "/dev/mtd[0-9]*";
	if (flags & FW_SCAN_GLOB_UBI)
		patterns[n++] = "/dev/ubi[0-9]*_[0-9]*";
	if (flags & FW_SCAN_GLOB_UBIBLOCK)
		patterns[n++] = "/dev/ubiblock[0-9]*_[0-9]*";
	if (flags & FW_SCAN_GLOB_MMCBLK) {
		patterns[n++] = "/dev/mmcblk[0-9]*";
		patterns[n++] = "/dev/mmcblk[0-9]*p[0-9]*";
	}
	if (flags & FW_SCAN_GLOB_SDBLK) {
		patterns[n++] = "/dev/sd[a-z]";
		patterns[n++] = "/dev/sd[a-z][0-9]*";
	}

	for (size_t i = 0; i < n; i++) {
		int rc = glob(patterns[i], did_call ? GLOB_APPEND : 0, NULL, out);
		did_call = true;
		if (rc == GLOB_NOMATCH)
			continue;
		if (rc != 0) {
			globfree(out);
			memset(out, 0, sizeof(*out));
			return -1;
		}
	}

	return 0;
}

static int add_created_node(char ***nodes, size_t *count, const char *path)
{
	char **tmp;
	char *dup;

	if (!nodes || !count || !path)
		return -1;

	dup = strdup(path);
	if (!dup)
		return -1;

	tmp = realloc(*nodes, (*count + 1) * sizeof(*tmp));
	if (!tmp) {
		free(dup);
		return -1;
	}

	*nodes = tmp;
	(*nodes)[*count] = dup;
	(*count)++;
	return 0;
}

void uboot_free_created_nodes(char **nodes, size_t count)
{
	if (!nodes)
		return;

	for (size_t i = 0; i < count; i++)
		free(nodes[i]);

	free(nodes);
}

static void create_node_if_missing(const char *path, mode_t mode, dev_t devno, bool verbose,
					   char ***created_nodes, size_t *created_count)
{
	struct stat st;

	if (!stat(path, &st))
		return;
	if (errno != ENOENT)
		return;

	if (mknod(path, mode, devno) < 0) {
		if (verbose)
			fprintf(stderr, "Warning: cannot create %s: %s\n", path, strerror(errno));
		return;
	}

	if (created_nodes && created_count && add_created_node(created_nodes, created_count, path) < 0) {
		if (verbose)
			fprintf(stderr, "Warning: failed to track created node %s\n", path);
	}

	if (verbose)
		printf("Created missing node: %s\n", path);
}

static int read_major_minor_from_sysfs(const char *dev_attr_path,
				       unsigned int *major_out,
				       unsigned int *minor_out)
{
	char buf[64];
	int fd;
	ssize_t n;
	unsigned int major, minor;

	if (!major_out || !minor_out)
		return -1;

	fd = open(dev_attr_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;

	buf[n] = '\0';
	if (sscanf(buf, "%u:%u", &major, &minor) != 2)
		return -1;

	*major_out = major;
	*minor_out = minor;
	return 0;
}

static bool str_all_digits(const char *s)
{
	if (!s || !*s)
		return false;

	for (const char *p = s; *p; p++) {
		if (*p < '0' || *p > '9')
			return false;
	}

	return true;
}

static bool is_sd_block_name(const char *name)
{
	if (!name || strncmp(name, "sd", 2))
		return false;
	if (name[2] < 'a' || name[2] > 'z')
		return false;
	if (name[3] == '\0')
		return true;

	return str_all_digits(name + 3);
}

static bool is_emmc_block_name(const char *name)
{
	const char *p;

	if (!name || strncmp(name, "mmcblk", 6))
		return false;

	p = name + 6;
	while (*p >= '0' && *p <= '9')
		p++;
	if (p == name + 6)
		return false;
	if (*p == '\0')
		return true;
	if (*p != 'p')
		return false;

	return str_all_digits(p + 1);
}

int uboot_ensure_block_nodes_collect(bool verbose, bool include_sd, bool include_emmc,
				  char ***created_nodes, size_t *created_count)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir("/sys/class/block");
	if (!dir)
		return -1;

	while ((de = readdir(dir))) {
		char dev_attr[PATH_MAX];
		char devnode[PATH_MAX];
		unsigned int major;
		unsigned int minor;

		if (!include_sd && is_sd_block_name(de->d_name))
			continue;
		if (!include_emmc && is_emmc_block_name(de->d_name))
			continue;
		if ((include_sd && is_sd_block_name(de->d_name)) ||
		    (include_emmc && is_emmc_block_name(de->d_name))) {
			snprintf(dev_attr, sizeof(dev_attr), "/sys/class/block/%s/dev", de->d_name);
			snprintf(devnode, sizeof(devnode), "/dev/%s", de->d_name);

			if (read_major_minor_from_sysfs(dev_attr, &major, &minor))
				continue;

			create_node_if_missing(devnode, S_IFBLK | 0600, makedev(major, minor), verbose,
				created_nodes, created_count);
		}
	}

	closedir(dir);
	return 0;
}

void uboot_ensure_block_nodes(bool verbose, bool include_sd, bool include_emmc)
{
	uboot_ensure_block_nodes_collect(verbose, include_sd, include_emmc, NULL, NULL);
}

int uboot_ensure_mtd_nodes_collect(bool verbose, char ***created_nodes, size_t *created_count)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir("/sys/class/mtd");
	if (!dir)
		return -1;

	while ((de = readdir(dir))) {
		unsigned int idx;
		char extra;
		char blockpath[64];

		if (sscanf(de->d_name, "mtd%u%c", &idx, &extra) != 1)
			continue;

		snprintf(blockpath, sizeof(blockpath), "/dev/mtdblock%u", idx);

		create_node_if_missing(blockpath, S_IFBLK | 0600, makedev(31, idx), verbose,
			created_nodes, created_count);
	}

	closedir(dir);
	return 0;
}

void uboot_ensure_mtd_nodes(bool verbose)
{
	uboot_ensure_mtd_nodes_collect(verbose, NULL, NULL);
}

int uboot_ensure_ubi_nodes_collect(bool verbose, char ***created_nodes, size_t *created_count)
{
	DIR *dir;
	struct dirent *de;
	const char *ubi_prefix = "/sys/class/ubi/";
	const char *blk_prefix = "/sys/class/block/";
	const char *dev_suffix = "/dev";

	dir = opendir("/sys/class/ubi");
	if (dir) {
		while ((de = readdir(dir))) {
			unsigned int ubi, vol;
			char extra;
			char dev_attr[256];
			char devnode[64];
			unsigned int major, minor;
			size_t name_len;
			size_t prefix_len;
			size_t suffix_len;

			if (sscanf(de->d_name, "ubi%u_%u%c", &ubi, &vol, &extra) == 2) {
				snprintf(devnode, sizeof(devnode), "/dev/ubi%u_%u", ubi, vol);
			} else if (sscanf(de->d_name, "ubi%u%c", &ubi, &extra) == 1) {
				snprintf(devnode, sizeof(devnode), "/dev/ubi%u", ubi);
			} else {
				continue;
			}

			name_len = strnlen(de->d_name, sizeof(dev_attr));
			prefix_len = strlen(ubi_prefix);
			suffix_len = strlen(dev_suffix);
			if (name_len >= sizeof(dev_attr))
				continue;
			if (prefix_len + name_len + suffix_len + 1 > sizeof(dev_attr))
				continue;

			memcpy(dev_attr, ubi_prefix, prefix_len);
			memcpy(dev_attr + prefix_len, de->d_name, name_len);
			memcpy(dev_attr + prefix_len + name_len, dev_suffix, suffix_len + 1);

			if (read_major_minor_from_sysfs(dev_attr, &major, &minor))
				continue;

			create_node_if_missing(devnode, S_IFCHR | 0600, makedev(major, minor), verbose,
				created_nodes, created_count);
		}

		closedir(dir);
	}

	dir = opendir("/sys/class/block");
	if (!dir)
		return 0;

	while ((de = readdir(dir))) {
		unsigned int ubi, vol;
		char extra;
		char dev_attr[256];
		char devnode[64];
		unsigned int major, minor;
		size_t name_len;
		size_t prefix_len;
		size_t suffix_len;

		if (sscanf(de->d_name, "ubiblock%u_%u%c", &ubi, &vol, &extra) != 2)
			continue;

		snprintf(devnode, sizeof(devnode), "/dev/ubiblock%u_%u", ubi, vol);

		name_len = strnlen(de->d_name, sizeof(dev_attr));
		prefix_len = strlen(blk_prefix);
		suffix_len = strlen(dev_suffix);
		if (name_len >= sizeof(dev_attr))
			continue;
		if (prefix_len + name_len + suffix_len + 1 > sizeof(dev_attr))
			continue;

		memcpy(dev_attr, blk_prefix, prefix_len);
		memcpy(dev_attr + prefix_len, de->d_name, name_len);
		memcpy(dev_attr + prefix_len + name_len, dev_suffix, suffix_len + 1);

		if (read_major_minor_from_sysfs(dev_attr, &major, &minor))
			continue;

		create_node_if_missing(devnode, S_IFBLK | 0600, makedev(major, minor), verbose,
			created_nodes, created_count);
	}

	closedir(dir);
	return 0;
}

void uboot_ensure_ubi_nodes(bool verbose)
{
	uboot_ensure_ubi_nodes_collect(verbose, NULL, NULL);
}
