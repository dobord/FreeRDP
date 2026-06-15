/*
 * frdpd - FreeRDP RDP daemon listener
 *
 * This implementation demonstrates a minimal TLS/NLA-capable listener for the
 * FreeRDP-based RDP server.  The daemon reads a simple TOML configuration,
 * initialises an OpenSSL context, binds a TCP socket and accepts incoming
 * connections.  For each connection the server performs a TLS handshake and
 * then hands off authentication and session management to separate
 * components.  Proper privilege separation, error handling and FreeRDP API
 * integration are essential for a production system, but are elided here
 * for brevity.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/* Simple server configuration structure. */
typedef struct {
    char listen[64];
    char tls_cert[PATH_MAX];
    char tls_key[PATH_MAX];
    int max_connections;
} server_config;

/* Parse a minimal subset of the frdpd.toml configuration.  This is
 * intentionally simplistic and will ignore whitespace and unknown keys.
 */
static int parse_config(server_config *cfg, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    /* Provide defaults */
    strcpy(cfg->listen, "0.0.0.0:3389");
    cfg->tls_cert[0] = '\0';
    cfg->tls_key[0] = '\0';
    cfg->max_connections = 200;
    char line[256];
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, " listen = \"%63[^\"]\"", cfg->listen) == 1)
            continue;
        if (sscanf(line, " tls_cert = \"%1023[^\"]\"", cfg->tls_cert) == 1)
            continue;
        if (sscanf(line, " tls_key = \"%1023[^\"]\"", cfg->tls_key) == 1)
            continue;
        if (sscanf(line, " max_connections = %d", &cfg->max_connections) == 1)
            continue;
    }
    fclose(f);
    return 0;
}

/* Initialize an OpenSSL server context with the configured certificate and key. */
static SSL_CTX *init_tls(const char *cert_file, const char *key_file)
{
    SSL_library_init();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
        return NULL;
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static volatile int running = 1;

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    server_config cfg;
    if (parse_config(&cfg, "config/frdpd.toml") != 0) {
        fprintf(stderr, "Failed to load configuration\n");
        return 1;
    }
    if (cfg.tls_cert[0] == '\0' || cfg.tls_key[0] == '\0') {
        fprintf(stderr, "TLS certificate or key not configured\n");
        return 1;
    }

    SSL_CTX *ssl_ctx = init_tls(cfg.tls_cert, cfg.tls_key);
    if (!ssl_ctx) {
        fprintf(stderr, "Failed to initialize TLS context\n");
        return 1;
    }

    /* Split listen host and port */
    char host[64] = "";
    char *colon = strchr(cfg.listen, ':');
    if (!colon) {
        fprintf(stderr, "Invalid listen address: %s\n", cfg.listen);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }
    size_t hostlen = colon - cfg.listen;
    strncpy(host, cfg.listen, hostlen);
    host[hostlen] = '\0';
    const char *port = colon + 1;

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(strlen(host) ? host : NULL, port, &hints, &res) != 0) {
        fprintf(stderr, "getaddrinfo failed\n");
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    int listen_fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        listen_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (listen_fd < 0)
            continue;
        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (bind(listen_fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close(listen_fd);
        listen_fd = -1;
    }
    freeaddrinfo(res);
    if (listen_fd < 0) {
        fprintf(stderr, "Could not bind to %s\n", cfg.listen);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }
    if (listen(listen_fd, cfg.max_connections) < 0) {
        perror("listen");
        close(listen_fd);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    printf("frdpd: listening on %s (TLS)\n", cfg.listen);

    while (running) {
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof addr;
        int client_fd = accept(listen_fd, (struct sockaddr *)&addr, &addrlen);
        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }
        /* Perform TLS handshake.  In a real server this should be offloaded to
         * a worker thread or process. */
        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "TLS handshake failed\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }
        printf("Accepted TLS connection\n");
        /* TODO: perform NLA/CredSSP handshake and call frdp-authd via IPC */
        /* TODO: hand over to session manager for authentication and session creation */
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(listen_fd);
    SSL_CTX_free(ssl_ctx);
    printf("frdpd: shutting down\n");
    return 0;
}
