
/*
 * Copyright (C) Nginx, Inc.
 */
#include <stdio.h>
#include <stdlib.h>
#include<openssl/evp.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sha1.h"
#include "token.h"


#define NGX_QUIC_MAX_TOKEN_SIZE              64
    /* SHA-1(addr)=20 + sizeof(time_t) + retry(1) + odcid.len(1) + odcid */

/* RFC 3602, 2.1 and 2.4 for AES-CBC block size and IV length */
#define NGX_QUIC_AES_256_CBC_IV_LEN          16
#define NGX_QUIC_AES_256_CBC_BLOCK_SIZE      16


static void ngx_quic_address_hash(struct sockaddr *sockaddr, socklen_t socklen,
    ngx_uint_t no_port, u_char buf[20]);


ngx_int_t
ngx_quic_new_token(ngx_connection_t *c, struct sockaddr *sockaddr,
    socklen_t socklen, u_char *key, ngx_str_t *token, ngx_str_t *odcid,
    time_t exp, ngx_uint_t is_retry)
{
    int                len, iv_len;
    u_char            *p, *iv;
    EVP_CIPHER_CTX    *ctx;
    const EVP_CIPHER  *cipher;

    u_char             in[NGX_QUIC_MAX_TOKEN_SIZE];

    ngx_quic_address_hash(sockaddr, socklen, !is_retry, in);

    p = in + 20;

    p = ngx_cpymem(p, &exp, sizeof(time_t));

    *p++ = is_retry ? 1 : 0;

    if (odcid) {
        *p++ = odcid->len;
        p = ngx_cpymem(p, odcid->data, odcid->len);

    } else {
        *p++ = 0;
    }

    len = p - in;

    cipher = EVP_aes_256_cbc();
    iv_len = NGX_QUIC_AES_256_CBC_IV_LEN;

    token->len = iv_len + len + NGX_QUIC_AES_256_CBC_BLOCK_SIZE;
    token->data = ngx_pnalloc(NULL, token->len);
    if (token->data == NULL) {
        return NGX_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    iv = token->data;

    if (RAND_bytes(iv, iv_len) <= 0
        || !EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    token->len = iv_len;

    if (EVP_EncryptUpdate(ctx, token->data + token->len, &len, in, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    token->len += len;

    if (EVP_EncryptFinal_ex(ctx, token->data + token->len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    token->len += len;

    EVP_CIPHER_CTX_free(ctx);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic new token len:%ld: %s\n", token->len, token->data);

    return NGX_OK;
}


static void
ngx_quic_address_hash(struct sockaddr *sockaddr, socklen_t socklen,
    ngx_uint_t no_port, u_char buf[20])
{
    size_t                len;
    u_char               *data;
    ngx_sha1_t            sha1;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    len = (size_t) socklen;
    data = (u_char *) sockaddr;

    if (no_port) {
        switch (sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sockaddr;

            len = sizeof(struct in6_addr);
            data = sin6->sin6_addr.s6_addr;

            break;
#endif

        case AF_INET:
            sin = (struct sockaddr_in *) sockaddr;

            len = sizeof(in_addr_t);
            data = (u_char *) &sin->sin_addr;

            break;
        }
    }

    ngx_sha1_init(&sha1);
    ngx_sha1_update(&sha1, data, len);
    ngx_sha1_final(buf, &sha1);
}


ngx_int_t
ngx_quic_validate_token(ngx_connection_t *c, u_char *key,
    ngx_quic_header_t *pkt)
{
    int                len, tlen, iv_len;
    u_char            *iv, *p;
    time_t             now, exp;
    size_t             total;
    ngx_str_t          odcid;
    EVP_CIPHER_CTX    *ctx;
    const EVP_CIPHER  *cipher;

    u_char             addr_hash[20];
    u_char             tdec[NGX_QUIC_MAX_TOKEN_SIZE];

    /* Retry token or NEW_TOKEN in a previous connection */

    cipher = EVP_aes_256_cbc();
    iv = pkt->token.data;
    iv_len = NGX_QUIC_AES_256_CBC_IV_LEN;

    /* sanity checks */

    if (pkt->token.len < (size_t) iv_len + NGX_QUIC_AES_256_CBC_BLOCK_SIZE) {
        goto garbage;
    }

    if (pkt->token.len > (size_t) iv_len + NGX_QUIC_MAX_TOKEN_SIZE) {
        goto garbage;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    p = pkt->token.data + iv_len;
    len = pkt->token.len - iv_len;

    if (EVP_DecryptUpdate(ctx, tdec, &len, p, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        goto garbage;
    }
    total = len;

    if (EVP_DecryptFinal_ex(ctx, tdec + len, &tlen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        goto garbage;
    }
    total += tlen;

    EVP_CIPHER_CTX_free(ctx);

    if (total < (20 + sizeof(time_t) + 2)) {
        goto garbage;
    }

    p = tdec + 20;

    ngx_memcpy(&exp, p, sizeof(time_t));
    p += sizeof(time_t);

    pkt->retried = (*p++ == 1);

    ngx_quic_address_hash(c->sockaddr, c->socklen, !pkt->retried, addr_hash);

    if (ngx_memcmp(tdec, addr_hash, 20) != 0) {
        goto bad_token;
    }

    odcid.len = *p++;
    if (odcid.len) {
        if (odcid.len > NGX_QUIC_MAX_CID_LEN) {
            goto bad_token;
        }

        if ((size_t)(tdec + total - p) < odcid.len) {
            goto bad_token;
        }

        odcid.data = p;
    }

    now = ngx_time();

    if (now > exp) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "quic expired token");
        return NGX_DECLINED;
    }

    if (odcid.len) {
        pkt->odcid.len = odcid.len;
        pkt->odcid.data = ngx_pstrdup(c->pool, &odcid);
        if (pkt->odcid.data == NULL) {
            return NGX_ERROR;
        }

    } else {
        pkt->odcid = pkt->dcid;
    }


    return NGX_OK;

garbage:

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "quic garbage token");

    return NGX_ABORT;

bad_token:

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "quic invalid token");

    return NGX_DECLINED;
}

