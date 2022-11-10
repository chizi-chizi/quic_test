#ifndef _TOKEN_H_INCLUDED_
#define _TOKEN_H_INCLUDED_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>


#define  NGX_OK          0
#define  NGX_ERROR      -1
#define  NGX_AGAIN      -2
#define  NGX_BUSY       -3
#define  NGX_DONE       -4
#define  NGX_DECLINED   -5
#define  NGX_ABORT      -6

#define NGX_QUIC_MAX_TOKEN_SIZE              64
    /* SHA-1(addr)=20 + sizeof(time_t) + retry(1) + odcid.len(1) + odcid */

/* RFC 3602, 2.1 and 2.4 for AES-CBC block size and IV length */
#define NGX_QUIC_AES_256_CBC_IV_LEN          16
#define NGX_QUIC_AES_256_CBC_BLOCK_SIZE      16
#define NGX_QUIC_MAX_CID_LEN                             20


#define NGX_QUIC_MAX_UDP_PAYLOAD_SIZE        65527

#define NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT  3
#define NGX_QUIC_DEFAULT_MAX_ACK_DELAY       25
#define NGX_QUIC_DEFAULT_HOST_KEY_LEN        32
#define NGX_QUIC_SR_KEY_LEN                  32
#define NGX_QUIC_AV_KEY_LEN                  32

#define NGX_QUIC_SR_TOKEN_LEN                16

#define NGX_QUIC_MIN_INITIAL_SIZE            1200

#define NGX_QUIC_STREAM_SERVER_INITIATED     0x01
#define NGX_QUIC_STREAM_UNIDIRECTIONAL       0x02

#define     ngx_log_debug2(level, log, error, format, args...) printf(format, ##args)
#define     ngx_log_error ngx_log_debug2

typedef struct {
    size_t      len;
    u_char     *data;
} ngx_str_t;

typedef intptr_t        ngx_int_t;
typedef unsigned char u_char;
typedef unsigned int u_int;
//typedef u_int               uintptr_t;
typedef uintptr_t       ngx_uint_t;
typedef uint32_t            in_addr_t;

typedef struct {
    ngx_str_t                                   token;
    /* cleartext fields */
    ngx_str_t                                   odcid; /* retry packet tag */
    ngx_str_t                                   dcid; 
    unsigned                                    retried:1;
} ngx_quic_header_t;

typedef void  ngx_pool_t ;
typedef void ngx_log_t ;
#define ngx_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
#define ngx_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))
#define ngx_memzero(buf, n)       (void) memset(buf, 0, n)
#define ngx_memcmp(s1, s2, n)  memcmp((const char *) s1, (const char *) s2, n)


static inline u_char* ngx_pstrdup(ngx_pool_t *pool, ngx_str_t *src){
    u_char *dst;
    dst = malloc(src->len);
    if (dst == NULL){
        return NULL;
    }
    memcpy(dst, src->data, src->len);
    return dst;
}

#define ngx_time()  time(NULL)

static inline void* ngx_pnalloc(ngx_pool_t *pool, size_t size){
    return malloc(size);
}
struct ngx_connection_s {
    ngx_log_t          *log;
    ngx_pool_t         *pool;
        struct sockaddr    *sockaddr;
    socklen_t           socklen;
};
typedef struct ngx_connection_s      ngx_connection_t;

ngx_int_t ngx_quic_new_token(ngx_connection_t *c, struct sockaddr *sockaddr,
    socklen_t socklen, u_char *key, ngx_str_t *token, ngx_str_t *odcid,
    time_t exp, ngx_uint_t is_retry);
#endif
