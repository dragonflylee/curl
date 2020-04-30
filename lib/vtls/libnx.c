/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010 - 2011, Hoi-Ho Chan, <hoiho.chan@gmail.com>
 * Copyright (C) 2012 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/*
 * Source file for all libnx-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 *
 */

#include "curl_setup.h"

#ifdef USE_LIBNX

#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "libnx.h"
#include "vtls.h"
#include "vtls_int.h"
#include "parsedate.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#include "multiif.h"

#undef BIT
#include <switch.h>

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

struct libnx_ssl_backend_data {
  SslContext context;
  SslConnection conn;
};

#define BACKEND ((struct libnx_ssl_backend_data *)connssl->backend)

/* ALPN for http2? */
#ifdef USE_NGHTTP2
#  undef HAS_ALPN
#  define HAS_ALPN
#endif


/* See https://tls.mbed.org/discussions/generic/
   howto-determine-exact-buffer-len-for-mbedtls_pk_write_pubkey_der
*/
/*
#define RSA_PUB_DER_MAX_BYTES   (38 + 2 * MBEDTLS_MPI_MAX_SIZE)
#define ECP_PUB_DER_MAX_BYTES   (30 + 2 * MBEDTLS_ECP_MAX_BYTES)

#define PUB_DER_MAX_BYTES   (RSA_PUB_DER_MAX_BYTES > ECP_PUB_DER_MAX_BYTES ? \
                             RSA_PUB_DER_MAX_BYTES : ECP_PUB_DER_MAX_BYTES)
*/

static CURLcode libnx_version_from_curl(u32 *outver, long version)
{
  switch(version) {
    case CURL_SSLVERSION_TLSv1_0:
      *outver = SslVersion_TlsV10;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_1:
      *outver = SslVersion_TlsV11;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_2:
      *outver = SslVersion_TlsV12;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_3:
      if (hosversionAtLeast(11, 0, 0)) {
        *outver = SslVersion_TlsV13;
        return CURLE_OK;
      }
      break;
  }
  return CURLE_SSL_CONNECT_ERROR;
}

static CURLcode
set_ssl_version_min_max(struct ssl_primary_config *conn_config,
                        struct Curl_easy *data, u32 *out_version)
{
  u32 libnx_ver_min=0;
  u32 libnx_ver_max=0;
  long ssl_version = conn_config->version;
  long ssl_version_max = conn_config->version_max;
  CURLcode result = CURLE_OK;

  switch(ssl_version) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
      ssl_version = CURL_SSLVERSION_TLSv1_0;
      if(ssl_version_max == CURL_SSLVERSION_MAX_NONE || ssl_version_max == CURL_SSLVERSION_MAX_DEFAULT) {
        *out_version = SslVersion_Auto;
        return result;
      }
      break;
  }

  switch(ssl_version_max) {
    case CURL_SSLVERSION_MAX_NONE:
    case CURL_SSLVERSION_MAX_DEFAULT:
      ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2;
      break;
  }

  result = libnx_version_from_curl(&libnx_ver_min, ssl_version);
  if(result) {
    failf(data, "unsupported min version passed via CURLOPT_SSLVERSION");
    return result;
  }
  result = libnx_version_from_curl(&libnx_ver_max, ssl_version_max >> 16);
  if(result) {
    failf(data, "unsupported max version passed via CURLOPT_SSLVERSION");
    return result;
  }

  *out_version = libnx_ver_min | libnx_ver_max;

  return result;
}

static CURLcode
libnx_connect_step1(struct Curl_cfilter *cf,
                    struct Curl_easy *data, bool nonblocking)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  curl_socket_t sockfd = Curl_conn_cf_get_socket(cf, data);
  const struct curl_blob *ca_info_blob = conn_config->ca_info_blob;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  const char * const ssl_cafile =
    /* CURLOPT_CAINFO_BLOB overrides CURLOPT_CAINFO */
    (ca_info_blob ? NULL : conn_config->CAfile);
  const bool verifypeer = conn_config->verifypeer;
  const char * const ssl_capath = conn_config->CApath;
  char * const ssl_cert = ssl_config->primary.clientcert;
  const char * const ssl_crlfile = ssl_config->primary.CRLfile;
  const char *hostname = connssl->peer.hostname;
  const long int port = Curl_ssl_cf_is_proxy(cf) ? cf->conn->conn_to_port : cf->conn->remote_port;
  int ret = -1;
  Result rc=0;
  char errorbuf[128];
  errorbuf[0] = 0;

  /* ssl-service only supports TLS 1.0-1.2 */
  if((conn_config->version == CURL_SSLVERSION_SSLv2) ||
     (conn_config->version == CURL_SSLVERSION_SSLv3)) {
    failf(data, "Not supported SSL version");
    return CURLE_NOT_BUILT_IN;
  }

  u32 ssl_version=0;
  switch(conn_config->version) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
  case CURL_SSLVERSION_TLSv1_0:
  case CURL_SSLVERSION_TLSv1_1:
  case CURL_SSLVERSION_TLSv1_2:
  case CURL_SSLVERSION_TLSv1_3:
    {
      CURLcode result = set_ssl_version_min_max(conn_config, data, &ssl_version);
      if(result != CURLE_OK)
        return result;
      break;
    }
  default:
    failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
    return CURLE_SSL_CONNECT_ERROR;
  }

  rc = sslCreateContext(&BACKEND->context, ssl_version);
  if(R_FAILED(rc)) return CURLE_SSL_CONNECT_ERROR;

  /* give application a chance to interfere with context set up. */
  if(data->set.ssl.fsslctx) {
    ret = (*data->set.ssl.fsslctx)(data, &BACKEND->context,
                                   data->set.ssl.fsslctxp);
    if(ret) {
      failf(data, "error signaled by ssl ctx callback");
      return ret;
    }
  }
  else { /* Only setup the context if the application didn't. */
    rc = sslContextRegisterInternalPki(&BACKEND->context, SslInternalPki_DeviceClientCertDefault, NULL);
    if(R_FAILED(rc)) return CURLE_SSL_CONNECT_ERROR;

    /* TODO: Impl the rest of the cert loading, and only use sslContextRegisterInternalPki if nothing else was specified. */
  }

  rc = sslContextCreateConnection(&BACKEND->context, &BACKEND->conn);

  if(R_SUCCEEDED(rc))
    rc = sslConnectionSetOption(&BACKEND->conn, SslOptionType_DoNotCloseSocket, TRUE);

  if(R_SUCCEEDED(rc)) {
    ret = socketSslConnectionSetSocketDescriptor(&BACKEND->conn, (int)sockfd);
    if (ret==-1 && errno!=ENOENT) return CURLE_SSL_CONNECT_ERROR;
  }

  if(R_SUCCEEDED(rc))
    rc = sslConnectionSetHostName(&BACKEND->conn, hostname, strlen(hostname));

  /* This will fail on system-versions where this option isn't available, so ignore errors from this. */
  if(R_SUCCEEDED(rc))
    sslConnectionSetOption(&BACKEND->conn, SslOptionType_SkipDefaultVerify, TRUE);

  if(R_SUCCEEDED(rc)) {
    u32 verifyopt = SslVerifyOption_DateCheck;
    if(verifypeer) verifyopt |= SslVerifyOption_PeerCa;
    if(conn_config->verifyhost) verifyopt |= SslVerifyOption_HostName;
    rc = sslConnectionSetVerifyOption(&BACKEND->conn, verifyopt);
  }

  if(R_SUCCEEDED(rc))
    rc = sslConnectionSetSessionCacheMode(&BACKEND->conn, conn_config->sessionid ? SslSessionCacheMode_SessionId : SslSessionCacheMode_None);

  if(R_SUCCEEDED(rc))
    rc = sslConnectionSetIoMode(&BACKEND->conn, nonblocking ? SslIoMode_NonBlocking : SslIoMode_Blocking);

  if (R_FAILED(rc))
    return CURLE_SSL_CONNECT_ERROR;

  connssl->connecting_state = ssl_connect_2;

  return CURLE_OK;
}

static CURLcode
libnx_connect_step2(struct Curl_cfilter *cf,
                    struct Curl_easy *data)
{
  Result rc=0;
  struct ssl_connect_data *connssl = cf->ctx;

  u32 out_size=0, total_certs=0;
  rc = sslConnectionDoHandshake(&BACKEND->conn, &out_size, &total_certs, NULL, 0); /* TODO: server_certbuf */
  if(R_FAILED(rc)) {
      if(R_VALUE(rc) == MAKERESULT(123, 204)) /* PR_WOULD_BLOCK_ERROR */
        return CURLE_AGAIN;

      return R_VALUE(rc) == MAKERESULT(123, 207) ? CURLE_PEER_FAILED_VERIFICATION : CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_done;
  infof(data, "SSL connected\n");

  return CURLE_OK;
}

static ssize_t libnx_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                         const void *mem, size_t len,
                         CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = cf->ctx;
  Result rc=0;
  u32 out_size=0;

  rc = sslConnectionWrite(&BACKEND->conn, mem, len, &out_size);

  if(R_FAILED(rc)) {
    *curlcode = (R_VALUE(rc) == MAKERESULT(123, 204)) ? /* PR_WOULD_BLOCK_ERROR */
      CURLE_AGAIN : CURLE_WRITE_ERROR;
    return -1;
  }

  return out_size;
}

static void Curl_libnx_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  sslConnectionClose(&BACKEND->conn);
  sslContextClose(&BACKEND->context);
}

static ssize_t libnx_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                         char *buf, size_t buffersize,
                         CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = cf->ctx;
  Result rc=0;
  u32 out_size=0;

  memset(buf, 0, buffersize);
  rc = sslConnectionRead(&BACKEND->conn, buf, buffersize, &out_size);

  if(R_FAILED(rc)) {
    *curlcode = (R_VALUE(rc) == MAKERESULT(123, 204)) ? /* PR_WOULD_BLOCK_ERROR */
      CURLE_AGAIN : CURLE_RECV_ERROR;
    return -1;
  }

  return out_size;
}

static size_t Curl_libnx_version(char *buffer, size_t size)
{
  return msnprintf(buffer, size, "libnx");
}

/*
 * This function is used to determine connection status.
 *
 * Return codes:
 *     1 means the connection is still in place
 *     0 means the connection has been closed
 *    -1 means the connection status is unknown
 */
static int Curl_libnx_check_cxn(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  u8 buffer=0;
  u32 out_size=0;
  Result rc = sslConnectionPeek(&BACKEND->conn, &buffer, sizeof(buffer), &out_size);
  if(R_FAILED(rc)) {
    return R_VALUE(rc) == MAKERESULT(123, 204) ? 1 : -1; /* PR_WOULD_BLOCK_ERROR == connection is still in place, otherwise connection status unknown */
  }
  return out_size ? 1 : 0;
}

static CURLcode
libnx_connect_common(struct Curl_cfilter *cf,
                    struct Curl_easy *data,
                    bool nonblocking,
                    bool *done)
{
  Result rc=0;
  CURLcode retcode = CURLE_OK;
  struct ssl_connect_data *connssl = cf->ctx;
  timediff_t timeout_ms;
  int what;

  *done = FALSE;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    /* Find out how much more time we're allowed */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }
    retcode = libnx_connect_step1(cf, data, nonblocking);
  }

  if(!retcode && ssl_connect_2 == connssl->connecting_state) {
    /* Find out how much more time we're allowed */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }
    retcode = libnx_connect_step2(cf, data);
  }

  if(!retcode) {
    /* Reset our connect state machine */
    connssl->connecting_state = ssl_connect_1;

    connssl->state = ssl_connection_complete;
    *done = TRUE;

    return CURLE_OK;
  }

  if(retcode == CURLE_AGAIN) return CURLE_OK;
  if(retcode == CURLE_PEER_FAILED_VERIFICATION) {
    rc = sslConnectionGetVerifyCertError(&BACKEND->conn);
    if(R_VALUE(rc) != MAKERESULT(123, 301) && R_VALUE(rc) != MAKERESULT(123, 303) && R_VALUE(rc) != MAKERESULT(123, 304)) {
      if(R_VALUE(rc) == MAKERESULT(123, 323) ||
         R_VALUE(rc) == MAKERESULT(123, 1509) ||  /* SSL_ERROR_BAD_CERT_ALERT */
         R_VALUE(rc) == MAKERESULT(123, 1511) ||  /* SSL_ERROR_REVOKED_CERT_ALERT */
         R_VALUE(rc) == MAKERESULT(123, 1512))    /* SSL_ERROR_EXPIRED_CERT_ALERT */
        retcode = CURLE_SSL_CERTPROBLEM;
    }
  }

  return retcode;
}

static CURLcode Curl_libnx_connect_nonblocking(struct Curl_cfilter *cf,
                                            struct Curl_easy *data, bool *done)
{
  return libnx_connect_common(cf, data, TRUE, done);
}


static CURLcode Curl_libnx_connect(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  CURLcode retcode;
  bool done = FALSE;

  retcode = libnx_connect_common(cf, data, FALSE, &done);
  if(retcode)
    return retcode;

  DEBUGASSERT(done);

  return CURLE_OK;
}

/*
 * return 0 error initializing SSL
 * return 1 SSL initialized successfully
 */
static int Curl_libnx_init(void)
{
  return R_SUCCEEDED(sslInitialize(0x3));
}

static void Curl_libnx_cleanup(void)
{
  sslExit();
}

static bool Curl_libnx_data_pending(struct Curl_cfilter *cf,
                                 const struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  s32 tmp=0;
  return R_SUCCEEDED(sslConnectionPending(&BACKEND->conn, &tmp)) && tmp>0;
}

static CURLcode Curl_libnx_sha256sum(const unsigned char *input,
                                    size_t inputlen,
                                    unsigned char *sha256sum,
                                    size_t sha256len UNUSED_PARAM)
{
  (void)sha256len;
  sha256CalculateHash(sha256sum, input, inputlen);
  return CURLE_OK;
}

static void *Curl_libnx_get_internals(struct ssl_connect_data *connssl,
                                        CURLINFO info UNUSED_PARAM)
{
  (void)info;
  return &BACKEND->context;
}

const struct Curl_ssl Curl_ssl_libnx = {
  { CURLSSLBACKEND_LIBNX, "libnx" }, /* info */

  SSLSUPP_PINNEDPUBKEY |
  SSLSUPP_SSL_CTX |
  SSLSUPP_TLS13_CIPHERSUITES,

  sizeof(struct libnx_ssl_backend_data),

  Curl_libnx_init,                  /* init */
  Curl_libnx_cleanup,               /* cleanup */
  Curl_libnx_version,               /* version */
  Curl_libnx_check_cxn,             /* check_cxn */
  Curl_none_shutdown,               /* shutdown */
  Curl_libnx_data_pending,          /* data_pending */
  Curl_none_random,                 /* random */
  Curl_none_cert_status_request,    /* cert_status_request */
  Curl_libnx_connect,               /* connect */
  Curl_libnx_connect_nonblocking,   /* connect_nonblocking */
  Curl_ssl_adjust_pollset,          /* adjust_pollset */
  Curl_libnx_get_internals,         /* get_internals */
  Curl_libnx_close,                 /* close_one */
  Curl_none_close_all,              /* close_all */
  Curl_none_session_free,           /* session_free */
  Curl_none_set_engine,             /* set_engine */
  Curl_none_set_engine_default,     /* set_engine_default */
  Curl_none_engines_list,           /* engines_list */
  Curl_none_false_start,            /* false_start */
  Curl_libnx_sha256sum,             /* sha256sum */
  NULL,                             /* associate_connection */
  NULL,                             /* disassociate_connection */
  NULL,                             /* free_multi_ssl_backend_data */
  libnx_recv,                       /* recv decrypted data */
  libnx_send,                       /* send data to encrypt */
};

#endif /* USE_LIBNX */
