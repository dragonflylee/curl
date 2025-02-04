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
#include "x509asn1.h"

#undef BIT
#include <switch.h>

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#include <dirent.h>

struct libnx_ssl_backend_data {
  SslContext context;
  SslConnection conn;
  u8 *certbuf;
  size_t certbuf_size;
};

#define BACKEND ((struct libnx_ssl_backend_data *)connssl->backend)

/* ALPN for http2? */
#ifdef USE_NGHTTP2
#  undef HAS_ALPN
#  define HAS_ALPN
#endif


static bool load_file(const char *path, void **buffer, size_t *size)
{
  struct stat filestat;
  size_t tmp = 0;
  *buffer = NULL;
  *size = 0;
  if(stat(path, &filestat)==-1)
    return FALSE;

  FILE *f = fopen(path, "rb");
  if(!f)
    return FALSE;

  *size = filestat.st_size;
  *buffer = calloc(1, *size);

  if(*buffer)
    tmp = fread(*buffer, 1, *size, f);
  fclose(f);

  if(!*buffer)
    return FALSE;

  if(tmp!=*size) {
    free(*buffer);
    *buffer = NULL;
    return FALSE;
  }

  return TRUE;
}

static CURLcode load_capath(struct Curl_easy *data, SslContext *context,
                            const char *path, const bool verifypeer)
{
  Result rc = 0;
  void *tmpbuf = NULL;
  size_t tmpbuf_size = 0;
  DIR *dir;
  struct dirent* dp;
  char tmp_path[PATH_MAX];

  dir = opendir(path);
  if(!dir) {
    failf(data, "Error opening ca path %s",
          path);

    if(verifypeer)
      return CURLE_SSL_CACERT_BADFILE;

    return CURLE_OK;
  }

  while((dp = readdir(dir))) {
    if(dp->d_name[0]=='.')
      continue;

    curl_msnprintf(tmp_path, sizeof(tmp_path), "%s/%s", path, dp->d_name);

    bool entrytype = FALSE;

    #ifdef _DIRENT_HAVE_D_TYPE
    if(dp->d_type == DT_UNKNOWN)
      continue;
    entrytype = dp->d_type != DT_REG;
    #else
    struct stat tmpstat;

    if(stat(tmp_path, &tmpstat)==-1)
      continue;

    entrytype = (tmpstat.st_mode & S_IFMT) != S_IFREG;
    #endif

    if(entrytype) /* Ignore directories. */
      continue;

    if(!load_file(tmp_path, &tmpbuf, &tmpbuf_size)) {
      failf(data, "Error reading ca path file %s",
            tmp_path);

      if(verifypeer)
        return CURLE_SSL_CACERT_BADFILE;
    }

    rc = sslContextImportServerPki(context, tmpbuf, tmpbuf_size,
                                   SslCertificateFormat_Pem, NULL);
    free(tmpbuf);

    if(R_FAILED(rc)) {
      failf(data, "Error importing ca path file %s - libnx: 0x%X",
            tmp_path, rc);

      if(verifypeer)
        return CURLE_SSL_CACERT_BADFILE;
    }
  }

  closedir(dir);

  return CURLE_OK;
}

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
  }
  return CURLE_NOT_BUILT_IN;
}

static CURLcode Curl_libnx_random(struct Curl_easy *data,
                                    unsigned char *entropy, size_t length)
{
  Result rc = csrngGetRandomBytes(entropy, length);

  return R_SUCCEEDED(rc) ? CURLE_OK : CURLE_FAILED_INIT;
}

static CURLcode
set_ssl_version_min_max(struct ssl_primary_config *conn_config,
                        struct Curl_easy *data,
                        u32 *out_version)
{
  u32 libnx_ver_min = 0;
  u32 libnx_ver_max = 0;
  long ssl_version = conn_config->version;
  long ssl_version_max = conn_config->version_max;
  CURLcode result = CURLE_OK;

  switch(ssl_version) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
      ssl_version = CURL_SSLVERSION_TLSv1_0;
      if(ssl_version_max == CURL_SSLVERSION_MAX_NONE ||
         ssl_version_max == CURL_SSLVERSION_MAX_DEFAULT) {
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
  const struct curl_blob *ca_info_blob = conn_config->ca_info_blob;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  curl_socket_t sockfd = Curl_conn_cf_get_socket(cf, data);

  const char * const ssl_cafile =
    /* CURLOPT_CAINFO_BLOB overrides CURLOPT_CAINFO */
    (ca_info_blob ? NULL : conn_config->CAfile);

  const bool verifypeer = conn_config->verifypeer;
  const char * const ssl_capath = conn_config->CApath;
  char * const ssl_cert = ssl_config->primary.clientcert;
  const char * const ssl_crlfile = ssl_config->primary.CRLfile;
  const char *hostname = connssl->peer.hostname;

  int ret = -1;
  Result rc = 0;
  void *tmpbuf = NULL;
  size_t tmpbuf_size = 0;

  /* ssl-service only supports TLS 1.0-1.2 */
  if((conn_config->version == CURL_SSLVERSION_SSLv2) ||
     (conn_config->version == CURL_SSLVERSION_SSLv3)) {
    failf(data, "Not supported SSL version");
    return CURLE_NOT_BUILT_IN;
  }

  u32 ssl_version = 0;
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
    return CURLE_NOT_BUILT_IN;
  }

  rc = sslCreateContext(&BACKEND->context, ssl_version);
  if(R_FAILED(rc))
    return CURLE_SSL_CONNECT_ERROR;

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
    /* Load the trusted CA */
    if(ssl_cafile) {
      if(!load_file(ssl_cafile, &tmpbuf, &tmpbuf_size)) {
        failf(data, "Error reading ca cert file %s",
              ssl_cafile);

        if(verifypeer)
          return CURLE_SSL_CACERT_BADFILE;
      }
      else {
        rc = sslContextImportServerPki(&BACKEND->context, tmpbuf, tmpbuf_size,
                                       SslCertificateFormat_Pem, NULL);
        free(tmpbuf);

        if(R_FAILED(rc)) {
          failf(data, "Error importing ca cert file %s - libnx: 0x%X",
                ssl_cafile, rc);

          if(verifypeer)
            return CURLE_SSL_CACERT_BADFILE;
        }
      }
    }

    if(ssl_capath) {
      CURLcode retcode = load_capath(data, &BACKEND->context,
                                     ssl_capath, verifypeer);

      if(retcode) return retcode;
    }

    /* Load the CRL */
    /* The input for CRLFILE is PEM, but the ssl-service requires DER.
     * A helper func for converting PEM to DER would be needed for this.
     * sectransp.c has pem_to_der(), but having a duplicate func isn't ideal.
     * Therefore, the below is disabled. */
    /*
    if(ssl_crlfile) {
      if(!load_file(ssl_crlfile, &tmpbuf, &tmpbuf_size)) {
        failf(data, "Error reading CRL file %s",
              ssl_cert);

        return CURLE_SSL_CRL_BADFILE;
      }

      rc = sslContextImportCrl(&BACKEND->context, tmpbuf, tmpbuf_size, NULL);
      free(tmpbuf);

      if(R_FAILED(rc)) {
        failf(data, "Error importing CRL file %s - libnx: 0x%X",
              ssl_crlfile, rc);

        return CURLE_SSL_CRL_BADFILE;
      }
    }*/

    /* Load the client certificate */
    if(ssl_cert) {
      if(!ssl_config->cert_type)
        infof(data, "WARNING: SSL: Certificate type not set, assuming "
                    "PKCS#12 format.\n");
        else if(strncmp(ssl_config->cert_type, "P12",
          strlen(ssl_config->cert_type)) != 0)
          infof(data, "WARNING: SSL: The ssl-service only supports "
                      "loading identities that are in PKCS#12 format.\n");

      if(!load_file(ssl_cert, &tmpbuf, &tmpbuf_size)) {
        failf(data, "Error reading client cert file %s",
              ssl_cert);

        return CURLE_SSL_CERTPROBLEM;
      }

      rc = sslContextImportClientPki(&BACKEND->context, tmpbuf, tmpbuf_size,
                                     ssl_config->key_passwd,
                                     ssl_config->key_passwd ? strlen(ssl_config->key_passwd) : 0,
                                     NULL);
      free(tmpbuf);

      if(R_FAILED(rc)) {
        failf(data, "Error importing client PKCS#12 file %s - libnx: 0x%X",
              ssl_cert, rc);

        return CURLE_SSL_CERTPROBLEM;
      }
    }
  }

  rc = sslContextCreateConnection(&BACKEND->context, &BACKEND->conn);

  if(R_SUCCEEDED(rc))
    rc = sslConnectionSetOption(&BACKEND->conn,
                                SslOptionType_DoNotCloseSocket, TRUE);

  if(R_SUCCEEDED(rc)) {
    ret = socketSslConnectionSetSocketDescriptor(&BACKEND->conn, (int)sockfd);
    if(ret == -1 && errno != ENOENT) return CURLE_SSL_CONNECT_ERROR;
  }

  if(R_SUCCEEDED(rc))
    rc = sslConnectionSetHostName(&BACKEND->conn, hostname, strlen(hostname));

  /* This will fail on system-versions where this option isn't available,
   * so ignore errors from this. */
  if(R_SUCCEEDED(rc))
    sslConnectionSetOption(&BACKEND->conn,
                           SslOptionType_SkipDefaultVerify, TRUE);

  if(R_SUCCEEDED(rc) && hosversionAtLeast(3, 0, 0))
    rc = sslConnectionSetOption(&BACKEND->conn,
                                SslOptionType_GetServerCertChain, TRUE);

  if(R_SUCCEEDED(rc)) {
    u32 verifyopt = SslVerifyOption_DateCheck;
    if(verifypeer) verifyopt |= SslVerifyOption_PeerCa;
    if(conn_config->verifyhost) verifyopt |= SslVerifyOption_HostName;
    rc = sslConnectionSetVerifyOption(&BACKEND->conn, verifyopt);
  }

  if(R_SUCCEEDED(rc)) {
    SslSessionCacheMode cache_mode = SslSessionCacheMode_None;
    if(conn_config->sessionid)
      cache_mode = SslSessionCacheMode_SessionId;
    rc = sslConnectionSetSessionCacheMode(&BACKEND->conn, cache_mode);
  }

#ifdef HAS_ALPN
  if(cf->conn->bits.tls_enable_alpn && hosversionAtLeast(9, 0, 0)) {
    rc = sslConnectionSetOption(&BACKEND->conn,
                                SslOptionType_EnableAlpn, TRUE);
    if(R_FAILED(rc)) {
      failf(data, "Failed enabling ALPN");
      return CURLE_SSL_CONNECT_ERROR;
    }

    u8 protocols[0x80]={0};
    u8 *p = protocols;
#ifdef USE_NGHTTP2
    if(data->set.httpversion >= CURL_HTTP_VERSION_2) {
      memcpy(p, NGHTTP2_PROTO_ALPN, NGHTTP2_PROTO_ALPN_LEN);
      p += NGHTTP2_PROTO_ALPN_LEN;
      infof(data, "ALPN, offering %s\n", NGHTTP2_PROTO_VERSION_ID);
    }
#endif
    *p++ = ALPN_HTTP_1_1_LENGTH;
    memcpy(p, ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH);
    infof(data, "ALPN, offering %s\n", ALPN_HTTP_1_1);

    u32 size = (uintptr_t)p + ALPN_HTTP_1_1_LENGTH - (uintptr_t)protocols;
    rc = sslConnectionSetNextAlpnProto(&BACKEND->conn, protocols,
                                       size);
    if(R_FAILED(rc)) {
      failf(data, "Failed setting ALPN protocols");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
#endif

  if(R_SUCCEEDED(rc)) {
    SslIoMode iomode = SslIoMode_Blocking;
    if(nonblocking)
      iomode = SslIoMode_NonBlocking;
    rc = sslConnectionSetIoMode(&BACKEND->conn, iomode);
  }

  if(R_FAILED(rc))
    return CURLE_SSL_CONNECT_ERROR;

  infof(data, "libnx: Connecting to %s:%ld\n", hostname, cf->conn->remote_port);

  connssl->connecting_state = ssl_connect_2;

  return CURLE_OK;
}

static CURLcode
libnx_connect_step2(struct Curl_cfilter *cf,
                    struct Curl_easy *data)
{
  Result rc = 0;
  CURLcode retcode = CURLE_OK;
  struct ssl_connect_data *connssl = cf->ctx;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
#ifndef CURL_DISABLE_PROXY
  const char * const pinnedpubkey = Curl_ssl_cf_is_proxy(cf) ?
        data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY] :
        data->set.str[STRING_SSL_PINNEDPUBLICKEY];
#else
  const char * const pinnedpubkey = data->set.str[STRING_SSL_PINNEDPUBLICKEY];
#endif
  const size_t bufsize = 16384;
  u8 *buffer = calloc(1, bufsize);
  u8 *peercert = NULL;
  u32 peercert_size = 0;
  u8 zeros[4]={0};

  if(!BACKEND->certbuf) {
    BACKEND->certbuf_size = bufsize;
    BACKEND->certbuf = (u8*)calloc(1, BACKEND->certbuf_size);
  }

  if(!buffer || !BACKEND->certbuf) {
    free(buffer);
    free(BACKEND->certbuf);
    return CURLE_OUT_OF_MEMORY;
  }

  u32 out_size = 0, total_certs = 0;
  rc = sslConnectionDoHandshake(&BACKEND->conn, &out_size, &total_certs,
                                buffer, bufsize);

  if(memcmp(buffer, zeros, sizeof(zeros)))
    memcpy(BACKEND->certbuf, buffer, bufsize);
  free(buffer);

  if(R_FAILED(rc)) {
    if(R_VALUE(rc) == MAKERESULT(123, 204)) /* PR_WOULD_BLOCK_ERROR */
      return CURLE_AGAIN;

      if(R_VALUE(rc) == MAKERESULT(123, 207))
        return CURLE_PEER_FAILED_VERIFICATION;
      else
        return CURLE_SSL_CONNECT_ERROR;
  }

  if(out_size && total_certs) {
    if(data->set.ssl.certinfo)
      retcode = Curl_ssl_init_certinfo(data,
                                       (int)total_certs);
    if(!retcode) {
      if(hosversionBefore(3, 0, 0)) {
        infof(data, "Dumping cert info:\n");
        retcode = Curl_extract_certinfo(data, 0, BACKEND->certbuf,
                                        &BACKEND->certbuf[out_size]);
        peercert = buffer;
        peercert_size = out_size;
      }
      else {
        for(u32 certi = 0; certi < total_certs; certi++) {
          void *certdata = NULL;
          u32 certdata_size = 0;

          rc = sslConnectionGetServerCertDetail(BACKEND->certbuf, out_size,
                                                certi, &certdata,
                                                &certdata_size);
          if(R_SUCCEEDED(rc)) {
            if(!certi) {
              infof(data, "Dumping cert info:\n");
              peercert = certdata;
              peercert_size = certdata_size;
            }
            retcode = Curl_extract_certinfo(data, (int)certi, certdata,
                                            &((u8*)certdata)[certdata_size]);
          }

          if(R_FAILED(rc) || retcode) break;
          if(!data->set.ssl.certinfo) break;
        }
      }
    }
  }

  if(R_FAILED(rc) || retcode)
    failf(data, "Unable to dump certificate information.\n");

  if(pinnedpubkey) {
    struct Curl_X509certificate x509_parsed;
    struct Curl_asn1Element *pubkey;

    if(!peercert || !peercert_size) {
      const char *errorptr = "";
      if(!conn_config->verifypeer)
        errorptr = ", CURLOPT_SSL_VERIFYPEER must be enabled";
      failf(data, "Failed due to missing peer certificate%s.", errorptr);
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    memset(&x509_parsed, 0, sizeof(x509_parsed));
    retcode = Curl_parseX509(&x509_parsed, peercert, &peercert[peercert_size]);
    if(!retcode)
      return retcode;

    pubkey = &x509_parsed.subjectPublicKeyInfo;
    if(!pubkey->header || pubkey->end <= pubkey->header) {
      failf(data, "SSL: failed retrieving public key from server certificate");
      return retcode;
    }

    retcode = Curl_pin_peer_pubkey(data,
                                  pinnedpubkey,
                                   (const unsigned char *)pubkey->header,
                                  (size_t)(pubkey->end - pubkey->header));
    if(retcode)
      return retcode;
  }

#ifdef HAS_ALPN
  if(cf->conn->bits.tls_enable_alpn) {
    u8 next_protocol[0x33]={0};
    SslAlpnProtoState state;
    u32 out_size = 0;
    rc = sslConnectionGetNextAlpnProto(&BACKEND->conn, &state, &out_size,
                                       next_protocol,
                                       sizeof(next_protocol)-1);

    if(R_SUCCEEDED(rc) && next_protocol[0] &&
      (state == SslAlpnProtoState_Negotiated ||
       state == SslAlpnProtoState_Selected)) {
      infof(data, "ALPN, server accepted to use %s\n", next_protocol);
#ifdef USE_NGHTTP2
      if(out_size == NGHTTP2_PROTO_VERSION_ID_LEN &&
         !memcmp(next_protocol, NGHTTP2_PROTO_VERSION_ID,
                 NGHTTP2_PROTO_VERSION_ID_LEN)) {
        cf->conn->alpn = CURL_HTTP_VERSION_2;
      }
      else
#endif
        if(out_size == ALPN_HTTP_1_1_LENGTH &&
           !memcmp(next_protocol, ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH)) {
          cf->conn->alpn = CURL_HTTP_VERSION_1_1;
        }
    }
    else {
      infof(data, "ALPN, server did not agree to a protocol\n");
    }
    Curl_multiuse_state(cf->conn, cf->conn->alpn == CURL_HTTP_VERSION_2 ?
                        BUNDLE_MULTIPLEX : BUNDLE_NO_MULTIUSE);
  }
#endif

  connssl->connecting_state = ssl_connect_done;
  infof(data, "SSL connected\n");

  return CURLE_OK;
}

static ssize_t libnx_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                         const void *mem, size_t len,
                         CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = cf->ctx;
  Result rc = 0;
  u32 out_size = 0;

  rc = sslConnectionWrite(&BACKEND->conn, mem, len, &out_size);

  if(R_FAILED(rc)) {
    /* PR_WOULD_BLOCK_ERROR */
    *curlcode = (R_VALUE(rc) == MAKERESULT(123, 204)) ?
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
  free(BACKEND->certbuf);
  BACKEND->certbuf = NULL;
  BACKEND->certbuf_size = 0;
}

static ssize_t libnx_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                         char *buf, size_t buffersize,
                         CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = cf->ctx;
  Result rc = 0;
  u32 out_size = 0;

  memset(buf, 0, buffersize);
  rc = sslConnectionRead(&BACKEND->conn, buf, buffersize, &out_size);

  if(R_FAILED(rc)) {
    /* PR_WOULD_BLOCK_ERROR */
    *curlcode = (R_VALUE(rc) == MAKERESULT(123, 204)) ?
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
  u8 buffer = 0;
  u32 out_size = 0;
  Result rc = sslConnectionPeek(&BACKEND->conn, &buffer,
                                sizeof(buffer), &out_size);
  if(R_FAILED(rc)) {
    /* PR_WOULD_BLOCK_ERROR == connection is still in place,
     * otherwise connection status unknown */
    return R_VALUE(rc) == MAKERESULT(123, 204) ? 1 : -1;
  }
  return out_size ? 1 : 0;
}

static CURLcode
libnx_connect_common(struct Curl_cfilter *cf,
                    struct Curl_easy *data,
                    bool nonblocking,
                    bool *done)
{
  Result rc = 0;
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

  if(retcode == CURLE_AGAIN)
    return CURLE_OK;
  if(retcode == CURLE_PEER_FAILED_VERIFICATION) {
    rc = sslConnectionGetVerifyCertError(&BACKEND->conn);
    if(R_VALUE(rc) != MAKERESULT(123, 301) &&
       R_VALUE(rc) != MAKERESULT(123, 303) &&
       R_VALUE(rc) != MAKERESULT(123, 304)) {
      /* 1509: SSL_ERROR_BAD_CERT_ALERT
       * 1511: SSL_ERROR_REVOKED_CERT_ALERT
       * 1512: SSL_ERROR_EXPIRED_CERT_ALERT */
      if(R_VALUE(rc) == MAKERESULT(123, 323) ||
         R_VALUE(rc) == MAKERESULT(123, 1509) ||
         R_VALUE(rc) == MAKERESULT(123, 1511) ||
         R_VALUE(rc) == MAKERESULT(123, 1512))
        retcode = CURLE_SSL_CERTPROBLEM;
    }
  }

  return retcode;
}

static CURLcode Curl_libnx_connect_nonblocking(struct Curl_cfilter *cf,
                                            struct Curl_easy *data,
                                            bool *done)
{
  return libnx_connect_common(cf, data, TRUE, done);
}


static CURLcode Curl_libnx_connect(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
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
  Result rc = 0;

  rc = sslInitialize(0x3);

  if(R_SUCCEEDED(rc))
    rc = csrngInitialize();

  return R_SUCCEEDED(rc);
}

static void Curl_libnx_cleanup(void)
{
  csrngExit();
  sslExit();
}

static bool Curl_libnx_data_pending(struct Curl_cfilter *cf,
                                 const struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  s32 tmp = 0;
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

  SSLSUPP_CA_PATH |
  SSLSUPP_CERTINFO |
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
  Curl_libnx_random,                /* random */
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
