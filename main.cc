#include <cstdio>
#include <cstring>


#include <unistd.h>  // close
#include <netdb.h>
#include <arpa/inet.h>


// openssl
#include "openssl/ssl.h"

// crypto_headers
// #include "openssl/aes.h"
// #include "openssl/base64.h"
// #include "openssl/crypto.h"
// #include "openssl/des.h"
// #include "openssl/dsa.h"
// #include "openssl/md5.h"
// #include "openssl/rsa.h"
// #include "openssl/sha.h"


int TcpConn(const char *host, const char *serv) {
  int sockfd;
  int n;
  struct addrinfo hints;
  struct addrinfo *res;
  struct addrinfo *ressave;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((n = getaddrinfo(host, serv, &hints, &res)) != 0) {
    fprintf(stderr, "TcpConn error for %s , %s:%s \n", gai_strerror(n), host,
            serv);
    return 0;
  }

  ressave = res;

  do {
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    // error , try next one
    if (sockfd < 0) continue;

    // connect , if return zero ,
    // it will be judged as success and break the loop
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0) break;

    // connect error ,
    // close this one and try next
    close(sockfd);

  } while ((res = res->ai_next) != NULL);

  if (res == NULL)  // errno from final socket() or connect()
  {
    fprintf(stderr, "TcpConn error for %s:%s \n", host, serv);
    return 0;
  }

  freeaddrinfo(ressave);
  return sockfd;
}

int main() {

  // char           dest_url[] = "https://example.com";
  const char             *domain = "google.com";
  const char             *port   = "443";
  const char             *dest_url = "https://google.com";
  X509                *cert = NULL;
  X509_NAME       *certname = NULL;
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;
  int sockfd;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();


  /* ---------------------------------------------------------- *
   * initialize SSL library and register algorithms             *
   * ---------------------------------------------------------- */
  if(SSL_library_init() < 0)
    fprintf( stdout, "Could not initialize the OpenSSL library !\n");

  /* ---------------------------------------------------------- *
   * Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
   * ---------------------------------------------------------- */
  method = SSLv23_client_method();

  /* ---------------------------------------------------------- *
   * Try to create a new SSL context                            *
   * ---------------------------------------------------------- */
  if ( (ctx = SSL_CTX_new(method)) == NULL)
    fprintf( stdout, "Unable to create a new SSL context structure.\n");

  /* ---------------------------------------------------------- *
   * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
   * ---------------------------------------------------------- */
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

  /* ---------------------------------------------------------- *
   * Create new SSL connection state object                     *
   * ---------------------------------------------------------- */
  ssl = SSL_new(ctx);

  /* ---------------------------------------------------------- *
   * Make the underlying TCP socket connection                  *
   * ---------------------------------------------------------- */
  //sockfd = create_socket(dest_url, outbio);
  sockfd = TcpConn(domain, port);
  if(sockfd != 0)
    fprintf( stdout, "Successfully made the TCP connection to: %s.\n", dest_url);

  /* ---------------------------------------------------------- *
   * Attach the SSL session to the socket descriptor            *
   * ---------------------------------------------------------- */
  SSL_set_fd(ssl, sockfd);

  /* ---------------------------------------------------------- *
   * Try to SSL-connect here, returns 1 for success             *
   * ---------------------------------------------------------- */
  if ( SSL_connect(ssl) != 1 )
    fprintf( stdout, "Error: Could not build a SSL session to: %s.\n", dest_url);
  else
    fprintf( stdout, "Successfully enabled SSL/TLS session to: %s.\n", dest_url);

  /* ---------------------------------------------------------- *
   * Get the remote certificate into the X509 structure         *
   * ---------------------------------------------------------- */
  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL)
    fprintf( stdout, "Error: Could not get a certificate from: %s.\n", dest_url);
  else
    fprintf( stdout, "Retrieved the sockfd's certificate from: %s.\n", dest_url);

  /* ---------------------------------------------------------- *
   * extract various certificate information                    *
   * -----------------------------------------------------------*/
  certname = X509_NAME_new();
  certname = X509_get_subject_name(cert);

  /* ---------------------------------------------------------- *
   * display the cert subject here                              *
   * -----------------------------------------------------------*/
  fprintf( stdout, "Displaying the certificate subject data:\n");
  X509_NAME_print_ex_fp(stdout, certname, 0, 0);
  fprintf( stdout, "\n");

  /* ---------------------------------------------------------- *
   * Free the structures we don't need anymore                  *
   * -----------------------------------------------------------*/
  SSL_free(ssl);
  ::close(sockfd);
  SSL_CTX_free(ctx);
  fprintf( stdout, "Finished SSL/TLS connection with sockfd: %s.\n", dest_url);
  return(0);
}
