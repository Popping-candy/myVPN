#ifndef _TLSSERVER_H
#define _TLSSERVER_H

SSL_CTX *setupTLSServer();
int createTunDevice();
int initTCPServer();
void tunSelected(int tunfd, SSL *ssl);
void socketSelected(int tunfd, SSL *ssl);
int authenticate(SSL *ssl);

#endif /* _TLSSERVER_H */
