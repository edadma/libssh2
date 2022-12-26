package io.github.edadma.libssh2

import scala.scalanative.unsafe.*
import scala.scalanative.unsigned.*
import scala.scalanative.posix.arpa.inet.{htons, inet_addr}
import scala.scalanative.posix.sys.socket.{AF_INET, SOCK_STREAM, socket, connect, sockaddr}
import scala.scalanative.posix.netinet.in.sockaddr_in
import scala.scalanative.posix.netinet.inOps

def connectSSH(hostname: String): Int = Zone { implicit z =>
  val sin = stackalloc[sockaddr_in]()
  val hostaddr = inet_addr(toCString(hostname))

  /* Ultra basic "connect to port 22 on localhost"
   * Your code is responsible for creating the socket establishing the
   * connection
   */
  val sock = socket(AF_INET, SOCK_STREAM, 0)

  !sin.sin_family = AF_INET
  sin.sin_port = htons(22)
  sin.sin_addr.s_addr = hostaddr

  if (connect(sock, sin.asInstanceOf[Ptr[sockaddr]], sizeof(struct sockaddr_in)) != 0) {
    fprintf(stderr, "failed to connect!\n");
    return -1;
  }

  sock
}
