package io_github_edadma.libssh2

import scala.scalanative.unsafe.*
import scala.scalanative.unsigned.*
import scala.scalanative.posix.arpa.inet.{htons, inet_addr}
import scala.scalanative.posix.sys.socket.{sa_family_t, AF_INET, SOCK_STREAM, socket, connect, sockaddr}
import scala.scalanative.posix.netinet.in.sockaddr_in
import scala.scalanative.posix.netinet.inOps._
import scala.scalanative.posix.inttypes.uint16_t

def connectPort22(hostname: String): Int =
  val sin = stackalloc[sockaddr_in]()
  val hostaddr = Zone(implicit z => inet_addr(toCString(hostname)))

  /* Ultra basic "connect to port 22 on localhost"
   * Your code is responsible for creating the socket establishing the
   * connection
   */
  val sock = socket(AF_INET, SOCK_STREAM, 0)

  sin.sin_family = AF_INET.toUShort
  sin.sin_port = htons(22.toUShort)
  sin.sin_addr.s_addr = hostaddr

  if connect(sock, sin.asInstanceOf[Ptr[sockaddr]], sizeof[sockaddr_in].toUInt) != 0 then -1
  else sock
