package io.github.edadma.libssh2

import extern.LibSSH2 as lib

import scala.collection.immutable.ArraySeq
import scala.scalanative.unsafe.*
import scala.scalanative.unsigned.*
import scala.scalanative.posix.sys.time.*
import scala.scalanative.posix.sys.select.*
import scalanative.posix.sys.timeOps.*

val LIBSSH2_CHANNEL_WINDOW_DEFAULT: CUnsignedInt = (2 * 1024 * 1024).toUInt
val LIBSSH2_CHANNEL_PACKET_DEFAULT: CUnsignedInt = 32768.toUInt

val LIBSSH2_SESSION_BLOCK_INBOUND = 0x0001
val LIBSSH2_SESSION_BLOCK_OUTBOUND = 0x0002

val LIBSSH2_ERROR_EAGAIN = -37

val LIBSSH2_KNOWNHOST_TYPE_PLAIN = 1
val LIBSSH2_KNOWNHOST_KEYENC_RAW = 1 << 16

val SSH_DISCONNECT_BY_APPLICATION = 11

val LIBSSH2_KNOWNHOST_CHECK_MATCH = 0
val LIBSSH2_KNOWNHOST_CHECK_MISMATCH = 1
val LIBSSH2_KNOWNHOST_CHECK_NOTFOUND = 2
val LIBSSH2_KNOWNHOST_CHECK_FAILURE = 3

implicit class Session(val session: lib.session_tp) extends AnyVal:
  def waitsocket(socket_fd: Int): Int =
    val timeout = stackalloc[timeval]()
    val fd = stackalloc[fd_set]()
    var writefd: Ptr[fd_set] = null
    var readfd: Ptr[fd_set] = null

    timeout.tv_sec = 10
    timeout.tv_usec = 0
    FD_ZERO(fd)
    FD_SET(socket_fd, fd)

    /* now make sure we wait in the correct direction */
    val dir = session.blockDirections

    if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) != 0 then readfd = fd
    if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) != 0 then writefd = fd
    select(socket_fd + 1, readfd, writefd, null, timeout)
  end waitsocket

  def setBlocking(blocking: Boolean): Unit = lib.libssh2_session_set_blocking(session, if blocking then 1 else 0)
  def knownHostInit: KnownHosts = lib.libssh2_knownhost_init(session)
  def hostKey: Option[(ArraySeq[Byte], Int)] =
    val len = stackalloc[CSize]()
    val typ = stackalloc[CInt]()
    val key = lib.libssh2_session_hostkey(session, len, typ)

    if key eq null then None
    else
      val keyarr = new Array[Byte]((!len).toInt)

      for i <- 0 until (!len).toInt do keyarr(i) = key(i)

      Some((keyarr to ArraySeq, !typ))
  def userAuthPassword(username: String, password: String): Int = Zone(implicit z =>
    lib.libssh2_userauth_password_ex(
      session,
      toCString(username),
      username.length.asInstanceOf[CUnsignedInt],
      toCString(password),
      password.length.asInstanceOf[CUnsignedInt],
      null,
    ),
  )
  def userauthPublickeyFromFile(username: String, publickey: String, privatekey: String, passphrase: String): Int =
    Zone(implicit z =>
      lib.libssh2_userauth_publickey_fromfile_ex(
        session,
        toCString(username),
        username.length.asInstanceOf[CUnsignedInt],
        toCString(publickey),
        toCString(privatekey),
        toCString(passphrase),
      ),
    )
  def channelOpen(): Channel = lib.libssh2_channel_open_ex(
    session,
    c"session",
    7.toUInt,
    LIBSSH2_CHANNEL_WINDOW_DEFAULT,
    LIBSSH2_CHANNEL_PACKET_DEFAULT,
    null,
    0.toUInt,
  )
  def lastError: String =
    val errmsg = stackalloc[CString]()
    val errmsg_len = stackalloc[CInt]()

    lib.libssh2_session_last_error(session, errmsg, errmsg_len, 0)
    fromCString(!errmsg)
  def blockDirections: Int = lib.libssh2_session_block_directions(session)
  def handshake(sock: Int): Int = lib.libssh2_session_handshake(session, sock)
  def disconnect(description: String): Int = Zone(implicit z =>
    lib.libssh2_session_disconnect_ex(session, SSH_DISCONNECT_BY_APPLICATION, toCString(description), c""),
  )
  def free(): Unit = lib.libssh2_session_free(session)

implicit class Channel(val channel: lib.channel_tp) extends AnyVal:
  def exec(command: String): Int =
    Zone(implicit z =>
      lib.libssh2_channel_process_startup(channel, c"exec", 4.toUInt, toCString(command), command.length.toUInt),
    )
  def read(session: Session, sock: Int): String =
    var bytecount = 0
    val buf = new StringBuilder

    def read(): Unit =
      var rc: CSSize = 1.asInstanceOf[CSSize]
      var buffer = stackalloc[CChar](0x4000)

      while rc > 0 do
        rc = lib.libssh2_channel_read_ex(channel, 0, buffer, 0x4000.toUInt)

        if rc > 0 then
          bytecount += rc.toInt
          Console.err.println("We read:")

          for i <- 0 until rc.toInt do
            buffer += buffer(i).toChar
            Console.err.print(buffer(i).toChar)

          Console.err.println()
        else if rc != LIBSSH2_ERROR_EAGAIN then Console.err.println(s"libssh2_channel_read returned $rc")
      end while

      if rc == LIBSSH2_ERROR_EAGAIN then session.waitsocket(sock)

    read()
    buf.toString
  end read
  def close: Int = lib.libssh2_channel_close(channel)
  def getExitStatus: Int = lib.libssh2_channel_get_exit_status(channel)
  def getExitSignal: (Int, String) =
    val exitsignal = stackalloc[CString]()

    !exitsignal = c"none"

    val rc = lib.libssh2_channel_get_exit_signal(channel, exitsignal, null, null, null, null, null)

    (rc, fromCString(!exitsignal))
  def free: Int = lib.libssh2_channel_free(channel)
end Channel

implicit class KnownHost(val host: lib.knownhost_tp) extends AnyVal:
  def magic: Int = host._1.toInt
  def name: String = fromCString(host._3)
  def key: String = fromCString(host._4)
  def typemask: Int = host._5

implicit class KnownHosts(val hosts: lib.knownhosts_tp) extends AnyVal:
  def readFile(filename: String, typ: KnownHostFile): Int =
    Zone(implicit z => lib.libssh2_knownhost_readfile(hosts, toCString(filename), typ.value))
  def writeFile(filename: String, typ: KnownHostFile): Int =
    Zone(implicit z => lib.libssh2_knownhost_writefile(hosts, toCString(filename), typ.value))
  def free(): Unit = lib.libssh2_knownhost_free(hosts) // 1105
  def checkp(host: String, port: Int, key: Seq[Byte], typemask: Int): (Int, KnownHost) = Zone { implicit z =>
    val keyarr = stackalloc[Byte](key.length.toUInt)
    val knownhost = stackalloc[lib.knownhost_tp]()

    for i <- key.indices do keyarr(i) = key(i)

    val rc = lib.libssh2_knownhost_checkp(hosts, toCString(host), port, keyarr, key.length.toUInt, typemask, knownhost)

    (rc, !knownhost)
  }

implicit class KnownHostFile(val value: CInt) extends AnyVal

object KnownHostFile {
  final val OPENSSH = new KnownHostFile(1)
}

def init(flags: Int): Int = lib.libssh2_init(flags)
def exit(): Unit = lib.libssh2_exit()
def sessionInit: Session = lib.libssh2_session_init_ex(null, null, null, null)
