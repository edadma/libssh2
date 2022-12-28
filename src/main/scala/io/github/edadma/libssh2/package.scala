package io.github.edadma.libssh2

import extern.LibSSH2 as lib

import scala.annotation.tailrec
import scala.collection.immutable.ArraySeq
import scala.scalanative.unsafe.*
import scala.scalanative.unsigned.*
import scala.scalanative.posix.sys.time.*
import scala.scalanative.posix.sys.select.*
import scala.scalanative.posix.sys.stat.stat
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

private def o(n: Int): Int = Integer.parseInt(n.toString, 8)

/* File mode */
/* Read, write, execute/search by owner */
val LIBSSH2_SFTP_S_IRWXU        = o(0000700)     /* RWX mask for owner */
val LIBSSH2_SFTP_S_IRUSR        = o(0000400)     /* R for owner */
val LIBSSH2_SFTP_S_IWUSR        = o(0000200)     /* W for owner */
val LIBSSH2_SFTP_S_IXUSR        = o(0000100)     /* X for owner */
/* Read, write, execute/search by group */
val LIBSSH2_SFTP_S_IRWXG        = o(0000070)     /* RWX mask for group */
val LIBSSH2_SFTP_S_IRGRP        = o(0000040)     /* R for group */
val LIBSSH2_SFTP_S_IWGRP        = o(0000020)     /* W for group */
val LIBSSH2_SFTP_S_IXGRP        = o(0000010)     /* X for group */
/* Read, write, execute/search by others */
val LIBSSH2_SFTP_S_IRWXO        = o(0000007)     /* RWX mask for other */
val LIBSSH2_SFTP_S_IROTH        = o(0000004)     /* R for other */
val LIBSSH2_SFTP_S_IWOTH        = o(0000002)     /* W for other */
val LIBSSH2_SFTP_S_IXOTH        = o(0000001)     /* X for other */

def permissions(path: String): Int =
  val info = stackalloc[stat]()

  Zone(implicit z => stat(toCString(path), info))
  info._13.toInt & 0x1ff

implicit class SFTP(val ptr: lib.sftp_tp) extends AnyVal:
  def mkdir(path: String, path_len: Int, mode: Int): Int =
    Zone(implicit z => lib.libssh2_sftp_mkdir_ex(ptr, toCString(path), path.length.toUInt, mode.toULong))
  def shutdown: Int = lib.libssh2_sftp_shutdown(ptr)

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

  def sftpInit: SFTP = lib.libssh2_sftp_init(session)
  def scpSend(path: String, mode: Int, size: Long): Channel =
    Zone(implicit z => lib.libssh2_scp_send_ex(session, toCString(path), mode, size.toULong, 0, 0))
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
      username.length.toUInt,
      toCString(password),
      password.length.toUInt,
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
  def openSession(): Channel = lib.libssh2_channel_open_ex(
    session,
    c"session",
    7.toUInt,
    LIBSSH2_CHANNEL_WINDOW_DEFAULT,
    LIBSSH2_CHANNEL_PACKET_DEFAULT,
    null,
    0.toUInt,
  )
  def lastError: (Int, String) =
    val errmsg = stackalloc[CString]()
    val errmsg_len = stackalloc[CInt]()
    val rc = lib.libssh2_session_last_error(session, errmsg, errmsg_len, 0)

    (rc, fromCString(!errmsg))
  def blockDirections: Int = lib.libssh2_session_block_directions(session)
  def handshake(sock: Int): Int = lib.libssh2_session_handshake(session, sock)
  def disconnect(description: String): Int = Zone(implicit z =>
    lib.libssh2_session_disconnect_ex(session, SSH_DISCONNECT_BY_APPLICATION, toCString(description), c""),
  )
  def free(): Unit = lib.libssh2_session_free(session)

implicit class Channel(val ptr: lib.channel_tp) extends AnyVal:
  def exec(command: String): Int =
    Zone(implicit z =>
      lib.libssh2_channel_process_startup(ptr, c"exec", 4.toUInt, toCString(command), command.length.toUInt),
    )
  def read(session: Session, sock: Int): String =
    val buf = new StringBuilder

    @tailrec
    def read(): Unit =
      var rc: CSSize = 1.asInstanceOf[CSSize]
      var buffer = stackalloc[CChar](0x4000)

      while rc > 0 do
        rc = lib.libssh2_channel_read_ex(ptr, 0, buffer, 0x4000.toUInt)

        if rc > 0 then for i <- 0 until rc.toInt do buf += buffer(i).toChar
        else if rc != LIBSSH2_ERROR_EAGAIN && rc != 0 then Console.err.println(s"libssh2_channel_read returned $rc")

      if rc == LIBSSH2_ERROR_EAGAIN then
        session.waitsocket(sock)
        read()

    read()
    buf.toString
  end read
  def close: Int = lib.libssh2_channel_close(ptr)
  def getExitStatus: Int = lib.libssh2_channel_get_exit_status(ptr)
  def getExitSignal: (Int, String) =
    val exitsignal = stackalloc[CString]()

    !exitsignal = c"none"

    val rc = lib.libssh2_channel_get_exit_signal(ptr, exitsignal, null, null, null, null, null)

    (rc, fromCString(!exitsignal))
  def free: Int = lib.libssh2_channel_free(ptr)
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
