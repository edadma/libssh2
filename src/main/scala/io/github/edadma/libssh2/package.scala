package io.github.edadma.libssh2

import extern.LibSSH2 as lib

import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

val LIBSSH2_CHANNEL_WINDOW_DEFAULT: CUnsignedInt = (2 * 1024 * 1024).toUInt
val LIBSSH2_CHANNEL_PACKET_DEFAULT: CUnsignedInt = 32768.toUInt

implicit class Session(val session: lib.session_tp):
  def setBlocking(blocking: Boolean): Unit = lib.libssh2_session_set_blocking(session, if blocking then 1 else 0)
  def knownhostInit: Knownhost = lib.libssh2_knownhost_init(session)
  def hostkey: (String, Long, Int) =
    val len = stackalloc[CSize]()
    val typ = stackalloc[CInt]()
    val key = fromCString(lib.libssh2_session_hostkey(session, len, typ))

    (key, (!len).toLong, !typ)
  def userauthPassword(username: String, password: String): Int = Zone(implicit z =>
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

implicit class Channel(val hosts: lib.channel_tp)

implicit class Knownhost(val hosts: lib.knownhosts_tp):
  def readfile(filename: String, typ: KnownhostFile): Int =
    Zone(implicit z => lib.libssh2_knownhost_readfile(hosts, toCString(filename), typ.value))
  def writefile(filename: String, typ: KnownhostFile): Int =
    Zone(implicit z => lib.libssh2_knownhost_writefile(hosts, toCString(filename), typ.value))
  def free(): Unit = lib.libssh2_knownhost_free(hosts) // 1105

implicit class KnownhostFile(val value: CInt) extends AnyVal

object KnownhostFile {
  final val OPENSSH = new KnownhostFile(1)
}

def init(flags: Int): Int = lib.libssh2_init(flags)
def exit(): Unit = lib.libssh2_exit()
def sessionInit: Session = lib.libssh2_session_init_ex(null, null, null, null)
