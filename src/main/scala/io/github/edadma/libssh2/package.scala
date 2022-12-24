package io.github.edadma.libssh2

import extern.LibSSH2 as lib

import scala.scalanative.unsafe._

implicit class Session(val session: lib.session_tp):
  def setBlocking(blocking: Boolean): Unit = lib.libssh2_session_set_blocking(session, if blocking then 1 else 0)
  def knownhostInit: Knownhost = lib.libssh2_knownhost_init(session)
  def hostkey: (String, Long, Int) =
    val len = stackalloc[CSize]()
    val typ = stackalloc[CInt]()
    val key = fromCString(lib.libssh2_session_hostkey(session, len, typ))

    (key, (!len).toLong, !typ)

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
