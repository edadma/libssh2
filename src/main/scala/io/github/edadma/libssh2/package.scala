package io.github.edadma.libssh2

import extern.LibSSH2 as lib

import scala.scalanative.unsafe._

implicit class Session(val session: lib.session_tp):
  def setBlocking(blocking: Boolean): Unit = lib.libssh2_session_set_blocking(session, if blocking then 1 else 0)
  def knownhostInit: KnownHosts = lib.libssh2_knownhost_init(session)

implicit class KnownHosts(val hosts: lib.knownhosts_tp):
  def readfile(filename: String, typ: Int): Int =
    Zone(implicit z => lib.libssh2_knownhost_readfile(hosts, toCString(filename), typ))

def init(flags: Int): Int = lib.libssh2_init(flags)
def exit(): Unit = lib.libssh2_exit()
def sessionInit: Session = lib.libssh2_session_init_ex(null, null, null, null)
