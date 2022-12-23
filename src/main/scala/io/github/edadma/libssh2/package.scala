package io.github.edadma.libssh2

import extern.{LibSSH2 => lib}

implicit class Session(val session: lib.session_tp):
  def setBlocking(blocking: Boolean): Unit = lib.libssh2_session_set_blocking(session, if blocking then 1 else 0)
  def knownhostInit: KnownHosts = lib.libssh2_knownhost_init(session)

implicit class KnownHosts(val knownHosts: lib.knownhosts_tp)

def init(flags: Int): Int = lib.libssh2_init(flags)
def exit(): Unit = lib.libssh2_exit()
def sessionInit: Session = lib.libssh2_session_init_ex(null, null, null, null)
