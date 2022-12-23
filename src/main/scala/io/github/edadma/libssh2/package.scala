package io.github.edadma.libssh2

import extern.{LibSSH2 => lib}

implicit class Session(val surface: lib.session_tp)

def init(flags: Int): Int = lib.libssh2_init(flags)
def exit(): Unit = lib.libssh2_exit()
def sessionInit: Session = lib.libssh2_session_init_ex(null, null, null, null)
