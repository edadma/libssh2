package io.github.edadma.libssh2

import extern.{LibSSH2 => lib}

def init(flags: Int): Int = lib.libssh2_init(flags)
def exit(): Unit = lib.libssh2_exit()
