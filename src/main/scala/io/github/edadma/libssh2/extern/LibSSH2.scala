package io.github.edadma.libssh2.extern

import scala.scalanative.unsafe._

@link("ssh2")
@extern
object LibSSH2:
  def libssh2_init(flags: CInt): CInt = extern // 530
