package io.github.edadma.libssh2.extern

import scala.scalanative.unsafe._

@link("ssh2")
@extern
object LibSSH2:
  type session_t = CStruct0
  type session_tp = Ptr[session_t]

  def libssh2_init(flags: CInt): CInt = extern // 530
  def libssh2_exit(): Unit = extern // 537
  def libssh2_session_init_ex(
      my_alloc: Ptr[CChar],
      my_free: Ptr[CChar],
      my_realloc: Ptr[CChar],
      abstrct: Ptr[CChar],
  ): session_tp = extern // 562
