package io.github.edadma.libssh2.extern

import io.github.edadma.libssh2.extern.LibSSH2.session_tp

import scala.scalanative.unsafe.*
import scala.scalanative.unsigned.*

@link("ssh2")
@extern
object LibSSH2:
  type session_t = CStruct0
  type session_tp = Ptr[session_t]
  type knownhosts_t = CStruct0
  type knownhosts_tp = Ptr[knownhosts_t]
  type knownhost_t = CStruct0
  type knownhost_tp = Ptr[knownhost_t]
  type channel_t = CStruct0
  type channel_tp = Ptr[channel_t]

  def libssh2_init(flags: CInt): CInt = extern // 530
  def libssh2_exit(): Unit = extern // 537
  def libssh2_session_init_ex(
      my_alloc: Ptr[CChar],
      my_free: Ptr[CChar],
      my_realloc: Ptr[CChar],
      abstrct: Ptr[CChar],
  ): session_tp = extern // 562
  def libssh2_session_set_blocking(session: session_tp, blocking: CInt): Unit = extern // 862
  // libssh2_session_handshake // 577
  def libssh2_knownhost_init(session: session_tp): knownhosts_tp = extern // 959
  def libssh2_knownhost_readfile(hosts: knownhosts_tp, filename: CString, typ: CInt): CInt = extern // 1134
  def libssh2_knownhost_writefile(hosts: knownhosts_tp, filename: CString, typ: CInt): CInt = extern // 1165
  def libssh2_session_hostkey(session: session_tp, len: Ptr[CSize], typ: Ptr[CInt]): CString = extern // 592
  def libssh2_knownhost_checkp(
      hosts: knownhosts_tp,
      host: CString,
      port: CInt,
      key: CString,
      keylen: CSize,
      typemask: CInt,
      knownhost: Ptr[knownhost_tp],
  ): CInt = extern // 1081
  def libssh2_knownhost_free(hosts: knownhosts_tp): Unit = extern // 1105
  def libssh2_userauth_password_ex(
      session: session_tp,
      username: CString,
      username_len: CUnsignedInt,
      password: CString,
      password_len: CUnsignedInt,
      passwd_change_cb: Ptr[CChar],
  ): CInt = extern // 619
  def libssh2_userauth_publickey_fromfile_ex(
      session: session_tp,
      username: CString,
      username_len: CUnsignedInt,
      publickey: CString,
      privatekey: CString,
      passphrase: CString,
  ): CInt = extern // 633
  def libssh2_channel_open_ex(
      session: session_tp,
      channel_type: CString,
      channel_type_len: CUnsignedInt,
      window_size: CUnsignedInt,
      packet_size: CUnsignedInt,
      message: CString,
      message_len: CUnsignedInt,
  ): channel_tp = extern // 727
  def libssh2_session_last_error(
      session: session_tp,
      errmsg: Ptr[CString],
      errmsg_len: Ptr[CInt],
      want_buf: CInt,
  ): CInt =
    extern // 600
