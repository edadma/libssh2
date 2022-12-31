package io_github_edadma.libssh2.extern

import LibSSH2.session_tp

import scala.scalanative.unsafe.*, Nat.*
import scala.scalanative.unsafe.Tag.Digit3
import scala.scalanative.unsigned.*

@link("ssh2")
@extern
object LibSSH2:
  type session_t = CStruct0
  type session_tp = Ptr[session_t]
  type knownhosts_t = CStruct0
  type knownhosts_tp = Ptr[knownhosts_t]
  type knownhost_t = CStruct5[CUnsignedInt, Ptr[Byte], CString, CString, CInt]
  type knownhost_tp = Ptr[knownhost_t]
  type channel_t = CStruct0
  type channel_tp = Ptr[channel_t]
  type sftpSession_t = CStruct0
  type sftpSession_tp = Ptr[sftpSession_t]
  type sftpHandle_t = CStruct0
  type sftpHandle_tp = Ptr[sftpHandle_t]
  type _1024 = Digit4[_1, _0, _2, _4]
  type struct_stat_t = CArray[Byte, _1024]
  type struct_stat_tp = Ptr[struct_stat_t]
  type attributes_t = CStruct7[
    CUnsignedLong, // flags
    CUnsignedLong, // filesize
    CUnsignedLong, // uid
    CUnsignedLong, // gid
    CUnsignedLong, // permissions
    CUnsignedLong, // atime
    CUnsignedLong, // mtime
  ]
  type attributes_tp = Ptr[attributes_t]

  def libssh2_init(flags: CInt): CInt = extern // 530
  def libssh2_exit(): Unit = extern // 537
  def libssh2_session_init_ex(
      my_alloc: Ptr[CChar],
      my_free: Ptr[CChar],
      my_realloc: Ptr[CChar],
      abstrct: Ptr[CChar],
  ): session_tp = extern // 562
  def libssh2_session_set_blocking(session: session_tp, blocking: CInt): Unit = extern // 862
  def libssh2_session_handshake(session: session_tp, sock: CInt): CInt = extern // 577
  def libssh2_knownhost_init(session: session_tp): knownhosts_tp = extern // 959
  def libssh2_knownhost_readfile(hosts: knownhosts_tp, filename: CString, typ: CInt): CInt = extern // 1134
  def libssh2_knownhost_writefile(hosts: knownhosts_tp, filename: CString, typ: CInt): CInt = extern // 1165
  def libssh2_session_hostkey(session: session_tp, len: Ptr[CSize], typ: Ptr[CInt]): Ptr[Byte] = extern // 592
  def libssh2_knownhost_checkp(
      hosts: knownhosts_tp,
      host: CString,
      port: CInt,
      key: Ptr[Byte],
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
  def libssh2_session_block_directions(session: session_tp): CInt = extern // 607
  def libssh2_channel_process_startup(
      channel: channel_tp,
      request: CString,
      request_len: CUnsignedInt,
      message: CString,
      message_len: CUnsignedInt,
  ): CInt = extern // 800
  def libssh2_channel_read_ex(channel: channel_tp, stream_id: CInt, buf: CString, buflen: CSize): CSSize = extern // 816
  def libssh2_channel_close(channel: channel_tp): CInt = extern // 912
  def libssh2_channel_get_exit_status(channel: channel_tp): CInt = extern // 901
  def libssh2_channel_get_exit_signal(
      channel: channel_tp,
      exitsignal: Ptr[CString],
      exitsignal_len: Ptr[CSize],
      errmsg: Ptr[CString],
      errmsg_len: Ptr[CSize],
      langtag: Ptr[CString],
      langtag_len: Ptr[CSize],
  ): CInt = extern // 902
  def libssh2_channel_free(channel: channel_tp): CInt = extern // 914
  def libssh2_session_disconnect_ex(session: session_tp, reason: CInt, description: CString, lang: CString): CInt =
    extern // 579
  def libssh2_session_free(session: session_tp): CInt = extern // 587
  def libssh2_scp_send_ex(
      session: session_tp,
      path: CString,
      mode: CInt,
      size: CSize,
      mtime: CLong,
      atime: CLong,
  ): channel_tp = extern // 924
  def libssh2_sftp_init(session: session_tp): sftpSession_tp = extern // 221
  def libssh2_sftp_mkdir_ex(sftp: sftpSession_tp, path: CString, path_len: CUnsignedInt, mode: CUnsignedLongInt): CInt =
    extern // 304
  def libssh2_sftp_shutdown(sftp: sftpSession_tp): CInt = extern // 222
  def libssh2_channel_write_ex(channel: channel_tp, stream_id: CInt, buf: Ptr[Byte], buflen: CSize): CSSize =
    extern // 846
  def libssh2_channel_send_eof(channel: channel_tp): CInt = extern // 909
  def libssh2_channel_wait_eof(channel: channel_tp): CInt = extern // 911
  def libssh2_channel_wait_closed(channel: channel_tp): CInt = extern // 913
  def libssh2_scp_recv2(session: session_tp, path: CString, sb: Ptr[struct_stat_t]): channel_tp = extern // 921
  def libssh2_sftp_fstat_ex(handle: sftpSession_tp, attrs: attributes_tp, setstat: CInt): CInt = extern // 268
  def libssh2_sftp_stat_ex(
      sftp: sftpSession_tp,
      path: CString,
      path_len: CUnsignedInt,
      stat_type: CInt,
      attrs: attributes_tp,
  ): CInt = extern // 316
