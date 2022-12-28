package io.github.edadma.libssh2

@main def sftp_mkdir(args: String*): Unit =
  var hostname = "127.0.0.1"
  var username = "testuser"
  var password = "easypassword"
  var sftppath = "/tmp/sftp_mkdir"

  if args.nonEmpty then hostname = args(0)
  if args.length > 1 then username = args(1)
  if args.length > 2 then password = args(2)
  if args.length > 3 then sftppath = args(3)

  var rc = init(0)

  if rc != 0 then
    Console.err.println(s"libssh2 initialization failed ($rc)")
    sys.exit(1)

  val sock =
    connectPort22(hostname) match
      case -1 =>
        Console.err.println("failed to connect!")
        sys.exit(1)
      case s => s

  val session = sessionInit

  def shutdown(): Unit =
    session.disconnect("Normal Shutdown, Thank you for playing")
    session.free()
    scala.scalanative.posix.unistd.close(sock)
    Console.err.println("All done")
    exit()

  if session.isNull then
    Console.err.println("failed to initialize a session")
    sys.exit(1)

  while ({ rc = session.handshake(sock); rc } == LIBSSH2_ERROR_EAGAIN) {}

  if rc != 0 then
    Console.err.println(s"Failure establishing SSH session: $rc")
    sys.exit(1)

  val nh = session.knownHostInit

  if nh.isNull then
    Console.err.println("failed to knownhost init")
    sys.exit(1)

  nh.readFile("known_hosts", KnownHostFile.OPENSSH)
  nh.writeFile("dumpfile", KnownHostFile.OPENSSH)

  val (fingerprint, _) =
    session.hostKey getOrElse {
      Console.err.println("hostKey() failed")
      sys.exit(1)
    }

  val (check, host) = nh.checkp(
    hostname,
    22,
    fingerprint,
    LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW,
  )

  Console.err.println(
    s"Host check: $check, key: ${if check <= LIBSSH2_KNOWNHOST_CHECK_MISMATCH then host.key else "<none>"}",
  )
  nh.free()

  if password.nonEmpty then
    while { rc = session.userAuthPassword(username, password); rc } == LIBSSH2_ERROR_EAGAIN do {}
    if rc != 0 then
      Console.err.println("Authentication by password failed")
      shutdown()
  else
    while {
        rc = session.userauthPublickeyFromFile(
          username,
          s"/home/$username/.ssh/id_rsa.pub",
          s"/home/$username/.ssh/id_rsa",
          password,
        ); rc
      } == LIBSSH2_ERROR_EAGAIN
    do {}
  if rc != 0 then
    Console.err.println("Authentication by public key failed")
    shutdown()

  val sftpSession = session.sftpInit

  if sftpSession.isNull then
    Console.err.println("Unable to init SFTP session")
    shutdown()

  session.setBlocking(true)

  rc = sftpSession.mkdir(
    sftppath,
    LIBSSH2_SFTP_S_IRWXU | LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IXGRP | LIBSSH2_SFTP_S_IROTH | LIBSSH2_SFTP_S_IXOTH,
  )

  if rc != 0 then
    Console.err.println(s"libssh2_sftp_mkdir failed: $rc")
    shutdown()

  sftpSession.shutdown
  shutdown()
