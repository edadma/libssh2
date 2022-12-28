package io.github.edadma.libssh2

import java.nio.file.{Files, Paths}

@main def scp_write(args: String*): Unit =
  var hostname = "127.0.0.1"
  var username = "testuser"
  var password = "easypassword"
  var localfile = "build.sbt"
  var scppath = "/tmp/TEST"

  if args.nonEmpty then hostname = args(0)
  if args.length > 1 then username = args(1)
  if args.length > 2 then password = args(2)
  if args.length > 3 then localfile = args(3)
  if args.length > 4 then scppath = args(4)

  var rc = init(0)

  if rc != 0 then
    Console.err.println(s"libssh2 initialization failed ($rc)")
    sys.exit(1)

  val data = Files.readAllBytes(Paths.get(localfile))
  val perm = permissions(localfile)
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

  if session.session eq null then
    Console.err.println("failed to initialize a session")
    sys.exit(1)

  session.setBlocking(false)

  while ({ rc = session.handshake(sock); rc } == LIBSSH2_ERROR_EAGAIN) {}

  if rc != 0 then
    Console.err.println(s"Failure establishing SSH session: $rc")
    sys.exit(1)

  val nh = session.knownHostInit

  if nh.hosts eq null then
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

  val channel = session.scpSend(scppath, perm, data.length)

  if channel.ptr == null then
    val (err, errmsg) = session.lastError

    Console.err.println(s"Unable to open a session: ($err) $errmsg")
    shutdown()

  Console.err.println("SCP session waiting to send file")
  rc = channel.write(data)

  if rc < 0 then
    Console.err.println(s"Error writing data: $rc")
    shutdown()

  Console.err.println("Sending EOF")
  channel.sendEof
  Console.err.println("Waiting for EOF")
  channel.waitEof
  Console.err.println("Waiting for channel to close")
  channel.waitClosed
  channel.free
  shutdown()
