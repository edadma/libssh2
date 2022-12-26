package io.github.edadma.libssh2

@main def run(args: String*): Unit =
  var hostname = "127.0.0.1"
  var commandline = "uptime"
  var username = "testuser"
  var password = "easypassword"

  if args.nonEmpty then hostname = args(0)
  if args.length > 1 then username = args(1)
  if args.length > 2 then password = args(2)
  if args.length > 3 then commandline = args(3)

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

  val fingerprint =
    session.hostKey getOrElse {
      Console.err.println("hostKey() failed")
      sys.exit(1)
    }

  println("done")
