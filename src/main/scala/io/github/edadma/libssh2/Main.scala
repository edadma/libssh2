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


