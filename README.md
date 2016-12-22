# revprox
A TLS reverse proxy customized for Unifield's needs

## Running as a Windows service

Put revprox.exe where you want it to live. Run "revprox install", then set it to
auto start with "sc config unifield-revprox start= auto".

## Running in Linux as a non-priv user

Build it like this: "go build && sudo setcap CAP_NET_BIND_SERVICE=+eip revprox"