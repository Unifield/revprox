# revprox

A TLS reverse proxy customized for Unifield's needs.

Given an instance name, it appends the domain name to get a FQDN for
itself. It then checks if it has a valid key/cert in $fqdn.{key,cer}
in the current directory. If not, it tries to fetch via LetsEncrypt.
If that fails, it exits with an error code 1.

Once it has a valid certificate, it starts running. It listens on port
8061 and issues redirects for any incoming request to the HTTPS on
the FQDN. It listens on the HTTPS port and does reverse proxying of all
requests to port 18061, where OpenERP Web should be running.

## Running in Linux as a non-priv user

Build it like this:
```
export GOPATH=~/GOPATH
mkdir -p $GOPATH/src
git clone git@github.com:Unifield/revprox.git $GOPATH/src/revprox
cd $GOPATH/src/revprox
make

```

or

```
go build && sudo setcap CAP_NET_BIND_SERVICE=+eip revprox
```

The `setcap` command will allow `revprox` to bind to the appropriate priviledge port. 

Note that this won't work if `revprox` is on a filesystem with the `nosuid` flag enabled (you can run `mount` to check this). If that's the case, you might need to move the file elsewhere so that it's able to bind. (N.B. : `cp` won't carry the capabilities across filsystems, you might need to reapply the setcap.)

