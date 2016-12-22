package main

import "os"

func main() {
	dom := getDomain(os.Args[1:])
	reverseProxy(dom)
}
