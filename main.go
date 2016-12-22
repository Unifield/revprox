package main

func getDomain(args []string) string {
	dom := "prod.unifield.org"
	if len(args) > 0 {
		dom = args[0]
	}
	return dom
}
