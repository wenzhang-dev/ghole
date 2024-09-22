package main

import (
    "os"
	"flag"
	"fmt"

	"github.com/wenzhang-dev/ghole/stun"
)

func main() {
    var localAddr string
    var serverAddr string

    flag.StringVar(&localAddr, "local", "", "local address")
    flag.StringVar(&serverAddr, "server", "", "server address")

    flag.Parse()

    if localAddr == "" {
        localAddr = ":18080"
    }

    if serverAddr == "" {
        fmt.Printf("Usage: %s -local :18080 -server 112.112.112.112:6999\n", os.Args[0])
        os.Exit(1)
    }

    cli, err := stun.NewClient(serverAddr, localAddr)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    defer cli.Close()

    typ, mapped, err := cli.Discover()
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    fmt.Printf("NAT Type: %s\n", stun.NT2String(typ))
    fmt.Printf("Address: %s:%d\n", mapped.IP, mapped.Port)
}
