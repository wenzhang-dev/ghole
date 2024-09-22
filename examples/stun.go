package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/wenzhang-dev/ghole/stun"
)

func main() {
    var localAddr string
    var serverAddr string

    flag.StringVar(&localAddr, "local", "", "local address")
    flag.StringVar(&serverAddr, "server", "", "server address")

    flag.Parse()

    if localAddr == "" {
        // use 0 to pick a random port
        localAddr = ":0"
    }

    if serverAddr == "" {
        // use the default stun server
        serverAddr = "stun.qwq.pink:3478"
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
