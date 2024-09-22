package stun

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
    numRetryTimes = 9
    defaultTimeout = 100 * time.Millisecond
    maxTimeout = 1600 * time.Millisecond
    maxMessageSize = 4096
)

type Client struct {
    ServerAddr string
    LocalAddr string

    Conn net.PacketConn
    closeOnce sync.Once
    ClosedCh chan struct{}

    serverUDPAddr *net.UDPAddr
    localUDPAddr *net.UDPAddr
}

func NewClient(serverAddr, localAddr string) (*Client, error) {
    laddr, err := net.ResolveUDPAddr("udp4", localAddr)
    if err != nil {
        return nil, err
    }
    conn, err := net.ListenUDP("udp4", laddr)
    if err != nil {
        return nil, err
    }

    saddr, err := net.ResolveUDPAddr("udp4", serverAddr)
    if err != nil {
        return nil, err
    }
    
    return &Client {
        ServerAddr: serverAddr,
        LocalAddr: localAddr,
        Conn: conn,
        ClosedCh: make(chan struct{}),
        serverUDPAddr: saddr,
        localUDPAddr: laddr,
    }, nil
}

// Follow RFC 3489 and RFC 5389.
// Figure 2: Flow for type discovery process (from RFC 3489).
//                        +--------+
//                        |  Test  |
//                        |   I    |
//                        +--------+
//                             |
//                             |
//                             V
//                            /\              /\
//                         N /  \ Y          /  \ Y             +--------+
//          UDP     <-------/Resp\--------->/ IP \------------->|  Test  |
//          Blocked         \ ?  /          \Same/              |   II   |
//                           \  /            \? /               +--------+
//                            \/              \/                    |
//                                             | N                  |
//                                             |                    V
//                                             V                    /\
//                                         +--------+  Sym.      N /  \
//                                         |  Test  |  UDP    <---/Resp\
//                                         |   II   |  Firewall   \ ?  /
//                                         +--------+              \  /
//                                             |                    \/
//                                             V                     |Y
//                  /\                         /\                    |
//   Symmetric  N  /  \       +--------+   N  /  \                   V
//      NAT  <--- / IP \<-----|  Test  |<--- /Resp\               Open
//                \Same/      |   I    |     \ ?  /               Internet
//                 \? /       +--------+      \  /
//                  \/                         \/
//                  |Y                          |Y
//                  |                           |
//                  |                           V
//                  |                           Full
//                  |                           Cone
//                  V              /\
//              +--------+        /  \ Y
//              |  Test  |------>/Resp\---->Restricted
//              |   III  |       \ ?  /
//              +--------+        \  /
//                                 \/
//                                  |N
//                                  |       Port
//                                  +------>Restricted
func (c *Client) Discover() (natType int, mapped *net.UDPAddr, err error) {
    mapped1, changed1, err := test1(c, c.serverUDPAddr)
    if err != nil {
        return NTUnknown, nil, err
    }

    if mapped1 == nil {
        return NTUdpBlocked, nil, nil
    }

    idential := mapped1.Port == c.localUDPAddr.Port &&
        bytes.Equal(mapped1.IP, c.localUDPAddr.IP)

    mapped2, err := test2(c, c.serverUDPAddr)
    if err != nil {
        return NTUnknown, mapped1, err
    }

    if idential {
        if mapped == nil {
            return NTSymUdpFirewall, mapped1, nil
        }
        return NTOpenInternat, mapped1, nil
    }

    if mapped2 != nil {
        return NTFull, mapped1, nil
    }

    mapped3, _, err := test1(c, changed1)
    if err != nil {
        return NTUnknown, mapped1, err
    }

    if mapped3 == nil {
        return NTUnknown, mapped1, nil
    }

    if mapped1.Port == mapped3.Port && bytes.Equal(mapped1.IP, mapped3.IP) {
        mapped4, err := test3(c, changed1)
        if err != nil {
            return NTUnknown, mapped1, err
        }

        if mapped4 == nil {
            return NTPortRes, mapped1, nil
        }

        return NTRes, mapped1, nil
    }

    return NTSym, mapped1, nil
}

func (c *Client) Close() {
    c.closeOnce.Do(func(){
        c.Conn.Close()
        close(c.ClosedCh)
    })
}

// RFC-3489 #9.3
// Clients SHOULD retransmit the request starting with an interval of 100ms,
// doubling every retransmit until the interval reaches 1.6s.
func (c *Client) send(msg *Message, dst net.Addr) (*Message, error) {
    timeout := defaultTimeout
    msgBuf := make([]byte, maxMessageSize)

    for i:=0; i<numRetryTimes; i++ {
        if _, err := c.Conn.WriteTo(msg.encode(), dst); err != nil {
            return nil, fmt.Errorf("write conn failed: ", err)
        }

        c.Conn.SetReadDeadline(time.Now().Add(timeout))
        if timeout < maxTimeout {
            timeout *= 2
        }

        for {
            length, _, err := c.Conn.ReadFrom(msgBuf)
            if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
                break
            } else if err != nil {
                return nil, fmt.Errorf("read conn failed: %s", err)
            }

            rsp, err := parseMessage(msgBuf[:length])
            if err != nil {
                return nil, fmt.Errorf("parse message failed: %s", err)
            }

            if !bytes.Equal(msg.TID, rsp.TID) {
                continue
            }

            return rsp, nil
        }
    }

    // timeout is not an error
    return nil, nil
}
