package stun

import (
	"errors"
	"fmt"
	"net"
)

// RFC-3489 #10.1
// In test I, the client sends a STUN Binding Request to a server,
// without any flags set in the CHANGE-REQUEST attribute, and
// without the RESPONSE-ADDRESS attribute. This causes the server
// to send the response back to the address and port that the
// request came from.
func test1(
    c *Client, dst net.Addr,
) (mapped *net.UDPAddr, changed *net.UDPAddr, err error) {
    fmt.Println("send test1")
    msg, err := sendBindingRequest(c, dst, false, false)
    if err != nil {
        return nil, nil, err
    }

    // send timeout
    if msg == nil {
        return
    }

    changedAttr := msg.getAttribute(ATChangedAddress)
    if changedAttr == nil {
        return nil, nil, errors.New("test1 response doesn't include changed address")
    }

    changed, err = changedAttr.toAddr()
    if err != nil {
        return
    }

    mappedAttr := msg.getAttribute(ATMappedAddress)
    if mappedAttr == nil {
        return nil, nil, errors.New("test1 response doesn't include mapped address")
    }

    mapped, err = mappedAttr.toAddr()

    return
}

// RFC-3489 #10.1
// In test II, the client sends a Binding Request with both the
// "change IP" and "change port" flags from the CHANGE-REQUEST
// attribute set.
func test2(c *Client, dst net.Addr) (mapped *net.UDPAddr, err error) {
    fmt.Println("send test2")
    msg, err := sendBindingRequest(c, dst, true, true)
    if err != nil {
        return nil, err
    }

    // send timeout
    if msg == nil {
        return
    }

    mappedAttr := msg.getAttribute(ATMappedAddress)
    if mappedAttr == nil {
        return nil, errors.New("test2 response doesn't include mapped address")
    }

    mapped, err = mappedAttr.toAddr()

    return
}

// RFC-3489 #10.1
// In test III, the client sends a Binding Request with only
// the "change port" flag set.
func test3(c *Client, dst net.Addr) (mapped *net.UDPAddr, err error) {
    fmt.Println("send test3")
    msg, err := sendBindingRequest(c, dst, false, true)
    if err != nil {
        return nil, err
    }

    // send timeout
    if msg == nil {
        return
    }

    mappedAttr := msg.getAttribute(ATMappedAddress)
    if mappedAttr == nil {
        return nil, errors.New("test3 response doesn't include mapped address")
    }

    mapped, err = mappedAttr.toAddr()

    return
}
