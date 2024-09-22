package stun

import "net"

func sendBindingRequest(
    c *Client,
    dst net.Addr,
    changeIP bool,
    changePort bool,
) (*Message, error) {
    msg := newMessage()
    msg.Type = MTBindingRequest

    if changeIP || changePort {
        attr := newChangeRequestAttribute(changeIP, changePort)
        msg.addAttribute(attr)
    }

    return c.send(msg, dst)
}

