package stun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
)

const (
    AttributeHeaderSize = 4
    MessageHeaderSize = 20
)

var (
    errInvalidAttribute = errors.New("invalid attribute")
    errInvalidMessage = errors.New("invalid message")
    errAttributeNotAddress = errors.New("attribute is not an address")
)

//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |         Type                  |            Length             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                         Value (variable)                ....
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//                Figure 4: Format of STUN Attributes
type Attribute struct {
    Type uint16
    Length uint16
    Value []byte
}

//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |x x x x x x x x|    Family     |           Port                |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                             Address                           |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type AddressAttribute struct {
    Family uint8
    Port uint16
    Address net.IP
}

func newAttribute(t uint16, v []byte) *Attribute {
    attr := new(Attribute)

    attr.Type = t

    if len(v) % 4 != 0 {
        paddings := [4]byte{}
        v = append(v, paddings[len(v)%4:]...)
    }

    attr.Value = v
    attr.Length = uint16(len(v))

    return attr
}

func (attr *Attribute) toAddr() (*net.UDPAddr, error) {
    var addr AddressAttribute
    if attr.Length != 8 {
        return nil, errAttributeNotAddress
    }

    switch attr.Type {
    case ATChangedAddress, ATMappedAddress, ATSourceAddress, ATResponseAddress:
        addr.Family = attr.Value[1]
        addr.Port = binary.BigEndian.Uint16(attr.Value[2:4])
        addr.Address = net.IP(attr.Value[4:8])

        return net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", addr.Address, addr.Port))
    default:
        return nil, errAttributeNotAddress
    }
}

func (attr *Attribute) String() string {
    return fmt.Sprintf("Type: %d, Length: %d", attr.Type, attr.Length)
}

func (attr *Attribute) size() uint16 {
    return AttributeHeaderSize + attr.Length
}

func (attr *Attribute) encode() []byte {
    buf := make([]byte, attr.size())

    binary.BigEndian.PutUint16(buf[:], attr.Type)
    binary.BigEndian.PutUint16(buf[2:], attr.Length)

    copy(buf[AttributeHeaderSize:], attr.Value)

    return buf
}

func parseAttribute(buf []byte) (*Attribute, error) {
    fmt.Printf("buf: %x\n", buf)
    if len(buf) < AttributeHeaderSize {
        return nil, errInvalidAttribute
    }

    typ := binary.BigEndian.Uint16(buf[:2])
    length := binary.BigEndian.Uint16(buf[2:4])

    fmt.Printf("type: %d, length: %d\n", typ, length)

    offset := length + AttributeHeaderSize
    if offset > math.MaxUint16 || offset % 4 != 0 {
        return nil, errInvalidAttribute
    }

    return newAttribute(typ, buf[AttributeHeaderSize:offset]), nil
}

// RFC-3489 #11.2.4 CHANGE-REQUEST
// The attribute is 32 bits long, although only two bits (A and B)
// are used:
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// A is the "change IP" flag. And B is the "change port" flag
func newChangeRequestAttribute(changeIP, changePort bool) *Attribute {
    v := make([]byte, 4)
    if changeIP {
        v[3] |= 0x1 << 2
    }

    if changePort {
        v[3] |= 0x1 << 1
    }

    return newAttribute(ATChangeRequest, v)
}


//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |0 0|     STUN Message Type     |         Message Length        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                         Magic Cookie                          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  |                     Transaction ID (96 bits)                  |
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//              Figure 2: Format of STUN Message Header
type Message struct {
    Type uint16
    Length uint16
    TID []byte // 4 bytes magic cookie + 12 bytes transaction id
    Attrs []Attribute
}

func newMessage() *Message {
    msg := new(Message)
    
    msg.Length = 0
    msg.TID = make([]byte, 16)
    binary.BigEndian.PutUint32(msg.TID[4:], MagicCookie)
    
    rand.Read(msg.TID[4:])

    return msg
}

func (m *Message) String() string {
    var buf bytes.Buffer
    buf.WriteString(fmt.Sprintf("Type: %d\n", m.Type))
    buf.WriteString(fmt.Sprintf("Length: %d\n", m.Length))
    buf.WriteString(fmt.Sprintf("TID: %x\n", m.TID))
    buf.WriteString("Attributes: \n")

    for _, attr := range m.Attrs {
        buf.WriteString(attr.String())
        buf.WriteByte('\n')
    }

    return buf.String()
}

func (m *Message) addAttribute(attr *Attribute) {
    m.Attrs = append(m.Attrs, *attr)
    m.Length += attr.size()
}

func (m *Message) getAttribute(at uint16) *Attribute {
    for _, attr := range m.Attrs {
        if attr.Type == at {
            return &attr
        }
    }

    return nil
}

func (m *Message) encode() []byte {
    buf := make([]byte, m.Length + MessageHeaderSize)
    binary.BigEndian.PutUint16(buf[:], m.Type)
    binary.BigEndian.PutUint16(buf[2:], m.Length)
    
    copy(buf[4:], m.TID)

    offset := MessageHeaderSize
    for _, attr := range m.Attrs {
        offset += copy(buf[offset:], attr.encode())
    }

    return buf
}

func parseMessage(buf []byte) (*Message, error) {
    if len(buf) < MessageHeaderSize || 
        len(buf) > math.MaxUint16 + MessageHeaderSize {
        return nil, errInvalidMessage
    }

    msg := newMessage()
    msg.Type = binary.BigEndian.Uint16(buf[:2])
    msg.Length = binary.BigEndian.Uint16(buf[2:4])
    msg.TID = buf[4:20]

    offset := 0
    attrBuf := buf[MessageHeaderSize:]
    for offset < len(attrBuf) {
        attr, err := parseAttribute(attrBuf[offset:])
        if err != nil {
            return nil, err
        }

        msg.addAttribute(attr)
        offset += int(attr.size())
    }

    return msg, nil
}
