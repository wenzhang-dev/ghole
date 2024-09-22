package stun

const (
    MagicCookie = 0x2112A442
)

// RFC-5389 #15.6 ERROR-CODE
const (
   ECTryAlternate = 300

   ECBadRequest = 400
   ECUnauthorized = 401
   ECUnknownAttribute = 420
   ECStaleCredentials = 430
   ECIntegrityCheckFailure = 431
   ECMissingUsername = 432
   ECStaleNonce = 438
   ECUseTLS = 433

   ECServerError = 500
   
   ECGlobalFailure = 600
)

// RFC-5389 #18.2 STUN Attribute
const (
    ATMappedAddress = 0x0001
    ATResponseAddress = 0x0002
    ATChangeRequest = 0x0003
    ATSourceAddress = 0x0004
    ATChangedAddress = 0x0005
    ATUsername = 0x0006
    ATPassword = 0x0007
    ATMessageIntegrity = 0x0008
    ATErrorCode = 0x0009
    ATUnknownAttributes = 0x000a
    ATReflectedFrom = 0x000b
    ATRealm = 0x000c
    ATNonce = 0x000d
    ATXorMappedAddress = 0x000e

    ATSoftware = 0x8022
    ATAlternateServer = 0x8023
    ATFingerprint = 0x8028
)

// RFC-3489 #11.1 Message Header
const (
    MTBindingRequest = 0x0001
    MTBindingResponse = 0x0101
    MTBindingErrorResponse = 0x0111
    MTSharedSecretRequest = 0x0002
    MTSharedSecretResponse = 0x0102
    MTSharedSecretErrorResponse = 0x0112
)

// RFC-3489 #10.1 Discovery Process
// NAT TYPE
const (
    NTUnknown = iota     // unknown nat type
    NTOpenInternat
    NTUdpBlocked
    NTSymUdpFirewall
    NTFull
    NTRes
    NTPortRes
    NTSym
)

func NT2String(typ int) string {
    switch typ {
    case NTOpenInternat:
        return "Open Internet"
    case NTUdpBlocked:
        return "UDP Blocked"
    case NTSymUdpFirewall:
        return "Symmetric UDP Firewall"
    case NTFull:
        return "Full cone NAT"
    case NTRes:
        return "Restricted cone NAT"
    case NTPortRes:
        return "Port Restricted cone NAT"
    case NTSym:
        return "Symmetric NAT"
    default:
        return "Unknown NAT"
    }
}
