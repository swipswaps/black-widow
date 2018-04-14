# Protocol

Communication is done over UDP. with Mainline DHT KRPC, from now on called DHT messages, on the same socket, so all assumptions are based off that.

Assumptions in this case are:

* Length of the packet is already known
* The additional overhead is always 44 (UDP + IPv6 headers)
* Packets may be silently dropped
* Packets may be received out of order

## Encryption, Signing, Hashing and DH

Hardcoded for version 1 of the black widow protocol the following algorithms are being used

| Type | Algorithm |
| --- | --- |
| (EC)DH | X25519 |
| Signing | Ed25519 |
| Encryption | ChaCha20 |
| Hash | HKDF: SHA-512, Packet HMAC: SHA-1 |

(*hipster* af.)

## Overcoupling packet

Since we need to make difference between DHT messages and our messages, the first byte is used as identification, when the first byte is `d` in ASCII (so 100) it is a DHT message, this is because a bencoded dictionary always starts with an `d`, and a DHT message is always a bencoded dictionary.

### Type table

Prefix (decimal) | Type
--- | ---
`c` (`99`) | [Encrypted Packet](#encrypted-packet)
`d` (`100`) | [DHT Message](#dht-message)
`e` (`101`) | [Key Exchange Message](#key-exchange-message)

## DHT Message

uses the Mainline DHT spec, which is documented by BitTorrent: [BEP-0005](http://bittorrent.org/beps/bep_0005.html), the communication of Mainline DHT is completely decoupled from black widow communication.

## Key Exchange Message

This message is used to create a black widow session, this message sent by the initiator, and send as response to the initiator.

| Offset | Size | Name | Description     |
| ------ | ---- | ---- | --------------- |
| 0      | 1    | Version | The version of the black widow protocol, hardcoded the value 1 right now |
| 1 | 32 | Public key | The public key peer of the requesting peer |
| 33 | 32 |  ECDH public key | The ephemeral public key for the ECDH (MUST newly generated for each session) |
| 65 | 64 | ECDH signature | the signature of the ECDH public key by the peer's public key |
| 129 | 1 | Auth type | the type of authentication being used, 0 = Authority, 1 = Shared Secret |
| 130 | 64 | Proof | If auth type is Shared Secret, this is the signature of the shared secret, signed by the ephemeral key used for ECDH, if the auth type is Authority, it's the signature of the peer's public key, signed by the authority.

The message is silently discarded if it's faulty or corrupted

the ECDHE results in key material on which KDF will be applied with the following parameters:

```
SK = HKDF(algo: SHA-512, key: KeyMaterial, info: NetworkId, length: 64 bytes)
```

The secret key (`SK`) is then split in 2, the first 32 bytes will be used as authentication key, the next 32 bytes as encryption key.

## Encrypted Packet

*L* is length of packet

Offset | Size | Name | Description
---    | ---  | ---  | ---
0 | 8 | Packet id | 64-bit number indicating the packet id, for each new packet this is increased, at the start of the session it should be a random number, should overflow, but skip 0. MUST never be 0. is also used as IV for the encrypted payload
8 | *L* - 8 | Payload | the actual encrypted payload, see here: [Encrypted Packet payload (decrypted)](#encrypted-packet-payload--decrypted-)

### Encrypted Packet payload (decrypted)

Offset | Size | Name | Description
--- | --- | --- | ---
0 | 1 bit | Compression | If this bit is 1, the payload of this packet is compressed using `DEFLATE`
1 bit | 7 bits | Type | which type of packet this is, 0 = Ethernet Frame
1 | *L* - 21 | Payload | Packet type dependent payload
*L* - 21 | 20 | HMAC | The HMAC made by `HMAC(data: Payload, algo: SHA-1, key: AuthenticationKey)`  

## Ethernet Frame

This is actually just the raw ethernet frame. since routing internally in black widow is also done by MAC address,

All things considered, the maximum overhead of Black Widow would be the following

Size | From
--- | ---
40 | IPv6
4 | UDP 
1 | Black Widow Prefix
8 | Black Widow Packet Id
1 | Black Widow Packet Type
20 | Black Widow Packet HMAC
**Total** |
74 | Total overhead
  
This would mean Black Widow should default with an MTU of 1426 
