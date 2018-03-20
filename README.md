# Black Widow

A Meshnet VPN on Layer 2.

# Ideas

- Focus on internal network first
- node publishing on mainline DHT
- protocol:
    - node verification via shared secret or signed DH key
    - ECDHE key exchange
    - ChaCha20/AES encrypted packets
- static announcement, with anycast support of hostnames and ips
- internal routing table and known ips and hostnames via internal DHT
    - implies relay support
- intercept hostname and ip announcements and add to own list and announce as such
- built-in DNS server for hostnames (powerdns with pipe interface can be used while there is no built-in)

# Execution

Maybe?
