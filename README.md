# Black Widow (`bw`)

A Meshnet VPN on Layer 2.

🔥 **WARNING!** 🔥 This VPN, it's protocol and the used cryptography library has not
received any formal or informal audit, use at your own risk.

# What is it?

Black Widow is a simple and efficient decentralised VPN: there is no central VPN server,
the nodes are interconnected to avoid creating a single point of failure.

With Black Widow every client turns into a VPN server so to say, or node in our case.
This removes the single point of failure of having a central VPN server. This is also
makes response times lower between 2 VPN clients, because their connection is direct.
The downside of this is that the routing may become more complex, because there is no
routing oracle anymore in the center, without correct handling of this situation we may
create Layer 2 loops.

Because routing is a complex issue, Black Widow provides multiple [routers](#routers)

# Protocol

Since you don't want to leak internetwork communication, the protocol is build up with
encryption in mind, and uses ChaCha20, Ed25519 and X25519 at it's core.

More details about that [here](docs/protocol.md)

# Routers

Black Widow has several router implementations, so be sure to chose the one that fits your
use case best.

## Dumb router

This is the first router build and is a very simple MAC to node ID map, and will not
rebroadcast broadcast messages, preventing a broadcast storm.

The downsides of this are that there is no relaying, and if 1 node is not connected to
another node, they will not be able to talk to each other.

## Python router

**Notice:** For this router to be included you must build Black Widow with the feature
`python-router`, since the `pyo3` runtime requires certain rustc feature flags to be turned
on, it will only build on the nightly branch of rust.

The python router starts a python runtime which may hook in to the Black Widow router
functions, allowing you to prototype a router in python before typing it in rust
An example can be seen [here](python/example_router.py)

This is as you might expect, by far the most inefficient router (gives you surprisingly
enough 80% of the performance of a pure rust router), and I do not recommend running it
in production.

# What does it *not* do

It doesn't provide any DHCP server built-in, this was initially an idea, but I chose to
scrap that, and will be building a separate project which handles DHCP in a distributed
manner.

It's not meant to be a VPN in the sense of how VPN is currently seen aka full network proxy.
While you may be able to build a router which allows for this, this is not the primary goal
for this project.

# Current state

Currently this project works™, but is still looking at the following challenges:

- [ ] provide an user friendly CLI interface
- [ ] provide an unix socket for control
- [ ] figure out if we still want to use DHT for node publishing
- [ ] allow preconfigured peers
- [ ] add health checks for peers
- [ ] document and clean up code
- [ ] config and key generation
- [ ] look into noise protocol integration?

# License

*TODO: Add a license (preferably GPLv3 :D)*
```
    Copyright (c) 2018 eater and contributors
```
