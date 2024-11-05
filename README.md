# rns.js

An _in-progress_, implementation of the [Reticulum Network Stack](https://reticulum.network/) written in Javascript.

This implementation is extremely limited, will likely have breaking changes and is probably not what you should be using.

I am implementing this to learn the RNS stack at the protocol level, while writing it in a language I am very familiar with.

At this stage, I will only be working on the features I want to use, rather than building a complete alternative transport stack.

You should probably look at the official reference stack written in Python;

- https://github.com/markqvist/Reticulum

## What can it do?

- [x] Create a new Identity
- [x] Load an existing Identity from Public Keys or Private Keys
- [x] Connect with a `TCPClientInterface` to an existing RNS `TCPServerInterface`
- [x] Listen for incoming announces
- [x] Register a Destination
- [x] Listen for inbound packets to a Destination
- [x] Send outbound packets to a Destination
- [x] Send and receive opportunistic LXMF messages over single packets
- [x] Accept inbound Links to a Destination
- [x] Create outbound Links to a Destination
- [x] Send and receive data packets over an established Link

## TODO

- [ ] Validate LXMF message signatures
- [ ] Only send packets to relevant interface. Currently sends to all interfaces
- [ ] Implement Resources over Links
- [ ] Support LXMF messages over Link Resources
- [ ] Implement rate limits
- [ ] Support being a Transport node

## References

- https://reticulum.network
- https://github.com/markqvist/Reticulum
- https://github.com/markqvist/Reticulum/wiki/Wire-Packet-Formats
- https://gist.github.com/liamcottle/e85953bccd6a4f8b436ac4284b29af49

## License

MIT
