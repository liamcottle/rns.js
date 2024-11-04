# rns.js

An _in-progress_ implementation of the [Reticulum Network Stack](https://reticulum.network/) written in Javascript.

## What can it do?

- [x] Create a new Identity
- [x] Load an existing Identity from Public Keys or Private Keys
- [x] Connect with a `TCPClientInterface` to an existing RNS `TCPServerInterface`
- [x] Listen for incoming announces
- [x] Register a Destination
- [x] Listen for inbound packets to a Destination
- [x] Send outbound packets to a Destination
- [x] Send and receive opportunistic LXMF messages over single packets

## TODO

- [ ] Validate LXMF message signatures
- [ ] Support RNS Links
- [ ] Only send packets to relevant interface. Currently sends to all interfaces
- [ ] Support direct LXMF messages over Links
- [ ] Implement rate limits
- [ ] Support being a Transport node

## References

- https://reticulum.network
- https://github.com/markqvist/Reticulum
- https://github.com/markqvist/Reticulum/wiki/Wire-Packet-Formats
- https://gist.github.com/liamcottle/e85953bccd6a4f8b436ac4284b29af49

## License

MIT
