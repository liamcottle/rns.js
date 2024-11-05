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
- [x] Send and receive direct LXMF messages over an inbound Link
- [x] Accept inbound Links to a Destination
- [x] Create outbound Links to a Destination
- [x] Close Links and listen for when they are closed by the other side
- [x] Send and receive data packets over an established Link

## Install

```
npm install @liamcottle/rns.js
```

## Simple Example

```
import { Reticulum, TCPClientInterface } from "@liamcottle/rns.js";

// create rns instance
const rns = new Reticulum();

// add interfaces
rns.addInterface(new TCPClientInterface("Test Net", "amsterdam.connect.reticulum.network", 4965));
rns.addInterface(new TCPClientInterface("Between the Borders", "reticulum.betweentheborders.com", 4242));
rns.addInterface(new TCPClientInterface("V0ltTech", "v0lttech.com", 4242));

// listen for announces
rns.on("announce", (event) => {
    console.log(`Announce Received: ${event.announce.destinationHash.toString("hex")} is now ${event.hops + 1} hops away on interface [${event.interface_name}]`);
});

```

## Examples

There's a few scripts in the [examples](./examples) folder for reference on what currently works.

## TODO

- [ ] Tidy up logic for sending packets and packet types
- [ ] Implement Link heartbeat packets
- [ ] Validate LXMF message signatures
- [ ] Only send packets to relevant interface. Some packets still send to all interfaces
- [ ] Implement Ratchets
- [ ] Implement Resources over Links
- [ ] Support LXMF messages over Link Resources
- [ ] Support LXMF stamps and tickets
- [ ] Implement rate limits
- [ ] Support being a Transport node

## References

- https://reticulum.network
- https://github.com/markqvist/Reticulum
- https://github.com/markqvist/Reticulum/wiki/Wire-Packet-Formats
- https://gist.github.com/liamcottle/e85953bccd6a4f8b436ac4284b29af49

## License

MIT
