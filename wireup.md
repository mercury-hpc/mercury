Establishing Two-Way Communication with "Wireup"

UCP addresses are long (addresses 185 bytes long are not uncommon)
and their length varies, so they are not suitable for embedding into
UCP messages as the "return address" in a two-way exchange of messages
(peer S -> request -> peer R, peer R -> reply -> peer S).

Also, UCP peers have to establish an endpoint for each peer before sending
it a message.  Establishing endpoints is a potentially costly operation
that we probably should amortize over many message transmissions.

To facilitate two-way communications, a peer establishes on each of
its remote peers a short, fixed-length Sender ID that it uses as a
return address.

Before a peer sends a message that requires the remote's reply, it looks
up the remote's endpoint and Sender ID.  The sender embeds the Sender
ID in the message and transmits it over the endpoint.  The recipient
uses the Sender ID to look up its endpoint for the sender, as well as
the recipient's Sender ID.  The recipient's Sender ID is embedded into
the reply, and the reply is sent over the endpoint.

Sender and recipient establish Sender ID -> UCP endpoint lookup tables by
performing a handshake called "wireup."  A sender starts the handshake
by establishing an endpoint for the recipient, assigning the recipient
a Sender ID, and sending that ID and the sender's UCP address to the
recipient in a "wireup request."

The recipient creates an endpoint for the sender, assigns a Sender ID
to the endpoint, and transmits the Sender ID back to the sender.

