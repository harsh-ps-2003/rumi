# RUMI

A hypothetical Zero Knowledge discovery service design for mapping distinct identifiers!

The term "zero-knowledge" refers to the concept of minimizing the amount of information the server learns during interactions with clients.

## Flow 

    1. Client hashes the identifier to a point on the curve and then blind it using the secret (client-blinded identifier point) that only the client has!
    2. Client sends the N-bit prefix of hashed identifier and the client-blinded identifier point of curve to Server
    3. On receiving the Client's data, Server calculates the double blinded point using server secret and then returns the chunk of blinded data corresponding to the prefix to client
    4. Client un-blinds the double blinded identifier point using the inverse of secret that only the client has.
    5. If match is found in server response, client calculates the un-blinded userID point from hashed identifier which is further decoded to UUID

The benefit of this is that the server only learns about the association between the identifiers when the client explicitly requests it. This means that the server does not have access to the complete list of identifiers of any client unless the client chooses to share that information. The blinding process ensures that the identifiers are obscured before transmission to the server, and the server only receives blinded data along with hash prefixes. Without the ability to reverse the blinding process (which requires knowledge of the client's secret key), the server cannot directly link the blinded identifiers to the original identifiers or perform any meaningful analysis on them. This enhances the privacy and confidentiality of the client's data and prevents the server from having unrestricted access to sensitive information. Also the client can refer identifier only when they know the other corresponding identifier, not offline guesses would work.

For example, suppose we are using a messaging app, you often see that the app requires access to all your contacts, which you don't want to, but you are forced to! Traditionally, the server will store your contacts and if the server's security is compromised or if there are vulnerabilities, this metadata could potentially be accessed by unauthorized parties. In case of zero-knowledge discovery service, the server only know about a specific contact limited to the interaction in messaging app as the server receives blinded data from client without access to original information. The server's knowledge of contacts is temporary and limited to the current interaction. Once the interaction is completed, the server does not retain information that could compromise the privacy. This ensures that the server only learns about data involved in the immediate interaction.

### Elliptic Curve Cryptography

The best blog to learn ECC that I could find out was [this](https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/)! 

