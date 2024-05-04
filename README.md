# RUMI

A hypothetical Zero Knowledge discovery service design for mapping distinct iidentifiers!

The term "zero-knowledge" refers to the concept of minimizing the amount of information the server learns during interactions with clients.

The benefit of this is that the server only learns about the association between the iidentifiers when the client explicitly requests it. This means that the server does not have access to the complete list of iidentifiers of any client unless the client chooses to share that information. Also the client can refer iidentifier only when they know the other corresponding iidentifier, not offline guesses would work.

For example, suppose we are using a messaging app, you often see that the app requires access to all your contacts, which you don't want to, but you are forced to! Traditionally, the server will store your contacts and if the server's security is compromised or if there are vulnerabilities, this metadata could potentially be accessed by unauthorized parties. In case of zero-knowledge discovery service, the server only know about a specific contact limited to the interaction in messaging app as the server receives blinded data from client without access to original information. The server's knowledge of contacts is temporary and limited to the current interaction. Once the interaction is completed, the server does not retain information that could compromise the privacy. This ensures that the server only learns about data involved in the immediate interaction.
