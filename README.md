# Stellar JSON RPC Integration
Stellar JSON RPC is a Rust project designed to facilitate interactions with smart contracts deployed on the Stellar blockchain. This integration enables developers to easily perform query and mutate operations on Stellar smart contracts.

Key Features:
- Query: Perform read operations on smart contracts
- Mutate: Execute write operations on contracts by sending transactions to the Stellar network.
- Bytes Handling: The project supports methods that accept arguments as Bytes and return Bytes. This standard setup ensures compatibility with any function that follows this convention.
- Decoding: The returned Bytes can be decoded into structured data, enabling further processing and interaction.
Usage:
