# AXÉ 

Axé is a social protocol on top of breeze network that provides a base social 
identity layer that can be used by other more specialized social protocols.

## Social Protocols 

Breeze network is designed to provide a scalable and inexpensive infrastructure
for autonomous digital interactions between people. Besides general functionality around its fungible token that overns the economics and governance of its 
infrasstrructure it offers a general purpose void instruction.

Axé starts from this void instruction and ads the functionality of proof of 
authorship with 

## Attorney



## Data Structure

Field           Type                Length          Protocol
--------------- ------------------  --------------  -----------
Version         0                    1 byte          Breeze
ActionKind      IVoid                1 byte          Breeze
Epoch           Numeric              8 bytes         Breeze
Protocol        Axé | Other          4 bytes         Breeze
  Author        Token               32 bytes         Axé
  AxéKind       AVoid                1 byte          Axé
  Data          Variable               Variable      Other
  Attorney      Token               32 bytes         Axé
  Signature     Signature           32 bytes         Axé
Wallet          Token               32 bytes         Breeze
Fee             Numeric              8 bytes         Breeze
Signature       Signature           32 bytes         Breeze

## Axé Protocol

Actions filtered by a trusted node running axé protocol 