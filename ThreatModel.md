# aetmodel
Documentation of threat model


## System Model 

The **system model** describes the high level view of the system and the context in which it is used. 
It abstracts the details and allows to define the trust boundaries and state changes relevant to security.

General blockchain, allowing whatever actions on the blockchain.

Different from BitCoin in that it has many more options and that it introduces an oracle.
Many more transactions possible than in BitCoin, faster in 2 ways:  
	* Faster block rate  
	* Offline state channels (micro-payments per second)


If there are too many transactions, some transaction might be stuck in the pool.  
	* Miners may attempt to block the vote by not processing the transactions with the vote(s)

High-level features:	
	
1. Account
	* **Public key on the chain + private key** - the blockchain does not handle the private keys of the users. Users are assumed to take care of their own keys; we trust the key generation code;
	* **Tokens as value on the account** - will be stored in wallets of some sort;
	* **Nonce** is a counter that increases upon every transaction.

2. **Contract language** a DSL for writing contracts.
3. **Oracle mechanism** ~ web server that exposes a certain API
4. **Naming service** - allows to claim a name;
5. **State channels** - allow offline transactions;
	* Opening the channel:  
	* Closing the channel	
6. **Privacy** - currently a non-issue;
7. **Communication with miners** - "seed" nodes provided by Aeternity, new nodes from the network through gossiping.
8. **Transaction fees** 
This is a community blockchain, minimum fees depending on a vote.
Paying more than a minimum fee is possible.

Blockchain-ng - selecting a leader who can mine the blockchain, until the next leader is elected.


## Assets
**Assets** describe are the valuable data that the business cares about

## Assumptions

**Assumptions** about the system model and about the way users will interact with the system

## Threat Modelling

Complementary paths:  
###1. Use the **STRIDE** model to threat modelling:   
* **Spoofing** - Impersonating something or someone else.  
* **Tampering** - Modifying data (transaction content?) or code.   
* **Repudiation** - Claiming	to	have	not  performed an action.   
* **Information disclosure** - Exposing information to someone not authorized to see it.  
* **Denial of service** - Deny or	degrade service to users.  
* **Elevation of privilege** -  Gain	capabilities without proper authorization
 
###2. Go through Bitcoin-Threat-Model.md and check relevance of attacks 

####An attacker could steal a users private keys
	* Users
	* Miners
	* Peers
	* Oracles
	* Contracts
 * Multiple malicious actions possible (enumerate to build tree)
 * **mitigation** ensure key never purposefully in the system
 * **past attacks** ...
 * Spoofing; Denial of Service;

 
####Broadcasting fake transactions
 * Invalid transactions - can be enabled by vulnerablities in the verification sw 
 * Tampered transactions - e.g. executing actions in the name of a contract
 * **mitigation** ensure key never purposefully in the system
 * **past attacks** ...
 * Denial of Service - only gossip valid transactions; "banning" users maybe implemented; information disclosure.
 


  
## STRIDE Threat Trees

### 1. Spoofing

|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   |
|---|---|---|---|---|
|   |   |   |   |   |
|   |   |   |   |   |
|   |   |   |   |   |

### 2. Tampering
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   |
|---|---|---|---|---|
|   |   |   |   |   |
|   |   |   |   |   |
|   |   |   |   |   |

### 3. Repudiation
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   |
|---|---|---|---|---|
|   |   |   |   |   |
|   |   |   |   |   |
|   |   |   |   |   |

### 4. Information Disclosure
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   |
|---|---|---|---|---|
|   |   |   |   |   |
|   |   |   |   |   |
|   |   |   |   |   |

### 5. Denial of service
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   |
|---|---|---|---|---|
|   |   |   |   |   |
|   |   |   |   |   |
|   |   |   |   |   |

### 6. Elevation of privilege
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   |
|---|---|---|---|---|
|   |   |   |   |   |
|   |   |   |   |   |
|   |   |   |   |   |

## Conclusions

### Threats to be mitigated

### Threats to be eliminated

### Threats to be transferred

### Accepted risks



