# aetmodel
Documentation of threat model

## Definition

**Client Node** is an aetherium node with no mining capability.

**Penetration testing** (aka ***pentesting***) authorized simulated attack on a computer system, performed to evaluate the security of the target system. 
The test aims to identify the target's strengths and vulnerabilities, including the potential for unauthorized parties to gain access to the system's software and data.

**Miner Node** is an aetherium node with mining capability.

**Node** is an aetherium node with a private key; includes miner nodes, client nodes, peers, etc.



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
* **(1) Spoofing** - Impersonating something or someone else.  
* **(2) Tampering** - Modifying data (transaction content?) or code.   
* **(3) Repudiation** - Claiming	to	have not performed an action.   
* **(4) Information disclosure** - Exposing information to someone not authorized to see it.  
* **(5) Denial of service** - Deny or	degrade service to users.  
* **(6) Elevation of privilege** -  Gain capabilities without proper authorization
* **(7) Other?...**
 
###2. Go through Bitcoin-Threat-Model.md and check relevance of attacks 

####========================================================

####(1) Spoofing: Spoof user actions

##### 1. Obtain private keys
	(1.1) At generation time.
	(1.2) At rest / in storage.
		(1.2.1) Local storage.
		(1.2.2) Third-party storage (e.g. on-line wallets).  
		(1.2.3) Exploit cross-site scripting vulnerabilities browser-based wallets.
	(1.3) Node run time.
	(1.4) At logging time.

 * **Past attacks** 
 	* [2011 | Bitcoin | Private keys stolen from wallet](https://bitcointalk.org/index.php?topic=16457.msg214423#msg214423)
 	* [2017 | Bitcoin | MtGox wallet.dat file stolen (e.g. through exploit, rogue employee, back-up theft)](https://blog.wizsec.jp/2017/07/breaking-open-mtgox-1.html)
 	* [2017 | Ethereum | Malicious wallet Providers](https://mybroadband.co.za/news/banking/214178-ethereum-wallet-provider-steals-account-keys-and-cashes-out.html)
 	* [2017 | Ethereum | Exploit in Parity wallet](https://thehackernews.com/2017/07/ethereum-cryptocurrency-hacking.html)
 	* [2017 | Ethereum | Bug in Parity wallet](https://www.theguardian.com/technology/2017/nov/08/cryptocurrency-300m-dollars-stolen-bug-ether)
 	* [2018 | Ethereum | Bug/misconfiguration in client node](https://thehackernews.com/2018/06/ethereum-geth-hacking.html) 
 	* [2018 | Ethereum | Conrail wallet exploit](https://mashable.com/2018/06/11/coinrail-exchange-hack/?europe=true)
 	* [2014 | Bitcoin | XSS wallet vulnerability](https://www.reddit.com/r/Bitcoin/comments/1n57uj/im_attempting_to_reach_a_security_contact_at/)
 * **Categories** Spoofing; Denial of Service.  
 ``` 
 info: "Categories" denote the threats where attacks listed in this branch may be applied;
 ```

##### 2. Exploit vulnerabilities in authentication code
	(2.1) Exploit incomplete or otherwise flawed signature verification
        (2.1.1)  when validating transactions
 * **Past attacks** 
 	* [2017 | Generic | Signature verification flaw 1](https://www.cvedetails.com/cve/CVE-2014-9934/)
	* [2017 | Generic | Signature verification flaw 2](https://www.cvedetails.com/cve/CVE-2017-2898/)
	
##### 3. Exploit vulnerabilities in network communication
	(3.1) Exploit DNS & BGP vulnerabilities to redirect traffic to an impersonated wallet web service;
 * **Past attacks** 
 	* [2018 | Etheremum | BGP hijacking](https://www.theverge.com/2018/4/24/17275982/myetherwallet-hack-bgp-dns-hijacking-stolen-ethereum)


####Broadcasting fake transactions
 * Invalid transactions - can be enabled by vulnerablities in the verification sw 
 * Tampered transactions - e.g. executing actions in the name of a contract
 * **mitigation** ensure key never purposefully in the system
 * **past attacks** ...
 * Denial of Service - only gossip valid transactions; "banning" users maybe implemented; information disclosure.

####(5) Denial of service

##### 1. Overloading with transactions
Creating and posting a transaction is a computationally cheap action for an attacker. A valid transaction is a transaction that can potentially be included in a future block and that a miner receives a fee for.
Valdiation of a transaction is computational cheap, but having to validate many transactions that cannot be included in a block, is a computational overhead for a node. If an attacker could
post enormous amounts of transactions to the network, it could potentially impact the rate in which correct transactions are accepted.
Transactions may validate but nevertheless not be possible to include in a block. For example, an attacker could post a spend-transaction including more tokens than the from account contains. This transaction is then kept in the transaction pool for a while and *check this*  validated for each new block candidate.  

	(5.1) Posting invalid transactions.
	(5.2) Posting valid, but impossible transactions
	(5.3) Exploiting memory leaks in cleaning transaction pool
	
 * **Past attacks** 
  
## STRIDE Threat Trees

### 1. Component Spoofing

|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priotity |
|---|---|---|---|---|---|---|
| 1.1  | Vulnerabilities in key generation implementation can lead to generation of keys that are predictable or brute-forceable  | Verify Key generation implementation and use keys of sufficient length |  | Private keys are 256 bits: both for P2P connections as well as for signing transactions.  | TODO: verify that the user cannot accidentally use a key with less than 256 bits | low priority (unlikely) |
|  1.2.1 | Vulnerabilities in client platform, exploited through trojans or viruses can expose private keys   |  N/A | N/A  | Out of scope (OOS) | | |
|  1.2.2    | Vulnerabilities in 3rd party wallets and applications can expose private keys  | N/A  |  N/A | OOS; NOTE: Risk of multiple account compromise   | | |
|1.2.3.     | Vulnerabilities in web services may allow an adversary to run and execute mailicious scripts on client nodes, potentially revealing the wallet| N/A  |  N/A | OOS; NOTE: Risk of multiple account compromise   | | |
|  1.3 | Remote exploitation of client applications  | Penetration testing of  external interfaces of application (http, noise) | Erlang distribution daemon blocked for incoming requests |  | TODO: Define penetration testing | |
| 1.4  | Client implementation can inadvertently expose private keys in logs and memory dumps | a. Ensure code never logs private key; b. User private keys are not handled by node (peer key and mining key are); c. Never send client logs/memory dumps unencrypted over public network; | Ensure secure access to monitoring software (datadog) |  | TODO: check encrypted submission to datadog | priority low |
|  2.1 | Code flaws in signature verification can be exploited to spoof user actions | Thoroughly and continuously test signature verification code;  | Exclude/ignore outdated clients (?)  |   | TODO: review robustness of signing | |
|  2.1.1 |  Code flaw in transaction validation can be exploited to spoof user actions | A binary serialization of each transactions is signed with the private key of the accounts that may get their balances reduced.  |   | Signing is performed using NaCL cryptographic signatures (implemented in LibSodium). Forging a signature is considered extremely difficult. The LibSodium library has an active user community (*has it been certified?*). LibSodium is connected via the Erlang enacl library (*version ...*), which has been reviewed for security violations.  | TODO: Check libsodium guarantees and update to latest version of enacl | |
|  3.1 |  Needs additional investigation |   |   |   | |   |


### 2. Tampering
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
|   |   |   |   |   |   |   |
|   |   |   |   |   |   |   |
|   |   |   |   |   |   |   |

### 3. Repudiation
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
|   |   |   |   |   |   |   |
|   |   |   |   |   |   |   |
|   |   |   |   |   |   |   |

### 4. Information Disclosure
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
|   |   |   |   |   |   |   |
|   |   |   |   |   |   |   |
|   |   |   |   |   |   |   |

### 5. Denial of service
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
| 5.1  | Posting invalid transactions  | The node that receives a transactions validates this transaction. Invalid transactions are rejected and never propagated to other nodes. | The node that receives a transactions validates this transaction. Invalid transactions are rejected and never propagated to other nodes. A valid transaction is a transaction that can potentially be included in a future block and that a miner receives a fee for.  |   |   |  |
| 5.2  | Posting valid, but impossible transactions  | Validation is light-weight and ensures that if the transaction is accepted in a block candidate fee and gas can be paid.  | Valid transactions have a configurable TTL that determines how long a transaction may stay in the memory pool. By default a node is configured to have a transaction in the pool for at most 256 blocks.  |   |   |   |
| 5.3  | Exploiting memory leaks in cleaning transaction pool  | Erlang is a garbage collected language _TODO: names as atoms_  |   |   |   |   |
|   |   |   |   |   |   |   |
|   |   |   |   |   |   |   |

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



