# aetmodel
Documentation of threat model

## List of acronyms
**CORS** Cross-Origin Resource Sharing

**EoP** Elevation of Privilege  
**OOS** Out Of Scope  
**PRNG** Pseudo-Random Number Generator   
**MitM** Man-in-the-Middle (attack)
**NTP** Network Time Protocol   
**XSS** Cross-Site Scripting (exploit)
## Definitions

**Client Node** is an Aeternity node with no mining capability.

**Miner Node** is an Aeternity node with mining capability.

**Noise protocol** [Crypto protocol based on Diffie-Hellman key agreement](http://noiseprotocol.org/noise.html) that we use with [specific handshake](https://github.com/aeternity/protocol/blob/master/SYNC.md) (**XK**) and encryption (ChaCHaPoly).

**Node** (aka **Epoch node**) umbrella term for Aeternity protocol participant; includes miner nodes, client nodes, peers, etc.
Identified by a URI consisting of the protocol 'aenode://', the public key, an '@' character, the hostname or IP number, a ':' character and the Noise port number.  

**Connection** is a communication channel between two nodes peers. There is only one connection between each two peers.

**Peer Node** [is a node participating in a channel](https://github.com/Aeternity/protocol/tree/master/channels#terms).
**Penetration testing** (aka ***pentesting***) authorized simulated attack on a computer system, performed to evaluate the security of the target system.
The test aims to identify the target's strengths and vulnerabilities, including the potential for unauthorized parties to gain access to the system's software and data.  
**Predefined Epoch Node** This is a peer that is automatically connected to upon node startup.

**Spoofing** is an attack in which a person or program successfully masquerades as another by falsifying data, to gain an illegitimate advantage.

**State Channel** [is an off-chain method for two peers to exchange state updates](https://github.com/Aeternity/protocol/tree/master/channels#terms), each node can have multiple state channels and a pair of nodes can also have multiple channels between each other, which should be multiplexed over one connection. Epoch nodes come with a state channel web-service API as a reference implementation.

**Transactions** A transaction is an artefact that you post to the blockchain to alter its state. There are many different kind of transactions, e.g. to transfer tokens from one account to another, to create a contract, to query an oracle, etc.
If a transaction is syntactically incorrect it will just be ignored. Syntactic correct transaction can be classified in 3 groups:
  * **Invalid** transactions are rejected by the validation algorithm. A reason could be that the nonce of a spend transaction is already used on chain, that the TTL (time-to-live) is less than the present height of the chain, etc. If the validation algorithm rejects it, it is an invalid transaction.
  * **Unusable** transactions are also rejected by the validation algorithm, but only because they cannot be used at the moment, but potentially in the future. For example, a transaction that spends more tokens than it has in the account is unusable, but can become usable a few blocks later if another transaction transfers money to it.
  * **Valid** transactions are transactions that are accepted by the validation algorithm and can be part of the next generated block. A miner is not forced to use a valid transaction in a generated block; miners are free to pick any number of valid transactions they prefer (e.g. depending on fees connected to them).


## System Model

The **system model** describes the high level view of the system and the context in which it is used.
It abstracts the details and allows to define the trust boundaries and state changes relevant to security.

General blockchain, allowing whatever actions on the blockchain.

Different from BitCoin in that it has many more features and that it introduces oracles, name registration, contracts, state-channels and governance.
Higher transaction throughput possible than in BitCoin, faster in 3 ways:  

		1. Faster block rate
		2. Bitcoin-NG technology with key-blocks and micro-blocks
		3. Off-chain state channels (micro-payments per second)

High-level features:

1. **Account**
	* **Public key on the chain + private key** - the blockchain does not handle the private keys of the users. Users are assumed to take care of their own keys; we trust the key generation code;
	* **Tokens** - each account holds a positive amount of tokens (aeons);
	* **Nonce** is a counter that increases upon every transaction.

2. **Contract language** a DSL for writing contracts.
3. **Oracle mechanism** ~ An oracle operator scans the blockchain for query transactions and posts answers to those queries to the chain.
4. **Naming service** - allows to claim a name;
5. **State channels** - allow offline transactions;
	* Opening the channel
	* Closing the channel
6. **Privacy** - currently a non-issue;
7. **Communication with nodes** - "seed" nodes provided by Aeternity, new nodes from the network through gossiping.
8. **Transaction fees**
This is a community blockchain, minimum fees are agreed upon by governance. Paying more than a minimum fee is possible and expected to be steered by the market.
9. **Governance**
There is a set of parameters, such as minimal transaction fee, that may be modified over the lifetime of the blockchain. Changes must be agreed upon by the majority of the community and governance is the mechanism to vote on the chain in favour or against changes.

=============================================

![Overview System Diagram](https://github.com/Aeternity/aetmodel/blob/master/epoch-system-diagram.jpeg)

=============================================

## Assets
**Assets** describe are the valuable data that the business cares about
1. **Private Keys** are of paramount importance, the "golden nuggets"; they uniquely identify epoch nodes and used to authenticate transactions.
2. **Password for key encryption** used to encrypt keypair files stored to disk (under invstigation if ***both*** keyspair files are encrypted - only private key is enough).
3. **Communication on state channels for cooperating nodes** - this is potentially an asset (according to [issue#2](https://github.com/ThomasArts/aetmodel/issues/2), but is unconfirmed and needs further investigation.
4. **Tokens** are an expression of value in the system.
Control over tokens that belong to an account should be unconditionally linked to the respective account's private key.
5. **Computational power** - we consider Tokens and computational power equivalent in the context of the Aeternity blockchain.

## Assumptions

**Assumptions** about the system model and about the way users will interact with the system.

1. **The user model is completely flat**, there is only one type of users in the system, all users have equal privileges.
	* To be discussed

2. **Security of Epoch nodes** relies on the security of the compilation toolchain.

3. **Security of Epoch nodes** relies on the absence of malicious Erlang nodes running on the same platform.

### FALSE Assumptions
1. **A node's private key** is the only data that must remain secret at all times   

	* 	FALSE, based on [issue #2](https://github.com/ThomasArts/aetmodel/issues/2): The messages exchanged in a state channel should be private—as long as peers cooperate—, i.e. MitM should not be possible.


2. **All code runs in the same privilege ring**, i.e. all code on the epoch nodes has the same privilege level.

	* FALSE, based on [issue #3](https://github.com/ThomasArts/aetmodel/issues/3): the AEVM executes untrusted code and EoP should not be possible.


## Threat Model

The threat model described in this document is based on three artifacts:

### 1. The **STRIDE** model:   

STRIDE is a mnemonic for things that go wrong in computer and network systems security [1],[2].
It stands for Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.
We base the threat model described in this document on an adaptation of the STRIDE methodology.
A virtualization of the threat trees will be added in the future if necessary.

* **(1) Spoofing** - Impersonating something or someone else.  
* **(2) Tampering** - Modifying data (transaction content?) or code.   
* **(3) Repudiation** - Claiming	to	have not performed an action.   
* **(4) Information disclosure** - Exposing information to someone not authorized to see it.  
* **(5) Denial of service** - Deny or	degrade service to users.  
* **(6) Elevation of privilege** -  Gain capabilities without proper authorization

### 2. Earlier threat model work on Bitcoin
Earlier work has been done on the [Bitcoin threat model](https://github.com/JWWeatherman/bitcoin_security_threat_model).
We have reviewed and adapted the parts that were considered relevant to Aeternity.

### 3. Previous Work on Threat Model
Earlier work has been done on a [thread model for Aeternity](https://github.com/Aeternity/protocol/blob/master/SYNC.md#threat-model).
We revised the updated information and relevant aspects and included them into the current threat model.

####========================================================

"(1.1.1)" -> Details provided in tables
"[1.1.1]" -> Details NOT provided in tables


### (1) Spoofing: Spoof user actions


	(1.1) Obtain private keys
		(1.1.1) At generation time.
			(1.1.1.1) Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
			(1.1.1.2) Flawed implementation of key generation code
					[1.1.1.2.1] Flawed Libsodium implememntation of key generation code
					[1.1.1.2.2] Flawed Erlang implementation of key generation code
		(1.1.2) At rest / in storage.
			(1.1.2.1) From local storage.
			(1.1.2.2) Third-party storage (e.g. on-line wallets).
			(1.1.2.3) Exploit cross-site scripting vulnerabilities browser-based wallets.
			(1.1.2.4) By neighbours on shared infrastructure.
			(1.1.2.5) By operator of virtualized infrastructure.
			(1.1.2.6) By malicious apps on mobile devices.
		(1.1.3) Node run time.
		(1.1.4) At logging time.
		(1.1.5) In error messages.
			(1.1.5.1) Errors caused by arbitrary corruption of files on file system.
			(1.1.5.2) Errors caused by invalid program state
			(1.1.5.3) Memory dump caused by an Erlang VM crash

	(1.2) Exploit vulnerabilities in authentication code
		(1.2.1) Exploit incomplete or otherwise flawed signature verification
			(1.2.1.1)  When validating transactions

	(1.3) Exploit vulnerabilities in network communication
		(1.3.1) Packet spoofing
			(1.3.1.1) On-path packet injection
			(1.3.1.2) Blind packet injection
		(1.3.2) Exploit DNS & BGP vulnerabilities to redirect traffic to an impersonated wallet web service;

	(1.4) Vulnerabilities in node API
		(1.4.1) Exploiting CORS to run arbitrary code on node
		(1.4.2) Exploiting the state channel API
		(1.4.3) Exploiting the HTTP API
		(1.4.4) Executing a fun though an external API

 * **Past attacks**
*  [2012 | Generic | Ron was wrong, Whit is right | iacr eprint](https://eprint.iacr.org/2012/064.pdf)
*  [2012 | Generic | Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices | Usenix Security](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final228.pdf)
*  [2016 | Generic | Weak Keys Remain Widespread in Network Devices | IMC'16](https://dl.acm.org/ft_gateway.cfm?id=2987486&type=pdf)
* [2013 | Bitcoin | Weak crypto on Android](https://arstechnica.com/information-technology/2013/08/google-confirms-critical-android-crypto-flaw-used-in-5700-bitcoin-heist/).
* [2011 | Bitcoin | Private keys stolen from wallet](https://bitcointalk.org/index.php?topic=16457.msg214423#msg214423)
* [2017 | Bitcoin | MtGox wallet.dat file stolen (e.g. through exploit, rogue employee, back-up theft)](https://blog.wizsec.jp/2017/07/breaking-open-mtgox-1.html)
* [2017 | Ethereum | Malicious wallet Providers](https://mybroadband.co.za/news/banking/214178-ethereum-wallet-provider-steals-account-keys-and-cashes-out.html)
* [2017 | Ethereum | Exploit in Parity wallet](https://thehackernews.com/2017/07/ethereum-cryptocurrency-hacking.html)
* [2017 | Ethereum | Bug in Parity wallet](https://www.theguardian.com/technology/2017/nov/08/cryptocurrency-300m-dollars-stolen-bug-ether)
* [2018 | Ethereum | Bug/misconfiguration in client node](https://thehackernews.com/2018/06/ethereum-geth-hacking.html)
* [2018 | Ethereum | Conrail wallet exploit](https://mashable.com/2018/06/11/coinrail-exchange-hack/?europe=true)
* [2014 | Bitcoin | XSS wallet vulnerability](https://www.reddit.com/r/Bitcoin/comments/1n57uj/im_attempting_to_reach_a_security_contact_at/)
* [2017 | Generic | Signature verification flaw 1](https://www.cvedetails.com/cve/CVE-2014-9934/)
* [2017 | Generic | Signature verification flaw 2](https://www.cvedetails.com/cve/CVE-2017-2898/)
* [2018 | Etheremum | BGP hijacking](https://www.theverge.com/2018/4/24/17275982/myetherwallet-hack-bgp-dns-hijacking-stolen-ethereum)

### (2) Tampering
Tampering is closely related to spoofing and information disclosure.

		(2.1) Connection tampering
			(2.1.1) No connection integrity
			(2.1.2) Weak connection integrity;
			(2.1.3) Connection security compromise;
		(2.2) Tampering with message integrity
			(2.2.1) No message integrity
			(2.2.2) Weak message integrity;
		(2.3) Tampering with the ordering of transactions included in a block
			(2.3.1) Tampering the timestamp in mined blocks
		(2.4) Tampering with block validity
			(2.4.1) No verification of block validity
			(2.4.2) Weak verification of block validity
		(2.5) Tampering with transaction validity
			(2.5.1) No verification of transaction validity
			(2.5.2) Weak verification of transaction validity
			(2.5.3) Violation of transaction integrity by a node prior to including in a block
		(2.6) Tampering with keys of epoch nodes
			(2.6.1) Replacing private keys of miner nodes
			(2.6.2) Replacing public key of miner beneficiary
		(2.7) Tampering with the persistent copy of the blockchain database (see Note 2.1)
			(2.7.1) Tampering the genesis blocks
			(2.7.2) Tampering blocks
		(2.8) Tampering with code (see Note 2.2)
			(2.8.1) Tampering with code in the epoch repository
			(2.8.2) Tampering with code in a library used by epoch
			(2.8.3) Tampering with code before compilation (e.g. via build software)
			(2.8.4) Tampering from Erlang nodes on the same platform (see Note 2.3)

* **Note 2.1: on (2.7) Database tampering**
Epoch stores a persistent copy of the blockchain on some storage. Clearly this storage is hard to get to, but if stored on some cloud machine, it may be tampered with.

* **Note 2.2: on (2.8) Code Tampering**
The epoch node software is open source and constructed using other open source components or libraries.
* **Note 2.3: on (2.8.4) Colocated Erlang nodes**
***Any*** Erlang node on the same platform can interact with the Epoch nodes

* **Related info**
	* [Unchecked block validity](https://github.com/Aeternity/protocol/blob/master/SYNC.md#incentives)

### (3) Repudiation
To be extended once the implementation of bitcoin-NG is stable.

	(3.1) Repudiating a future commitment
	(3.2) Repudiating a past transaction
		(3.2.1) Repudiating a past off-chain transaction
		(3.2.2) Repudiating a past on-chain transaction
				(3.2.2.1) Repudiating timely reception of an oracle response
				(3.2.2.2) Repudiating late submission of an oracle response

### (4) Information Disclosure

Considering that all information added to the blockchain is public, the scope of information disclosure is significantly reduced.

The working assumption is that the only data that must remain secret at all times are the private keys of nodes (see Assumptions above) and the private keys of the accounts, oracles, and contracts.
The threats to the confidentiality and integrity of the node private keys are listed in the ***Spoofing*** threat tree.

Hence, if the assumption is correct, the information disclosure threat tree is a subtree of the ***Spoofing*** threat tree

Update 2018-07-02, based on [issue#2](https://github.com/ThomasArts/aetmodel/issues/2)***The messages exchanged in a state channel should be private—as long as peers cooperate—, i.e. MitM should not be possible***, i.e. assumption  1 is false.

Threat tree for threat vector (4): Information Disclosure.

	(4.1) Disclosure of messages in a state channel.
		(4.1.1) Adversary performs a MitM attack on the state channel to breach communication confidentiality and integrity;
		(4.1.2) Forcing early arbitration to breach communication confidentiality;


### (5) Denial of service

##### 1. Overloading with transactions
Creating and posting a transaction is a computationally cheap action for an attacker. A valid transaction is a transaction that can potentially be included in a future block and that a miner receives a fee for.
Validation of a transaction is computational cheap, but having to validate many transactions that cannot be included in a block, is a computational overhead for a node. If an attacker could
post enormous amounts of transactions to the network, it could potentially impact the rate in which correct transactions are accepted.
Transactions may validate but nevertheless not be possible to include in a block. For example, an attacker could post a spend-transaction including more tokens than the from account contains. This transaction is then kept in the transaction pool for a while and *check this* validated for each new block candidate.  

	(5.1) Posting invalid transactions.
	(5.2) Posting valid, but impossible transactions
			[5.1.1] Resubmitting unusable transactions directly to a node
			[5.1.2] Gossiping unusable transactions through the p2p network (related to 5.4.2.1)
	(5.3) Exploiting memory limitations
		[5.3.1] Memory leaks in cleaning transaction pool
		[5.3.2] Overloading memory with atoms
		[5.3.3] Overloading memory with non-garbage-collected processes
	(5.4) Exploiting network or communication vulnerabilities to degrade or deny service
		(5.4.1) Launch Eclipse attacks against a node or a set of nodes
			(5.4.1.1) Eclipse by connection monopolization
			(5.4.1.2) Eclipse by owning the table
			(5.4.1.3) Eclipse by manipulating time
			(5.4.1.4) Obtain node 'secret' used to determine peer selection from unverified pool
		(5.4.2) Network-wide attacks against the Aeternity network
			(5.4.2.1) Attacks to slow down the Aeternity network
		(5.4.3) Denial of Service against Predefined Peer Nodes
			(5.4.3.1) Denial of Service using API functionality
			(5.4.3.2) Denial of Service using generic DoS methods
	(5.5) Exploiting software vulnerabilities to degrade or deny service
		(5.5.1) Improper Check for Unusual or Exceptional Condition
	(5.6) Exploiting epoch protocol vulnerabilities to degrade or deny service.
		(5.6.1) Refusing to cooperate after having opened the channel;  
		(5.6.2) Refusing to sign a multi-party transaction;
		(5.6.3) Open channels up to the full capacity of the node;
		(5.6.4) Dropping messages on a state channel;
		(5.6.5) Exploiting errors in the contract language to run contracts without gas;

 * **Past attacks**
 	* [2018 | Ethereum | Low-Resource Eclipse Attacks on Ethereum’s Peer-to-Peer Network (iacr eprint)](https://www.cs.bu.edu/~goldbe/projects/eclipseEth.pdf)
 	* [2018 | Ethereum | Unhandled exception vulnerability exists in Ethereum API](https://nvd.nist.gov/vuln/detail/CVE-2017-12119)
 	* [2017 | Bitcoin | Hijacking Bitcoin: routing attacks on cryptocurrencies | IEEE S&P](https://btc-hijack.ethz.ch/)

### (6) Elevation of privilege
The working assumption is that the user model is flat, i.e. there is no difference between the privileges of any two nodes.
Hence, if the assumption is correct, the elevation of privilege threat tree only applies to underlying environment and is orthogonal to the software developed in this project.

**Update 2018-07-02** Assumption is FALSE, since [the AEVM executes untrusted code](https://github.com/ThomasArts/aetmodel/issues/3)

**discuss** As long as the network is small, there is a concept of Aeternity owned nodes that would be more "trustable" than other nodes. In the beginning it might be important to prevent a small different subset of nodes to take the role as trusted set to connect to.  

* Indeed, this falls under the threat of ["altcoin infanticide"](https://bitcointalk.org/index.php?topic=56675.0).


	(6.1) EoP on the epoch node.
		(6.1.1)	Exploitable vulnerabilities in AEVM leading to EoP
		(6.1.2) Exploit Erlang distribution to get access to node
	(6.2) EoP in p2p network
		(6.2.1) EoP of an arbitrary node to status of trusted node
				(6.2.1.1) EoP though exploitabtion of API vulnerabilities;
				(6.2.1.2) EoP through forged Epoch node distributions;

## STRIDE Threat Trees

### 1. (Node) Spoofing

|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
| 1.1.1.1  | Using weak or flawed PRNGs may lead to generating keys that are predictable or brute-forceable  | Ensure best-practice PRNG is used | [Libsodium PRNG](https://download.libsodium.org/doc/generating_random_data/) is used | relevant for mobile devices - past attacks exist | | low priority (unlikely) |
| 1.1.1.2  | Vulnerabilities in key generation implementation can lead to generation of keys that are predictable or brute-forceable  | Verify Key generation implementation and use keys of sufficient length |  | Private keys are 256 bits: both for P2P connections as well as for signing transactions. relevant for mobile devices - past attacks exist  | TODO: verify that the user cannot accidentally use a key with less than 256 bits;  | low priority (unlikely)|
| 1.1.1.2.1  | Vulnerabilities in the crypto library implementation  | Extensive testing of the underlying crypto library | Short patching cycle |   |   | low priority (unlikely)|
| 1.1.1.2.2  | Vulnerabilities in the Epoch crypto functionality implementation | Extensive testing of the Epoch crypto functionality | Short patching cycle |   |   | medium priority |
|  1.1.2.1 | Vulnerabilities in client platform, exploited through trojans or viruses can expose private keys   |  N/A | N/A  | Out of scope (OOS) | | |
|  1.1.2.2    | Vulnerabilities in 3rd party wallets and applications can expose private keys  | N/A  |  N/A | OOS; NOTE: Risk of multiple account compromise   | | |
|1.1.2.3     | Vulnerabilities in web services may allow an adversary to execute code on nodes, potentially revealing the wallet| Security Testing  |  N/A | OOS; NOTE: Risk of multiple account compromise   | | |
|1.1.2.4  | Competing nodes running on shared infrastructure may leak keys of neighbour nodes, e.g. from configuration file | API for storing keys in a hardware enclave / on external device | (a) Erlang ports should be closed; | May be difficult to solve|  | |
|1.1.2.5  | Operators of virtualized infrastructure may obtain keys of nodes in virtual containers by reading files stored on disk | API for storing keys in a hardware enclave |  N/A |  Low bar | | |
|1.1.2.6  | Malicious mobile applications with access to file system may leak Epoch node private key | Leverage hardware-supported features  (e.g. ARM TrustZone) to protect private key |  N/A |  This might be very specific (and highly relevant) to Aeternity since it envisions that mobile devices could/will run Epoch nodes | | |
|  1.1.3 | Remote exploitation of client applications  | Penetration testing of  external interfaces of application (http, noise) | Erlang distribution daemon blocked for incoming requests |  | TODO: Define penetration testing | |
| 1.1.4  | Client implementation can inadvertently expose private keys in logs and memory dumps | a. Ensure code never logs private key; b. User private keys are not handled by node (peer key and mining key are); c. Never send client logs/memory dumps unencrypted over public network; | Ensure secure access to monitoring software (datalog) |  | TODO: check encrypted submission to datalog | priority low |
| 1.1.5  | An error message can inadvertently expose private keys directly to a user or in logs and memory dumps | a. Ensure code never raises an error with  private key as argument; b. User private keys are not handled by node (peer key and mining key are); c. Never send client logs/memory dumps unencrypted over public network; | Ensure secure access to monitoring software (datalog) |  | TODO: check error messages | priority medium |
| 1.1.5.1  |  Exposing sensitive information - such as private keys - through arbitrary corruption of files | Ensure data considered security sensitive not exposed in logs unless explicitly unusable | Ensure secure access to monitoring software (datalog) | Example: aec_keys:setup_sign_keys/2; aec_keys:setup_peer_keys/2 | | priority medium |
| 1.1.5.2  |  Exposing sensitive information - such as private keys - through logs and crash dumps | Ensure data considered security sensitive not exposed in logs unless explicitly unusable | Ensure secure access to monitoring software (datalog) |  | Example: none yet | priority medium |
| 1.1.5.3  |  Exposing sensitive information - such as private keys - through the Erlang VM crash dump | Minimize or eradicate vulnerabilities leading to Erlang VM crashes | Rapid patching of identified vulnerabilities |  | Example: none yet | priority medium |
|  1.2.1 | Code flaws in signature verification can be exploited to spoof user actions | Thoroughly and continuously test signature verification code;  | Exclude/ignore outdated clients (?)  |   | TODO: review robustness of signing | |
|  1.2.1.1 |  Code flaw in transaction validation can be exploited to spoof user actions | A binary serialization of each transactions is signed with the private key of the accounts that may get their balances reduced.  |   | Signing is performed using NaCL cryptographic signatures (implemented in LibSodium). Forging a signature is considered extremely difficult. The LibSodium library has an active user community (*has it been certified?*). LibSodium is connected via the Erlang enacl library (*version ...*), which has been reviewed for security violations.  | TODO: Check libsodium guarantees and update to latest version of enacl | |
|  1.3.1.1 |  Adversary can observe the normal packet flow and insert own packets. | Enforce transport integrity  |   |  | Prevented using the Noise protocol with specific handshake and encryption |   |
|  1.3.1.2 |  Adversary cannot observe the packet flow but inserts own arbitrary packets. | Enforce transport integrity  | Transport layer security  |  | Prevented using the Noise protocol |   |
|  1.3.2 |  DNS attack that reroutes users to a scam site collecting user's login credentials | N/A  | N/A  | OOS  | |   |
|  1.3.3.1 |  Adversary runs a web service with malicious code exploiting internal node APIs  | Enforce strict origin policy  | N/A  | Needs further investigation  | |   |
|  1.3.3.2 |  Exploiting the state channel HTTP API  | Security testing of the API  | N/A  | Needs further investigation  | |   |
|  1.3.3.2 |  Exploiting the node's HTTP APIs  | Security testing of the API  | N/A  | Needs further investigation  | |   |
|  1.3.3.4 |  Externally executing a fun over the nodes API  | Security testing of the API  | N/A  | Needs further investigation  | |  High (devastating consequences) |



### 2. Tampering
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
| 2.1.1  | Connection integrity is not implemented | Ensure channel integrity |   |   Prevented using the Noise protocol with specific handshake and encryption |  Verify correct implementation using a QuickCheck model ||  
| 2.1.2  | Weak algorithms used to ensure connection integrity | Use cryptographically strong and well tested crypto algorithms and implementations  |   | Prevented using the Noise protocol with specific handshake and encryption |   Verify correct implementation using a QuickCheck model|   |  
| 2.1.3  | Connection security compromised due to nonce wrap back |  |  | Nonce wraps back after 2^64 - 1 messages, long over channel lifetime |  |   |
|  2.2.1 | Message integrity verified  | Ensure message integrity  |   | Prevented using the Noise protocol with specific handshake and encryption | Verify correct implementation using a QuickCheck model  ||  
|  2.2.2 | Message integrity is verified, but implementation is incomplete or flawed  | Use cryptographically strong and well tested crypto algorithms and implementations   |   |   Prevented using the Noise protocol with specific handshake and encryption |  Verify correct implementation using a QuickCheck model ||  
|  2.3 | Order of transactions included  in a block is modified (due to a bug or malicious intent) | Correct node implementation |   |   |  Discuss whether this is a threat |   |
|  2.4.1 | Nodes do not verify block validity before adding it to the blockchain  | Correct implementation of block validity verification in node implementation |  Strong incentives for nodes to validate blocks |   |  Verify correct implementation using a QuickCheck model |   |
|  2.4.2 | Nodes verify block validity, but verification implementation is incomplete or flawed  | Correct implementation of block validity verification in node implementation |    |   |  Verify correct implementation using a QuickCheck model |   |
|  2.5.1 | Nodes do not verify transaction validity  | Correct implementation of transaction validity verification in node implementation |  Protocol incentives for nodes to validate blocks |   |  Verify correct implementation using a QuickCheck model |   |
|  2.5.2 | Nodes verify transaction validity, but verification implementation is incomplete or flawed  | Correct implementation of transaction validity verification in node implementation |    |   |  Verify correct implementation using a QuickCheck model |   |
|  2.5.3 | Nodes modify transaction prior to including it in a block  | | Protocol incentives preventing nodes from modifying transactions  |   |  Verify correct implementation using a QuickCheck model |   |
|  2.6.1 | Tampering with the keys of miner nodes in order to obtain rewards from mining | Prevent run-time substitution of keys | Needs further investigation |   | Review once protocol implementation stable  |   |
|  2.7.1 | Tampering the genesis block in persistent DB | A node is isolated if genesis block differs, no communication with other epochs possible  | Ensure that database runs in protected area |   |   |  no issue |
|  2.7.2 | Tampering a block in persistent DB | DB is read at startup and all blocks are validated again, tampering will be noticed in block-hash that does not fit. If new consecutive hashes have been computed, then DB is considered a fork and tampered part is removed while syncing with other nodes |  Ensure that database runs in protected area | |   | no issue  |
|  2.8.1 | Tampering with code in the Epoch repository | N/A |  (a) Use strong, 2-factor authentication for code repository (b) Security review of external pull requests | |   | low priority  |
|  2.8.2 | Tampering with code in the Epoch trusted computing base (incl. dependencies) | N/A |  (a) Bind releases to whitelisted release tags of dependency libraries   (b) Epoch security review and testing whenever release tag changes  | |   | low priority  |
|  2.8.3 | Tampering with code via build software prior to compilation |  N/A	 | Provide recommended toolchains for most common platforms | | | low priority  |
|  2.8.4 | Tampering with the Epoch node over another Erlang node running on the same platform |  N/A	 | OOS; run Epoch on a dedicated host (physical or virtual) | | | low priority  |


### 3. Repudiation
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
|  3.1 |  An Epoch node  repudiating a future commitment (e.g. as oracle) | N/A  |  N/A | Can someone "announce" a victim node X as oracle without node X's its consent? motivation: to "damage" a nodes' reputation as oracle;  Needs further investigation |   |   |
|  3.2.1 | Epoch node repudiating a past transaction that is not on the chain | N/A  | N/A  | OOS; Since a transaction on the chain is signed with private keys, only possible due to loss of private keys; safeguarding private keys is responsibility of the node  |   |   |
|  3.2.2 | Epoch node repudiating a past transaction that is on the chain | N/A |  N/A | Needs further investigation   |   |   |
|  3.2.2.1 |  Epoch node repudiating timely reception of oracle response (within originally posted TTL)  |  N/A | N/A  |  Needs further investigation |   |   |
|  3.2.2.2 | Oracle node repudiating late submission of a query response  |  N/A | adjust miner incentives  | Needs further investigation; since the oracle has no control (?) over when the transaction enters the chain, it can claim that it has posted an oracle response transaction "on time", but no miner picked it up;  |   |   |
|   |   |   |   |   |   |   |

### 4. Information Disclosure
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
| 4.1.1  |  Perform a MitM attack on the communication over a state channel  | If naming system is used - implement reliable mapping between peer names and keypairs; correct implementation of Noise protocol with specific handshake and encryption |   |   |   |   |
| 4.1.2  |  Adversary performs a selective DoS attack on the state channel to force peer to revert to arbitration and (partly) disclose state channel content | Ensure arbitration requires minimum information about the messages exchanged on the state channel  | N/A  |   |   |   |
|   |   |   |   |   |   |   |

### 5. Denial of service
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
| 5.1  | Posting invalid transactions  | The node that receives a transaction validates this transaction. Invalid transactions are rejected and never propagated to other nodes.  | Handling the http request is more work than validating the transaction. By standard http load balancing the number of posted transactions is the limiting factor, rejecting the transactions is cheap. |   | Verify that indeed all invalid transactions are rejected using a QuickCheck model  | medium |
| 5.2  | Posting valid, but unusable transactions  | Validation is light-weight and ensures that if the transaction is accepted in a block candidate fee and gas can be paid.  | Valid transactions have a configurable TTL that determines how long a transaction may stay in the memory pool. By default a node is configured to have a transaction in the pool for at most 256 blocks.  |   |   |   |
| 5.3  | Exploiting memory leaks in cleaning transaction pool  | Erlang is a garbage collected language and additional garbage collection is implemented for invalid transactions.  |   | Erlang does not garbage collect atoms. Transactions that are potentially able to create new atoms from arbitrary binaries (e.g. name claim transactions) should be reviewed | TODO: check for binary_to_atom in transaction handling. Verify memory constraints on transaction pool | low |
| 5.4.1.1  | Attacker waits until the victim reboots (or deliberately forces the victim to reboot), and then immediately initiates incoming connections to victim from each of its attacker nodes  |  Needs further investigation | Needs further investigation  |   |  Attack shown for ETH - investigate relevance see [Persistence](https://github.com/Aeternity/protocol/blob/master/GOSSIP.md#persistence) |   |
|  5.4.1.2 | Attacker probabilistically forces the victim to form all outgoing connection to the attacker, combined with unsolicited incoming connection requests  |  Needs further investigation |  Needs further investigation |   |Attack shown for ETH - investigate relevance; see [Peer Maintenance](https://github.com/Aeternity/protocol/blob/master/GOSSIP.md#peers-maintenance)| |   
|  5.4.1.3 | Eclipsing node by skewing time, e.g. by manipulating the network time protocol (NTP) used by the host |  Needs further investigation | Configure host to use secure/trusted NTP (esp. relevant for peers)  | |Attack shown for ETH - investigate relevance| |  
|  5.4.1.4 | Eclipsing node by influencing peer selection from unverified pool; assumes obtaining 'secret' used for peer selection |  Needs further investigation | Needs further investigation  | |Secret generation, storage and usage is [undocumented](https://github.com/Aeternity/protocol/blob/master/GOSSIP.md#bucket-selection) | |  
| 5.4.2.1  | Slow down the Aeternity network by tampering with the outgoing and incoming messages of a subset of nodes  | Ensure message integrity   |   |   | Attack shown for Bitcoin - investigate relevance  |   |
| 5.4.3.1  | Flood Predefined Peer Nodes with requests on the Chain WebSocket API  |  Check request signature   | Throttle requests from same origin  |   |   |   |
| 5.4.3.2  | Flood Predefined Peer Nodes with packets using DoS techniques on the TCP (SYN flood) or Epoch protocol level  |    |   |   | Investigate feasibility  |   |
|  5.5.1 |  Specially crafted JSON requests can cause an unhandled exception resulting in denial of service | Security testing of the API  |  N/A |   | Verify that indeed all invalid transactions are rejected using a QuickCheck model (?) |  High |
|  5.6.1 | Open a channel with a peer and subsequently refuse to cooperate, [locking up coins](https://github.com/Aeternity/protocol/tree/master/channels#incentives) and making the peer pay the channel closing fees. | N/A  |  Discouraged through incentives |  Needs further investigation |  |   |
|  5.6.2 | Refuse to sign a transaction when the channel holds significant funds and the account sending the transaction does not have sufficient funds to close the channel. | N/A  |  Halt interactions if on-chain fees reach the point, where the fees required to timely close a channel approach the balance of the channel; Discouraged through incentives |  Needs further investigation |  |  |
|  5.6.3 | Open multiple channels with a peer (up to the capacity of the WebSocket and subsequently refuse to cooperate, locking up coins and making the peer pay the channel closing fees. | Discouraged through incentives  |  Implement deterring incentives in protocol |  Needs further investigation |  |  High |
|  5.6.4 | Drop arbitrary packets on a state channel to disrupt or degrade communication between two peers. | N/A  |  Discouraged through incentives |  Needs further investigation |  |  High |


 * **Past attacks/Background information**
 	* [2018 | Aeternity state channel incentives](https://github.com/Aeternity/protocol/tree/master/channels#incentives)
	* [2018 | Aeternity state channel fees](https://github.com/Aeternity/protocol/tree/master/channels#fees)



### 6. Elevation of privilege
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes | Actions | Priority |
|---|---|---|---|---|---|---|
| 6.1.1  | Malicious code embedded in the contracts can be run to exploit vulnerabilities in AEVM and lead to elevation of privilege on the epoch node or disclosure of information | Correct implementation and security testing of the AEVM | Sanity checks for code in smart contracts?  |   |   |   |
| 6.1.2 | Erlang daemon accepts incoming connection from other Erlang node (default cookie is epoch_cookie) | Node is started with -sname which disallows access from different IP address | Erlang daemon only listens to localhost  |   |   | low |
| 6.2.1.1  |  Exploit Epoch node API vulnerability to obtain status of trusted node |  Security testing of Epoch node APIs | N/A  |   |   |   |
| 6.2.1.2  | Create custom distribution of Epoch node code with a modified set of trusted nodes	 | N/A  | Encourage use of "genuine" epoch nodes |  Discuss potential as "existential" risk to the network |   |   | |


## Notes

 * **Questions, concerns**

	* Privilege levels for the code - what is the correct model?

	* Password for keypair protection stored in CONFIG file OR as an environment variable is NOT a good practice (example in aec_keys:start_worker/0; config in epoch_config_schema.json)

	* In epoch_config_schema.json: ***such defaults provide a false sense of security and should not be used.***
	* In epoch_config_schema.json: "used to encrypt the peer key-pair files" - it does not make sense to encrypt the public key file (investigate if that is actually done).

	"peer_password" : {
			"description" :
			"Password used to encrypt the peer key-pair files - if left blank `password` will be used",
			"type" : "string"
		}

* **[Undiscussed]** In aec_peers, '-type peer\_id(): What is the consideration behind using the public key (and not e.g. a hash of it) as peer id?

* **[Undiscussed]** In epoch_config_schema.json: ***description contradicts defaults***
	  "extra_args" : { "description" : "Extra arguments to pass to the miner executable binary. The safest choice is specifying no arguments i.e. empty string.",
		                                    "type" : "string",
		                                    "default": "-t 5"
		                                },

* **[Undiscussed]** In epoch_config_schema.json: ***consider placing such controls in a separate file - otherwise there is a high risk of deliberately misleading users to make damaging changes, this can damage availability.***
		"node_bits" : {
		"description" : "Number of bits used for representing a node in the Cuckoo Cycle problem. It affects both PoW generation (mining) and verification. WARNING: Changing this makes the node incompatible with the chain of other nodes in the network, do not change from the default unless you know what you are doing.",
		                                    "type": "integer",
		                                    "default": 28

## Conclusions

### Threats to be mitigated

### Threats to be eliminated

### Threats to be transferred

### Accepted risks

## References

[1] P. Torr, "Demystifying the Threat-Modeling Process," in IEEE Security & Privacy, vol. 3, no. , pp. 66-70, 2005.
[doi](10.1109/MSP.2005.119), [url](doi.ieeecomputersociety.org/10.1109/MSP.2005.119)

[2] A. Shostack "Threat Modeling: Designing for Security", ISBN: 978-1-118-80999-0, Feb 2014
