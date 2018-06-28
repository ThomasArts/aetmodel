# aetmodel
Documentation of threat model

## List of acronyms
**OOS** Out of scope  
**NTP** Network Time Protocol

## Definitions

**Client Node** is an aetherium node with no mining capability.

**Penetration testing** (aka ***pentesting***) authorized simulated attack on a computer system, performed to evaluate the security of the target system. 
The test aims to identify the target's strengths and vulnerabilities, including the potential for unauthorized parties to gain access to the system's software and data.

**Miner Node** is an aetherium node with mining capability.

**Node** (aka ***Epoch node***, ***Peer node***) umbrella term for aeternity protocol participant; includes miner nodes, client nodes, peers, etc.
Identified by a URI consisting of the protocol 'aenode://', the public key, an '@' character, the hostname or IP number, a ':' character and the Noise port number.   
**Predefined Peer Node** This is a set of peers that are automatically connected to upon node startup.

**Spoofing** is an attack in which a person or program successfully masquerades as another by falsifying data, to gain an illegitimate advantage.

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

## Previous Work on Threat Model

Some work on building the thread model for aeternity [has already been done](https://github.com/aeternity/protocol/blob/master/SYNC.md#threat-model).

## Assets
**Assets** describe are the valuable data that the business cares about

## Assumptions

**Assumptions** about the system model and about the way users will interact with the system

## Threat Model

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
		(1.2.4) By neighbours on shared infrastructure.
		(1.2.5) By operator of virtualized infrastructure.
		(1.2.6) By malicious apps on mobile devices.
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
    (3.1) Packet spoofing
    	(3.1.1) On-path packet injection
    	(3.1.2) Blind packet injection    
	 (3.2) Exploit DNS & BGP vulnerabilities to redirect traffic to an impersonated wallet web service;
 * **Past attacks**
 	* [2018 | Etheremum | BGP hijacking](https://www.theverge.com/2018/4/24/17275982/myetherwallet-hack-bgp-dns-hijacking-stolen-ethereum)


####(2) Tampering
Tampering is closely related to spoofing and information disclosure.
##### 1. Channel tampering
    (2.1.1) No channel integrity
	 (2.1.2) Weak channel integrity;
	 (2.1.3) Channel security compromise;
	 
##### 2. Message tampering
	(2.2) Verification of message integrity
    (2.2.1) No message integrity
	 (2.2.1) Weak message integrity;
	 
##### 3. Time and ordering
    (2.3) Tampering with the ordering of transactions included in a block
     

##### 4. Block tampering
	  (2.4) Verification of block validity
		  (2.4.1) No verification of block validity
		  (2.4.2) Weak verification of block validity

##### 5. Transaction tampering
	  (2.5) Verification of transaction validity
	  	  (2.5.1) No verification of transaction validity
		  (2.5.2) Weak verification of transaction validity
		  (2.5.3) Violation of transaction integrity by a node prior to including in a block

* **Related info**
	* [Unchecked block validity](https://github.com/aeternity/protocol/blob/master/SYNC.md#incentives)



####(5) Denial of service

##### 1. Overloading with transactions
Creating and posting a transaction is a computationally cheap action for an attacker. A valid transaction is a transaction that can potentially be included in a future block and that a miner receives a fee for.
Validation of a transaction is computational cheap, but having to validate many transactions that cannot be included in a block, is a computational overhead for a node. If an attacker could
post enormous amounts of transactions to the network, it could potentially impact the rate in which correct transactions are accepted.
Transactions may validate but nevertheless not be possible to include in a block. For example, an attacker could post a spend-transaction including more tokens than the from account contains. This transaction is then kept in the transaction pool for a while and *check this*  validated for each new block candidate.  

	(5.1) Posting invalid transactions.
	(5.2) Posting valid, but impossible transactions
	(5.3) Exploiting memory leaks in cleaning transaction pool
	(5.4) Exploiting network or communication vulnerabilities to degrade or deny service
		(5.4.1) Launch Eclipse attacks against a node or a set of nodes
			(5.4.1.1) Eclipse by connection monopolization
			(5.4.1.2) Eclipse by owning the table
			(5.4.1.3) Eclipse by manipulating time
			(5.4.1.4) Obtain node 'secret' used to determine peer selection from unverified pool
		(5.4.2) Network-wide attacks against the aetherium network
			(5.4.2.1) Attacks to slow down the aetherium network
		(5.4.3) Denial of Service against Predefined Peer Nodes
	(5.5) Exploiting software vulnerabilities to degrade or deny service
		(5.5.1) Improper Check for Unusual or Exceptional Condition
 * **Past attacks**
 	* [2018 | Ethereum | Low-Resource Eclipse Attacks on Ethereum’s Peer-to-Peer Network (iacr eprint)](https://www.cs.bu.edu/~goldbe/projects/eclipseEth.pdf)
 	* [2018 | Ethereum | Unhandled exception vulnerability exists in Ethereum API](https://nvd.nist.gov/vuln/detail/CVE-2017-12119)
 	* [2017 | Bitcoin | Hijacking Bitcoin: routing attacks on cryptocurrencies | IEEE S&P](https://btc-hijack.ethz.ch/)
 	
 	
## STRIDE Threat Trees

### 1. (Node) Spoofing

|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priotity |
|---|---|---|---|---|---|---|
| 1.1  | Vulnerabilities in key generation implementation can lead to generation of keys that are predictable or brute-forceable  | Verify Key generation implementation and use keys of sufficient length |  | Private keys are 256 bits: both for P2P connections as well as for signing transactions.  | TODO: verify that the user cannot accidentally use a key with less than 256 bits | low priority (unlikely) |
|  1.2.1 | Vulnerabilities in client platform, exploited through trojans or viruses can expose private keys   |  N/A | N/A  | Out of scope (OOS) | | |
|  1.2.2    | Vulnerabilities in 3rd party wallets and applications can expose private keys  | N/A  |  N/A | OOS; NOTE: Risk of multiple account compromise   | | |
|1.2.3     | Vulnerabilities in web services may allow an adversary to run and execute mailicious scripts on client nodes, potentially revealing the wallet| Security Testing  |  N/A | OOS; NOTE: Risk of multiple account compromise   | | |
|1.2.4  | Competing nodes running on shared infrastructure may leak keys of neighbour nodes | API for storing keys in a hardware enclave / on external device |  N/A | | May be difficult to solve | |
|1.2.5  | Operators of virtualized infrastructure may obtain keys of nodes in virtual containers | API for storing keys in a hardware enclave |  N/A | | Difficult to solve | |
|1.2.6  | Malicious mobile applications with access to file sysstem may leak Epoch node private key | Leverage hardware-supported features  (e.g. ARM TrustZone) to protect private key |  N/A | | This migh be very specific (and highly relevant) to Aetherium since it envisions that mobile devices could/will run full nodes | |
|  1.3 | Remote exploitation of client applications  | Penetration testing of  external interfaces of application (http, noise) | Erlang distribution daemon blocked for incoming requests |  | TODO: Define penetration testing | |
| 1.4  | Client implementation can inadvertently expose private keys in logs and memory dumps | a. Ensure code never logs private key; b. User private keys are not handled by node (peer key and mining key are); c. Never send client logs/memory dumps unencrypted over public network; | Ensure secure access to monitoring software (datadog) |  | TODO: check encrypted submission to datadog | priority low |
|  2.1 | Code flaws in signature verification can be exploited to spoof user actions | Thoroughly and continuously test signature verification code;  | Exclude/ignore outdated clients (?)  |   | TODO: review robustness of signing | |
|  2.1.1 |  Code flaw in transaction validation can be exploited to spoof user actions | A binary serialization of each transactions is signed with the private key of the accounts that may get their balances reduced.  |   | Signing is performed using NaCL cryptographic signatures (implemented in LibSodium). Forging a signature is considered extremely difficult. The LibSodium library has an active user community (*has it been certified?*). LibSodium is connected via the Erlang enacl library (*version ...*), which has been reviewed for security violations.  | TODO: Check libsodium guarantees and update to latest version of enacl | |
|  3.1.1 |  Adversary can observe the normal packet flow and insert own packets. | Enforce transport integrity  |   |  | Prevented using the Noise protocol |   |
|  3.1.2 |  Adversary cannot observe the packet flow but inserts own arbitrary packets. | Enforce transport integrity  | Transport layer security  |  | Prevented using the Noise protocol |   |
|  3.2 |  DNS attack that rerouts users to a scam site collecting user's login credentials | N/A  | N/A  | OOS  | |   |


### 2. Tampering
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
| 2.1.1  | Channel integrity is not implemented | Ensure channel integrity |   |   Prevented through use of Noise protocol |  Verify correct implementation using a QuickCheck model ||  
| 2.1.2  | Weak algorithms used to ensure channel integrity | Use cryptographically strong and well tested crypto algorithms and implementations  |   |Prevented through correct implementation of the Noise protocol |   Verify correct implementation using a QuickCheck model|   |  
| 2.1.3  | Channel security compromised due to nonce wrap back | Ensure parties do not send more than 2^64 - 1 messages with the same session key  |  | |  Verify through code review (?) |   |  
|  2.2.1 | Message integrity verified  | Ensure message integrity  |   |   Prevented through correct implementation of the Noise protocol | Verify correct implementation using a QuickCheck model  ||  
|  2.2.2 | Message integrity is verified, but implementation is incomplete or flawed  | Use cryptographically strong and well tested crypto algorithms and implementations   |   |   Prevented through correct implementation of the Noise protocol |  Verify correct implementation using a QuickCheck model ||  
|  2.2.3 | Message integrity is not verified  | Correct implementation of authenticated encryption |   |   |  Verify correct implementation using a QuickCheck model |   |
|  2.3 | Order of transactions included  in a block is modified (due to a bug or malicious intent) | Correct node implmenetation | Protocol incentived to prevent transaction reordering  |   |  Discuss whether this is a threat |   |
|  2.4.1 | Nodes do not verify block validity before adding it to the blockchain  | Correct implementation of block validity verification in node implementation |  Strong incentives for nodes to validate blocks |   |  Verify correct implementation using a QuickCheck model |   |
|  2.4.2 | Nodes verify block validity, but verification implementation is incomplete or flawed  | Correct implementation of block validity verification in node implementation |    |   |  Verify correct implementation using a QuickCheck model |   |
|  2.5.1 | Nodes do not verify transaction validity  | Correct implementation of transaction validity verification in node implementation |  Protocol incentives for nodes to validate blocks |   |  Verify correct implementation using a QuickCheck model |   |
|  2.5.2 | Nodes verify transaction validity, but verification implementation is incomplete or flawed  | Correct implementation of transaction validity verification in node implementation |    |   |  Verify correct implementation using a QuickCheck model |   |
|  2.5.3 | Nodes modify transaction prior to including it in a block  | | Protocol incentives preventing nodes from modifying transactions  |   |  Verify correct implementation using a QuickCheck model |   |


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
| 5.1  | Posting invalid transactions  | The node that receives a transaction validates this transaction. Invalid transactions are rejected and never propagated to other nodes.  | Handling the http request is more work than validating the transaction. By standard http load balancing the number of posted transactions is the limiting factor, rejecting the transactions is cheap. |   | Verify that indeed all invalid transactions are rejected using a QuickCheck model  | medium |
| 5.2  | Posting valid, but impossible transactions  | Validation is light-weight and ensures that if the transaction is accepted in a block candidate fee and gas can be paid.  | Valid transactions have a configurable TTL that determines how long a transaction may stay in the memory pool. By default a node is configured to have a transaction in the pool for at most 256 blocks.  |   |   |   |
| 5.3  | Exploiting memory leaks in cleaning transaction pool  | Erlang is a garbage collected language and additional garbage collection is implemented for invalid transactions.  |   | Erlang does not garbage collect atoms. Transactions that are potentially able to create new atoms from arbitrary binaries (e.g. name claim transactions) should be reviewed | TODO: check for binary_to_atom in transaction handling. | low |
| 5.4.1.1  | Attacker waits until the victim reboots (or deliberately forces the victim to reboot), and then immediately initiates incoming connections to victim from each of its attacker nodes  |  Needs further investigation | Needs further investigation  |   |  Attack shown for ETH - investigate relevance see [Persistence](https://github.com/aeternity/protocol/blob/master/GOSSIP.md#persistence) |   |
|  5.4.1.2 | Attacker probabilistically forces the victim to form all outgoing connection to the attacker, combined with unsolicited incomming connection requests  |  Needs further investigation |  Needs further investigation |   |Attack shown for ETH - investigate relevance; see [Peer Maintenance](https://github.com/aeternity/protocol/blob/master/GOSSIP.md#peers-maintenance)| |   
|  5.4.1.3 | Eclipsing node by skewing time, e.g. by manipulating the network time protocol (NTP) used by the host |  Needs further investigation | Configure host to use secure/trusted NTP (esp. relevant for peers)  | |Attack shown for ETH - investigate relevance| |  
|  5.4.1.4 | Eclipsing node by influencing peer selection from unverified pool; assumes obtaining 'secret' used for peer selection |  Needs further investigation | Needs further investigation  | |Secret generation, storage and usage is [undocumented](https://github.com/aeternity/protocol/blob/master/GOSSIP.md#bucket-selection) | |  
| 5.4.2.1  | Slow down the aetherium network by tampering with the outgoing and incoming messages of a subset of nodes  | Ensure message integrity   |   |   | Attack shown for Bitcoin - investigate relevance  |   |
| 5.4.3  | Flood Predefined Peer Nodes with packets using DoS techniques on the TCP (SYN flood) or Epoch protocol level  |    |   |   | Investigate feasibility  |   |
|  5.5.1 |  Specially crafted JSON requests can cause an unhandled exception resulting in denial of service | Security testing of the API  |  N/A |   | Verify that indeed all invalid transactions are rejected using a QuickCheck model (?) |  High |


### 6. Elevation of privilege
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes | Actions | Priority |
|---|---|---|---|---|---|---|
|   |   |   |   |   |   |   |
|   |   |   |   |   |   |   |
|   |   |   |   |   |   |   |

## Conclusions

### Threats to be mitigated

### Threats to be eliminated

### Threats to be transferred

### Accepted risks
