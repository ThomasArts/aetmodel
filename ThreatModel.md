# aetmodel
Documentation of threat model

## List of acronyms
**EoP** Elevation of Privilege  
**OOS** Out Of Scope  
**PRNG** Pseudo-Random Number Generator   
**MitM** Man-in-the-Middle (attack) 
**NTP** Network Time Protocol   
**XSS** Cross-Site Scripting (exploit)
## Definitions

**State Channel** [is an off-chain method for two peers to exchange state updates](https://github.com/aeternity/protocol/tree/master/channels#terms), each node can have multiple state channels and a pair of nodes can also have multiple channels between each other, which should be multiplexed over one connection. Epoch nodes come with a state channel web-service API as a reference implementation.
**Client Node** is an Aeternity node with no mining capability.



**Miner Node** is an Aeternity node with mining capability.

**Node** (aka **Epoch node***) umbrella term for Aeternity protocol participant; includes miner nodes, client nodes, peers, etc.
Identified by a URI consisting of the protocol 'aenode://', the public key, an '@' character, the hostname or IP number, a ':' character and the Noise port number.  

**Connection** is a communication channel between two nodes peers. There is only one connection between each two peers.

**Peer Node** [is a node participating in a channel](https://github.com/aeternity/protocol/tree/master/channels#terms).  
**Penetration testing** (aka ***pentesting***) authorized simulated attack on a computer system, performed to evaluate the security of the target system.
The test aims to identify the target's strengths and vulnerabilities, including the potential for unauthorized parties to gain access to the system's software and data.  
**Predefined Peer Node** This is a peer that is automatically connected to upon node startup.

**Spoofing** is an attack in which a person or program successfully masquerades as another by falsifying data, to gain an illegitimate advantage.

## System Model

The **system model** describes the high level view of the system and the context in which it is used.
It abstracts the details and allows to define the trust boundaries and state changes relevant to security.

General blockchain, allowing whatever actions on the blockchain.

Different from BitCoin in that it has many more options and that it introduces oracles, name registration, contracts and state-channels.
Many more transactions possible than in BitCoin, faster in 3 ways:  
	* Faster block rate
  * Bitcoin-NG technology with key-blocks and micro-blocks
	* Off-chain state channels (micro-payments per second)


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

bitcoin-NG - selecting a leader who can mine the blockchain, until the next leader is elected.

## Previous Work on Threat Model

Some work on building the thread model for Aeternity [has already been done](https://github.com/aeternity/protocol/blob/master/SYNC.md#threat-model).

## Assets
**Assets** describe are the valuable data that the business cares about

## Assumptions

**Assumptions** about the system model and about the way users will interact with the system.

1. **The user model is completely flat**, there is only one type of users in the system, all users have equal privileges.
	* To be discussed

### FALSE Assumptions
1. **A node's private key** is the only data that must remain secret at all times   

	* 	FALSE, based on [issue #2](https://github.com/ThomasArts/aetmodel/issues/2): The messages exchanged in a state channel should be private—as long as peers cooperate—, i.e. MitM should not be possible. 

	
2. **All code runs in the same privilege ring**, i.e. all code on the epoch nodes has the same privilege level.
	
	* FALSE, based on [issue #3](https://github.com/ThomasArts/aetmodel/issues/3): the AEVM executes untrusted code and EoP should not be possible. 


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

"(1.1.1)" -> Details provided in tables
"[1.1.1]" -> Details NOT provided in tables


### (1) Spoofing: Spoof user actions

##### 1. Obtain private keys
	(1.1) At generation time.
		(1.1.1) Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
		(1.1.2) Flawed implementation of key generation code
	 (1.2) At rest / in storage.
		(1.2.1) Local storage.
		(1.2.2) Third-party storage (e.g. on-line wallets).  
		(1.2.3) Exploit cross-site scripting vulnerabilities browser-based wallets.
		(1.2.4) By neighbours on shared infrastructure.
		(1.2.5) By operator of virtualized infrastructure.
		(1.2.6) By malicious apps on mobile devices.
	(1.3) Node run time.
	(1.4) At logging time.
	(1.5) In error messages.


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
  
		(3.3) Exploit vulnberabilities in communication security protocols
			(3.3.1) 	
 	

### (2) Tampering
Tampering is closely related to spoofing and information disclosure.
##### 1. Connection tampering
	(2.1.1) No connection integrity
		(2.1.2) Weak connection integrity;
		(2.1.3) Connection security compromise;

##### 2. Message tampering
	(2.2) Verification of message integrity
		(2.2.1) No message integrity
		(2.2.2) Weak message integrity;

##### 3. Time and ordering
	(2.3) Tampering with the ordering of transactions included in a block
		(2.3.1) Tampering the timestamp in mined blocks

##### 4. Block tampering
	(2.4) Verification of block validity
		(2.4.1) No verification of block validity
		(2.4.2) Weak verification of block validity

##### 5. Transaction tampering
	(2.5) Verification of transaction validity
		(2.5.1) No verification of transaction validity
		(2.5.2) Weak verification of transaction validity
		(2.5.3) Violation of transaction integrity by a node prior to including in a block

##### 6. Key tampering
	(2.6) Tampering with keys of epoch nodes
		(2.6.1) Replacing private keys of miner nodes
	
	
	
* **Related info**
	* [Unchecked block validity](https://github.com/aeternity/protocol/blob/master/SYNC.md#incentives)

### (3) Repudiation
To be further addressed once a better understanding of the bitcoin-NG and epoch protocols is reached.




### (4) Information Disclosure


Considering that all information added to the blockchain is public, the scope of information disclosure is significantly reduced.

The working assumption is that the only data that must remain secret at all times are the private keys of nodes (see Assumptions above) and the private keys of the accounts, oracles, and contracts.
The threats to the confidentiality and integrity of the node private keys are listed in the ***Spoofing*** threat tree.

Hence, if the assumption is correct, the information disclosure threat tree is a subtree of the ***Spoofing*** threat tree

Update 2018-07-02, based on [issue #2](https://github.com/ThomasArts/aetmodel/issues/2)***The messages exchanged in a state channel should be private—as long as peers cooperate—, i.e. MitM should not be possible***, i.e. assumption  1 is false.

NoTE: double check threat by leaking key information by tampering key and then catching error messages in crash log like this one:

```erlang
sign(Tx, PrivKeys) when is_list(PrivKeys) ->
    Bin = aetx:serialize_to_binary(Tx),
    case lists:filter(fun(PrivKey) -> not (?VALID_PRIVK(PrivKey)) end, PrivKeys) of
        [_|_]=BrokenKeys -> erlang:error({invalid_priv_key, BrokenKeys});
        [] -> pass
    end,
    Signatures = sign_bin(Bin, PrivKeys),
    #signed_tx{tx = Tx, signatures = Signatures}.
```
If somehow we provide 2 private keys with one valid and one broken, the valid key will appear in the log.


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
	(5.3) Exploiting memory leaks in cleaning transaction pool
	(5.4) Exploiting network or communication vulnerabilities to degrade or deny service
		(5.4.1) Launch Eclipse attacks against a node or a set of nodes
			(5.4.1.1) Eclipse by connection monopolization
			(5.4.1.2) Eclipse by owning the table
			(5.4.1.3) Eclipse by manipulating time
			(5.4.1.4) Obtain node 'secret' used to determine peer selection from unverified pool
		(5.4.2) Network-wide attacks against the Aeternity network
			(5.4.2.1) Attacks to slow down the Aeternity network
		(5.4.3) Denial of Service against Predefined Peer Nodes
			(5.4.3.1) Denial of Service API functionality
			(5.4.3.2) Denial of Service using generic DoS methods
	(5.5) Exploiting software vulnerabilities to degrade or deny service
		(5.5.1) Improper Check for Unusual or Exceptional Condition
	(5.6) Exploiting epoch protocol vulnerabilities to degrade or deny service.
		(5.6.1) Refusing to cooperate after having opened the channel;  
		(5.6.2) Refusing to sign a multi-party transaction;
		(5.6.3) Open channels up to the full capacity of the node;
		(5.6.4) Dropping messages on a state channel;



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


## STRIDE Threat Trees

### 1. (Node) Spoofing

|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priotity |
|---|---|---|---|---|---|---|
| 1.1.1  | Using weak or flawed PRNGs may lead to generating keys that are predictable or brute-forceable  | Ensure best-practice PRNG is used |  | relevant for mobile devices - past attacks exist | | low priority (unlikely) |
| 1.1.2  | Vulnerabilities in key generation implementation can lead to generation of keys that are predictable or brute-forceable  | Verify Key generation implementation and use keys of sufficient length |  | Private keys are 256 bits: both for P2P connections as well as for signing transactions. relevant for mobile devices - past attacks exist  | TODO: verify that the user cannot accidentally use a key with less than 256 bits;  | low priority (unlikely)|
|  1.2.1 | Vulnerabilities in client platform, exploited through trojans or viruses can expose private keys   |  N/A | N/A  | Out of scope (OOS) | | |
|  1.2.2    | Vulnerabilities in 3rd party wallets and applications can expose private keys  | N/A  |  N/A | OOS; NOTE: Risk of multiple account compromise   | | |
|1.2.3     | Vulnerabilities in web services may allow an adversary to execute code on nodes, potentially revealing the wallet| Security Testing  |  N/A | OOS; NOTE: Risk of multiple account compromise   | | |
|1.2.4  | Competing nodes running on shared infrastructure may leak keys of neighbour nodes | API for storing keys in a hardware enclave / on external device |  N/A | May be difficult to solve|  | |
|1.2.5  | Operators of virtualized infrastructure may obtain keys of nodes in virtual containers | API for storing keys in a hardware enclave |  N/A |  Difficult to solve | | |
|1.2.6  | Malicious mobile applications with access to file system may leak Epoch node private key | Leverage hardware-supported features  (e.g. ARM TrustZone) to protect private key |  N/A |  This might be very specific (and highly relevant) to Aeternity since it envisions that mobile devices could/will run Epoch nodes | | |
|  1.3 | Remote exploitation of client applications  | Penetration testing of  external interfaces of application (http, noise) | Erlang distribution daemon blocked for incoming requests |  | TODO: Define penetration testing | |
| 1.4  | Client implementation can inadvertently expose private keys in logs and memory dumps | a. Ensure code never logs private key; b. User private keys are not handled by node (peer key and mining key are); c. Never send client logs/memory dumps unencrypted over public network; | Ensure secure access to monitoring software (datadog) |  | TODO: check encrypted submission to datadog | priority low |
| 1.5  | An error message can inadvertently expose private keys directly to a user or in logs and memory dumps | a. Ensure code never raises an error with  private key as argument; b. User private keys are not handled by node (peer key and mining key are); c. Never send client logs/memory dumps unencrypted over public network; | Ensure secure access to monitoring software (datadog) |  | TODO: check error messages | priority medium |
|  2.1 | Code flaws in signature verification can be exploited to spoof user actions | Thoroughly and continuously test signature verification code;  | Exclude/ignore outdated clients (?)  |   | TODO: review robustness of signing | |
|  2.1.1 |  Code flaw in transaction validation can be exploited to spoof user actions | A binary serialization of each transactions is signed with the private key of the accounts that may get their balances reduced.  |   | Signing is performed using NaCL cryptographic signatures (implemented in LibSodium). Forging a signature is considered extremely difficult. The LibSodium library has an active user community (*has it been certified?*). LibSodium is connected via the Erlang enacl library (*version ...*), which has been reviewed for security violations.  | TODO: Check libsodium guarantees and update to latest version of enacl | |
|  3.1.1 |  Adversary can observe the normal packet flow and insert own packets. | Enforce transport integrity  |   |  | Prevented using the Noise protocol |   |
|  3.1.2 |  Adversary cannot observe the packet flow but inserts own arbitrary packets. | Enforce transport integrity  | Transport layer security  |  | Prevented using the Noise protocol |   |
|  3.2 |  DNS attack that reroutes users to a scam site collecting user's login credentials | N/A  | N/A  | OOS  | |   |


### 2. Tampering
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
| 2.1.1  | Connection integrity is not implemented | Ensure channel integrity |   |   Prevented through use of Noise protocol |  Verify correct implementation using a QuickCheck model ||  
| 2.1.2  | Weak algorithms used to ensure connection integrity | Use cryptographically strong and well tested crypto algorithms and implementations  |   |Prevented through correct implementation of the Noise protocol |   Verify correct implementation using a QuickCheck model|   |  
| 2.1.3  | Connection security compromised due to nonce wrap back | Ensure parties do not send more than 2^64 - 1 messages with the same session key  |  | Consider that a connection can be [multiplexed](https://github.com/aeternity/protocol/tree/master/channels#high-level-overview) into long-lived channels |  Verify through code review (?) |   |  
|  2.2.1 | Message integrity verified  | Ensure message integrity  |   |   Prevented through correct implementation of the Noise protocol | Verify correct implementation using a QuickCheck model  ||  
|  2.2.2 | Message integrity is verified, but implementation is incomplete or flawed  | Use cryptographically strong and well tested crypto algorithms and implementations   |   |   Prevented through correct implementation of the Noise protocol |  Verify correct implementation using a QuickCheck model ||  
|  2.2.3 | Message integrity is not verified  | Correct implementation of authenticated encryption |   |   |  Verify correct implementation using a QuickCheck model |   |
|  2.3 | Order of transactions included  in a block is modified (due to a bug or malicious intent) | Correct node implementation | Protocol uses incentive to prevent transaction reordering  |   |  Discuss whether this is a threat |   |
|  2.4.1 | Nodes do not verify block validity before adding it to the blockchain  | Correct implementation of block validity verification in node implementation |  Strong incentives for nodes to validate blocks |   |  Verify correct implementation using a QuickCheck model |   |
|  2.4.2 | Nodes verify block validity, but verification implementation is incomplete or flawed  | Correct implementation of block validity verification in node implementation |    |   |  Verify correct implementation using a QuickCheck model |   |
|  2.5.1 | Nodes do not verify transaction validity  | Correct implementation of transaction validity verification in node implementation |  Protocol incentives for nodes to validate blocks |   |  Verify correct implementation using a QuickCheck model |   |
|  2.5.2 | Nodes verify transaction validity, but verification implementation is incomplete or flawed  | Correct implementation of transaction validity verification in node implementation |    |   |  Verify correct implementation using a QuickCheck model |   |
|  2.5.3 | Nodes modify transaction prior to including it in a block  | | Protocol incentives preventing nodes from modifying transactions  |   |  Verify correct implementation using a QuickCheck model |   |
|  2.6.1 | Tampering with the keys of miner nodes in order to obtain rewards from mining | Prevent run-time substitution of keys | N/A |   |   |   |

### 3. Repudiation
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
|   |   |   |   |   |   |   |
|   |   |   |   |   |   |   |
|   |   |   |   |   |   |   |


### 4. Information Disclosure
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
| 4.1.1  |  Perform a MitM attack on the communication over a state channel  | If naming system is used - implement reliable mapping between peer names and keypairs; correct implementation of the Noise protocol |   |   |   |   |
| 4.1.2  |  Adversary performs a selective DoS attack on the state channel to force peer to revert to arbitration and (partly) disclose state channel content | Ensure arbitration requires minimum information about the messages exchanged on the state channel  | N/A  |   |   |   |
|   |   |   |   |   |   |   |

### 5. Denial of service
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes   | Actions | Priority |
|---|---|---|---|---|---|---|
| 5.1  | Posting invalid transactions  | The node that receives a transaction validates this transaction. Invalid transactions are rejected and never propagated to other nodes.  | Handling the http request is more work than validating the transaction. By standard http load balancing the number of posted transactions is the limiting factor, rejecting the transactions is cheap. |   | Verify that indeed all invalid transactions are rejected using a QuickCheck model  | medium |
| 5.2  | Posting valid, but impossible transactions  | Validation is light-weight and ensures that if the transaction is accepted in a block candidate fee and gas can be paid.  | Valid transactions have a configurable TTL that determines how long a transaction may stay in the memory pool. By default a node is configured to have a transaction in the pool for at most 256 blocks.  |   |   |   |
| 5.3  | Exploiting memory leaks in cleaning transaction pool  | Erlang is a garbage collected language and additional garbage collection is implemented for invalid transactions.  |   | Erlang does not garbage collect atoms. Transactions that are potentially able to create new atoms from arbitrary binaries (e.g. name claim transactions) should be reviewed | TODO: check for binary_to_atom in transaction handling. Verify memory constraints on transaction pool | low |
| 5.4.1.1  | Attacker waits until the victim reboots (or deliberately forces the victim to reboot), and then immediately initiates incoming connections to victim from each of its attacker nodes  |  Needs further investigation | Needs further investigation  |   |  Attack shown for ETH - investigate relevance see [Persistence](https://github.com/aeternity/protocol/blob/master/GOSSIP.md#persistence) |   |
|  5.4.1.2 | Attacker probabilistically forces the victim to form all outgoing connection to the attacker, combined with unsolicited incoming connection requests  |  Needs further investigation |  Needs further investigation |   |Attack shown for ETH - investigate relevance; see [Peer Maintenance](https://github.com/aeternity/protocol/blob/master/GOSSIP.md#peers-maintenance)| |   
|  5.4.1.3 | Eclipsing node by skewing time, e.g. by manipulating the network time protocol (NTP) used by the host |  Needs further investigation | Configure host to use secure/trusted NTP (esp. relevant for peers)  | |Attack shown for ETH - investigate relevance| |  
|  5.4.1.4 | Eclipsing node by influencing peer selection from unverified pool; assumes obtaining 'secret' used for peer selection |  Needs further investigation | Needs further investigation  | |Secret generation, storage and usage is [undocumented](https://github.com/aeternity/protocol/blob/master/GOSSIP.md#bucket-selection) | |  
| 5.4.2.1  | Slow down the Aeternity network by tampering with the outgoing and incoming messages of a subset of nodes  | Ensure message integrity   |   |   | Attack shown for Bitcoin - investigate relevance  |   |
| 5.4.3.1  | Flood Predefined Peer Nodes with requests on the Chain WebSocket API  |  Check request signature   | Throttle requests from same origin  |   |   |   |
| 5.4.3.2  | Flood Predefined Peer Nodes with packets using DoS techniques on the TCP (SYN flood) or Epoch protocol level  |    |   |   | Investigate feasibility  |   |
|  5.5.1 |  Specially crafted JSON requests can cause an unhandled exception resulting in denial of service | Security testing of the API  |  N/A |   | Verify that indeed all invalid transactions are rejected using a QuickCheck model (?) |  High |
|  5.6.1 | Open a channel with a peer and subsequently refuse to cooperate, [locking up coins](https://github.com/aeternity/protocol/tree/master/channels#incentives) and making the peer pay the channel closing fees. | N/A  |  Implement deterring incentives in protocol |  Needs further investigation |  |   |
|  5.6.2 | Refuse to sign a transaction when the channel holds significant funds and the account sending the transaction does not have sufficient funds to close the channel. | N/A  |  Halt interactions if on-chain fees reach the point, where the fees required to timely close a channel approach the balance of the channel. |  Needs further investigation |  |  |
|  5.6.3 | Open multiple channels with a peer (up to the capacity of the WebSocket and subsequently refuse to cooperate, locking up coins and making the peer pay the channel closing fees. | N/A  |  Implement deterring incentives in protocol |  Needs further investigation |  |  High |
|  5.6.4 | Drop arbitrary packets on a state channel to disrupt or degrade communication between two peers. | N/A  |  N/A |  Needs further investigation |  |  High |


 * **Past attacks/Background information**
 	* [2018 | Aeternity state channel incentives](https://github.com/aeternity/protocol/tree/master/channels#incentives)
	* [2018 | Aeternity state channel fees](https://github.com/aeternity/protocol/tree/master/channels#fees)



### 6. Elevation of privilege
|  Tree Node |Explanation   | Developer Mitigation   | Operational Mitigation   | Notes | Actions | Priority |
|---|---|---|---|---|---|---|
| 6.1.1  | Malicious code embedded in the contracts can be run to exploit vulnerabilities in AEVM and lead to elevation of privilege on the epoch node or disclosure of information | Correct implementation and security testing of the AEVM | Sanity checks for code in smart contracts?  |   |   |   |
| 6.1.2 | Erlang daemon accepts incoming connection from other Erlang node (default cookie is epoch_cookie) | Node is started with -sname which disallows access from different IP address | Erlang daemon only listens to localhost  |   |   | low |
|   |   |   |   |   |   |   |


## Notes

 * **Notes from Documentation**
 	* [**Sync**](https://github.com/aeternity/protocol/blob/master/SYNC.md)
		* [Sync Transport Protocol](https://github.com/aeternity/protocol/blob/master/SYNC.md#transport-protocol): ***initiator of the handshake sends their static key to the responder and the initiator knows the static key of the responder.*** 
			* 	How does the initiator knows the static key of the responder?
			*  The reponder's public key is published and authenticated out of band.
	* [**Æternity epoch node API**](https://github.com/aeternity/protocol/blob/master/epoch/api/README.md#%C3%86ternity-epoch-node-api)
		* 	How is internal and external (Internet) exposure of APIs enforced?
	* [**Release 0.17.0 introduced backward-incompatibility**](https://github.com/aeternity/epoch/blob/master/docs/release-notes/RELEASE-NOTES-0.17.0.md)
	* Privilege levels for the code - what is the correct model?

	
	

## Conclusions

### Threats to be mitigated

### Threats to be eliminated

### Threats to be transferred

### Accepted risks
