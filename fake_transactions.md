# Posting fake transactions to the network in order to steal aetokens

# Posting fake transactions to the network in order to overlaod the system

Creating and posting a transaction is a computationally cheap action for an attacker. Valdiation of a transaction is computational cheap, but having to validate many transactions that cannot be included in a block, is a computational overhead for a miner. If an attacker could post enormous amounts of transactions to the network, it could potentially impact the rate in which correct transactions are accepted.

## Safety features

* The node that receives a transactions validates this transaction. Invalid transactions are rejected and never propagated to other nodes. A valid transaction is a transaction that can potentially be included in a future block and that a miner receives a fee for.
* Transactions may validate but nevertheless not be possible to include in a block. For example, an attacker could post a spend-transaction including more tokens than the from account contains. This transaction is then kept in the transaction pool for a while and *check this*  validated for each new block candidate.
* Validation of transactions that involve running contracts is done by checking that there enough funds are available for the gas cost of actually running the contract. The actual validation does not run the contract.
* ### name transactions and risk of binary_to_atom memory overload

## Impact
* Posted invalid transactions are load balanced using web framework; since they are not propagated it is expensive to attack many nodes at once. When attacking one specific node, it is considered a traditional DoS attack on an http webserver. Standard webserver protection mittigates the effect of these attacks.
* Valid transactions have a configurable TTL that determines how long a transaction may stay in the memory pool. By default a node is configured to have a transaction in the pool for at most 256 blocks.

