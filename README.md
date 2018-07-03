Treasury coin
====================================================================================================================================================================================
Treasury coin is an experimental implementation of the perspective treasury system
described in [A Treasury System for Cryptocurrencies: Enabling Better Collaborative Intelligence](https://eprint.iacr.org/2018/435.pdf)

Scorex
-------------------
This repository is a fork of the Scorex platform upon which the treausury system was
built. Specifically, the "Hybrid" example was modified to integrate treasury.

More information about Scorex and how to work with it can be found in
[https://github.com/ScorexFoundation/Scorex/](https://github.com/ScorexFoundation/Scorex/) 

Note that Scorex framework is still raw and not production ready.


Motivation
-------------------
Modern cryptocurrencies are complex systems that require continuous maintenance.
Even though it is usually proclaimed that such systems are completely decentralized
and no one in full possession, all existing cryptocurrency systems have core team 
of members that, at least, controls the development effort.

It becomes crucial how this core team is funded, because in most cases a music is
played by those who pays money. If a core team is payed by some standalone investor
most likely they will follow his wishes that are not necesseraly beneficial for a 
cryptocurrency general well-being.

Treasury system aims to solve this problem by providing means for establishing 
collaborative consensus among all cryptocurency stakeholders about financing a system.
The source of funds is usually some part of block reward, but not restricted to be
only this one.


Treasury implementation
--------
The treasury system is built upon Hybrid example in Scorex. It introduces new transaction
types and separate Treasury state to facilitate voting protocol and proposals funding.

All cryptography needed for the voting protocol is implemented in a separate library 
[https://github.com/input-output-hk/treasury-crypto](https://github.com/input-output-hk/treasury-crypto)
which is currently in a private repository. 

The following features are implemented:
* Proposals submission
* Voters/Experts/Committe members registration
* Locked deposits for all actors in the system
* Random selection of the committee
* Distributed key generation
* Ballots casting
* Joint decryption with recovery in case of faulty committee members
* Randomness generation
* Reward payments and deposit paybacks
* Penalties for faulty actors
* etc.

Current status
-------------
The system was successfully tested with local testnet of up to 15 nodes. But still it
can't be considered as production ready.

Documentation
-------------

[Scorex tutorial](https://github.com/ScorexFoundation/ScorexTutorial)
[Treasury paper](https://eprint.iacr.org/2018/435.pdf)


License
-------

TODO
