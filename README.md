# Byzantine Fault Tolerant CRDTs

This work is mainly inspired by implementing Martin Kleppmann's 2022 paper on *Making CRDTs Byzantine Fault Tolerant* ([source](https://martin.kleppmann.com/papers/bft-crdt-papoc22.pdf))
on top of a simplified [Automerge](https://automerge.org/) implementation.

The goal is to show a working prototype that demonstrated in simple code the ideas behind
1. An Automerge-like CRDT
2. How a primitive list CRDT can be composed to create complex CRDTs like JSON
2. How to add Byzantine Fault Tolerance to arbitrary CRDTs

Unlike most other CRDT implementations, I leave out many performance optimizations that would make the basic algorithm harder to understand.

## Benchmarks
Altough this implementation does not optimize for performance, it still nonetheless performs quite well.

Benchmarking happened on a 2019 Macbook Pro with a 2.6GHz i7.
Numbers are compared to  which report their performance benchmarks [here](https://github.com/automerge/automerge-perf)

| # Ops | Raw String (JS) | Ours (basic) | Ours (BFT) | Automerge |
|--|--|--|--|
|10k       | -     | 0.085s  | - | 1.6s    |
|100k      | -     | 11.321s | - | 43.0s   |
|All (259k)| 0.61s | 110.040s| - | Timeout |
