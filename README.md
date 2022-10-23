# Byzantine Fault Tolerant CRDTs

This work is mainly inspired by implementing Martin Kleppmann's 2022 paper on *Making CRDTs Byzantine Fault Tolerant* ([source](https://martin.kleppmann.com/papers/bft-crdt-papoc22.pdf))
on top of a simplified [Automerge](https://automerge.org/) implementation.

The goal is to show a working prototype that demonstrated in simple code the ideas behind
1. An Automerge-like CRDT
2. How a primitive list CRDT can be composed to create complex CRDTs like JSON
2. How to add Byzantine Fault Tolerance to arbitrary CRDTs

Unlike most other CRDT implementations, I leave out many performance optimizations that would make the basic algorithm harder to understand.

Check out the [accompanying blog post for this project!](https://jzhao.xyz/posts/bft-json-crdt)

## Benchmarks
Altough this implementation does not optimize for performance, it still nonetheless performs quite well.

Benchmarking happened on a 2019 Macbook Pro with a 2.6GHz i7.
Numbers are compared to  which report their performance benchmarks [here](https://github.com/automerge/automerge-perf)

| # Ops | Raw String (JS) | Ours (basic) | Ours (BFT) | Automerge |
|--|--|--|--|--|
|10k       | n/a     | 0.081s   | 1.793s   | 1.6s         |
|100k      | n/a     | 9.321s   | 38.842s  | 43.0s        |
|All (259k)| 0.61s   | 88.610s  | 334.960s | Out of Memory|
|Memory    | 0.1MB   | n/a      | 69.5MB   | 880MB        |

## Flamegraph
To get some flamegraphs of the time graph on MacOS, run:

```bash
sudo cargo flamegraph --dev --root --bench speed
```

## Further Work 
This is mostly a learning/instructional project but there are a few places where performance improvements are obvious
1. This is backed by `std::Vec` which isn't great for random insert. Replace with a `collections::BTreeSet` or something that provides better insert performance.
2. Avoid calling `find` so many times 
  1. A few Automerge optimizations that were not implemented
  2. e.g. skipping the second `find` operation in `integrate` if sequence number is already larger
3. Improve storage requirement. As of now, a single `Op` weighs in at *over* 168 bytes. This doesn't even fit in a single cache line!
