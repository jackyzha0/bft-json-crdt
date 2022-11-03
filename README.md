# Byzantine Fault Tolerant CRDTs

This work is mainly inspired by implementing Martin Kleppmann's 2022 paper on *Making CRDTs Byzantine Fault Tolerant*[^2] 
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
Numbers are compared to Automerge which report their performance benchmarks [here](https://github.com/automerge/automerge-perf)

| # Ops | Raw String (JS) | Ours (basic) | Ours (BFT) | Automerge (JS) | Automerge (Rust) |
|--|--|--|--|--|--|
|10k       | n/a     | 0.081s   | 1.793s   | 1.6s         | 0.047s  |
|100k      | n/a     | 9.321s   | 38.842s  | 43.0s        | 0.597s  |
|All (259k)| 0.61s   | 88.610s  | 334.960s | Out of Memory| 1.780s  |
|Memory    | 0.1MB   | 27.6MB   | 59.5MB   | 880MB        | 232.5MB |

## Flamegraph
To get some flamegraphs of the time graph on MacOS, run:

```bash
sudo cargo flamegraph --dev --root --bench speed
```

## Further Work 
This is mostly a learning/instructional project but there are a few places where performance improvements are obvious:

1. This is backed by `std::Vec` which isn't great for random insert. Replace with a B-tree or something that provides better insert and find performance
    1. [Diamond Types](https://github.com/josephg/diamond-types) and [Automerge (Rust)](https://github.com/automerge/automerge-rs) use a B-tree
    2. Yjs is backed by a doubly linked-list and caches last ~5-10 accessed locations (assumes that most edits happen sequentially; seeks are rare)
    3. (funnily enough, main peformance hit is dominated by find and not insert, see [this flamegraph](./flamegraphs/flamegraph_unoptimized.svg))
2. Avoid calling `find` so many times. A few Automerge optimizations that were not implemented
    1. Use an index hint (especially for local inserts)
    2. Skipping the second `find` operation in `integrate` if sequence number is already larger
3. Improve storage requirement. As of now, a single `Op` weighs in at *over* 168 bytes. This doesn't even fit in a single cache line!
4. Speed up Ed25519 signature verification time by batching. For example, a peer might create an atomic 'transaction' that contains a bunch of changes.
5. Currently, each character is a single op. Similar to Yjs, we can combine runs of characters into larger entities like what André, Luc, et al.[^1] suggest
6. Implement proper persistence using SQLLite or something similar

[^1]: André, Luc, et al. "Supporting adaptable granularity of changes for massive-scale collaborative editing." 9th IEEE International Conference on Collaborative Computing: Networking, Applications and Worksharing. IEEE, 2013. 
[^2]: Kleppmann, Martin. "Making CRDTs Byzantine Fault Tolerant." Proceedings of the 9th Workshop on Principles and Practice of Consistency for Distributed Data. 2022.

## Acknowledgements
Thank you to [Nalin Bhardwaj](https://nibnalin.me/) for helping me with my cryptography questions and [Martin Kleppmann](https://martin.kleppmann.com/)
for his teaching materials and lectures which taught me a significant portion of what I've learned about distributed systems and CRDTs.
