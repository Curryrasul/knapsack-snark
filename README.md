# zk-SNARK Preimage knowledge of Knapsack hash (Free TON contest)

## Building

Requirements: Boost >= 1.74.

```shell
git clone https://github.com/Curryrasul/knapsack-snark && cd knapsack-snark
mkdir build && cd build
cmake ..
make cli
```

Usage example

```shell
cd ./bin/cli
./cli --hash
./cli --keys
./cli --proof
./cli --verify
```
