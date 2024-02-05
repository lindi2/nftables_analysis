# Introduction

This is a simple attempt at programmatically analyzing nftables rulesets.

# Dependencies

This tool uses the z3 SMT solver, you can install it with e.g.

```
apt install python3-z3
```

# Usage example

The test_data directory comes with some example rulesets. If you run

```
./find_satisfying_packet.py --json-ruleset test_data/complex1.nft.json -c tcp.dport==1234 --verdict accept
```

you can programmatically find a packet that is accepted by the ruleset, with the extra constraint that the packet must have TCP destination port of 1234. This is useful for example to find out if there is a way to construct a packet that reaches a given service.

