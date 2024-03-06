#!/usr/bin/python3
import sys


def uniq(seq):
    seen = []
    return [x for x in seq if not (x in seen or seen.append(x))]


def get_chain(entry):
    return entry["chain"]


def get_rule(entry):
    return entry["rule"]


def chain_priority(entry):
    return entry["chain"]["prio"]


def is_chain(entry, family, table_name, chain_name):
    if "chain" not in entry:
        return False
    if entry["chain"]["family"] != family:
        return False
    if entry["chain"]["table"] != table_name:
        return False
    if entry["chain"]["name"] != chain_name:
        return False
    return True


def is_rule_in_chain(entry, family, table_name, chain_name):
    if "rule" not in entry:
        return False
    if "chain" not in entry["rule"]:
        return False
    if entry["rule"]["chain"] != chain_name:
        return False
    if entry["rule"]["table"] != table_name:
        return False
    if entry["rule"]["family"] != family:
        return False
    return True


def is_input_chain(entry):
    if "chain" not in entry:
        return False
    if "hook" not in entry["chain"]:
        return False
    if "type" not in entry["chain"]:
        return False
    if entry["chain"]["hook"] != "input":
        return False
    if entry["chain"]["type"] != "filter":
        return False
    return True


class PacketSimulation:
    def __init__(self, nftables, packet_exprs, print_trace=False):
        self.nftables = nftables
        self.packet_exprs = packet_exprs
        self.compared_exprs = []
        self.print_trace = print_trace


    def trace(self, msg):
        if self.print_trace:
            print("trace: {msg}",
                  file=sys.stderr)


    def eval_nftables(self):
        self.trace("eval_nftables")
        ip6_expr = {
            "match": {
                "op": "==",
                "left": {
                    "meta": {
                      "key": "nfproto"
                    }
                },
                "right": "ipv6"
            }
        }
        families = [
            "inet",
            "ip6" if self.eval_expr(ip6_expr) else "ip"
        ]
        for chain in map(get_chain, sorted(filter(is_input_chain, self.nftables), key=chain_priority)):
            if chain["family"] not in families:
                continue
            verdict = self.eval_chain(chain["family"],
                                      chain["table"],
                                      chain["name"])
            if verdict == "drop":
                return verdict
        return "accept"


    def eval_rule(self, family, table_name, rule):
        self.trace(f"    eval_rule {family} {table_name}")
        verdict = self.eval_rule_real(family, table_name, rule)
        self.trace(f"    eval_rule {family} {table_name} => {verdict}")
        return verdict


    def eval_rule_real(self, family, table_name, rule):
        eval_true = True
        for expr in rule["expr"][:-1]:
            if not self.eval_expr(expr):
                eval_true = False
                break
        if not eval_true:
            return None
        operation = rule["expr"][-1]
        if "log" in operation:
            return None
        elif "drop" in operation:
            return "drop"
        elif "xt" in operation and operation["xt"]["type"] == "target" and operation["xt"]["name"] == "REJECT":
            return "drop"
        elif "accept" in operation:
            return "accept"
        elif "counter" in operation:
            return None
        elif "jump" in operation:
            return self.eval_chain(family,
                                   table_name,
                                   operation["jump"]["target"])
        elif "return" in operation:
            return "return"
        elif "xt" in operation and operation["xt"]["type"] == "target" and operation["xt"]["name"] == "LOG":
            return None
        else:
            print(f"Unsupported operation: {operation}",
                  file=sys.stderr)
            sys.exit(1)


    def eval_chain(self, family, table_name, chain_name):
        self.trace(f"  eval_chain {family} {table_name} {chain_name}")
        verdict = None
        policy = list(map(get_chain, filter(lambda entry: is_chain(entry, family, table_name, chain_name), self.nftables)))[0].get("policy", None)

        for rule in map(get_rule, filter(lambda entry: is_rule_in_chain(entry, family, table_name, chain_name), self.nftables)):
            verdict = self.eval_rule(family, table_name, rule)
            if verdict is not None:
                break
        if verdict is None:
            verdict = policy
        self.trace(f"  eval_chain {family} {table_name} {chain_name} => {verdict}")
        if verdict == "return":
            return None
        else:
            return verdict


    def eval_expr(self, expr):
        if "counter" in expr:
            return True
        if "limit" in expr:
            return True
        self.compared_exprs.append(expr)
        ret = expr in self.packet_exprs
        self.trace(f"      eval_expr {expr} => {ret}")
        return ret


def simulate(nftables, packet_exprs, print_trace=False):
    simulation = PacketSimulation(nftables, packet_exprs, print_trace=print_trace)
    verdict = simulation.eval_nftables()
    return verdict, uniq(simulation.compared_exprs)
