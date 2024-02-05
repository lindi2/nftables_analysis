#!/usr/bin/python3
import argparse
import json
import sys
import ipaddress
import re
from z3 import Int, solve, Solver, If, sat, And, Optimize, Implies, Or, Xor, Not
import nft_simulator


def parse_constraint(constraint):
    CONSTRAINT_PATTERN = re.compile(r"^([^<>=!]+)(<|==|>|!=)([^<>=!]+)$")
    m = CONSTRAINT_PATTERN.match(constraint)
    if not m:
        print(f"Unable to parse constraint: {constraint}",
              file=sys.stderr)
        if "=" in constraint:
            print("Did you mean \"==\" perhaps?",
                  file=sys.stderr)
        sys.exit(1)
    return m.group(2), m.group(1), int(m.group(3))

    
def load_nftables(jsonruleset):
    if jsonruleset:
        with open(jsonruleset) as f:
            return json.load(f)["nftables"]
    else:
        cmd = [
            "nft",
            "--json",
            "list",
            "ruleset"
        ]
        return json.loads(subprocess.check_output(cmd, encoding="utf-8"))["nftables"]


def find_all_paths(nftables, target_verdict):
    packet_exprs = []
    while True:
        verdict, compared_exprs = nft_simulator.simulate(nftables, packet_exprs)
        if verdict == target_verdict:
            yield [(expr, expr in packet_exprs) for expr in compared_exprs]

        for level in range(len(compared_exprs) - 1, -1, -1):
            if compared_exprs[level] in packet_exprs:
                if level == 0:
                    return
                packet_exprs = list(filter(lambda x: x != compared_exprs[level], packet_exprs))
            else:
                packet_exprs.append(compared_exprs[level])
                break

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-ruleset",
                        help="File with output of \"nft --json list ruleset\"")
    parser.add_argument("-c",
                        "--constraint",
                        default=[],
                        action="append",
                        help="Extra constraint for the packet (example: tcp.dport==1234)")
    parser.add_argument("--verdict",
                        default="accept",
                        help="Desired verdict (default: accept)")
    args = parser.parse_args()

    nftables = load_nftables(args.json_ruleset)

    all_paths = find_all_paths(nftables, args.verdict)

    s = Optimize()
    p = {}
    
    p["meta.nfproto"] = Int("meta.nfproto")
    NFPROTO_IPV4 = 2
    NFPROTO_IPV6 = 10
    s.add(Or(p["meta.nfproto"] == NFPROTO_IPV4,
             p["meta.nfproto"] == NFPROTO_IPV6))


    p["meta.l4proto"] = Int("meta.l4proto")
    NFPROTO_ICMP = 1
    NFPROTO_TCP = 6
    NFPROTO_UDP = 17
    s.add(Or(p["meta.l4proto"] == NFPROTO_ICMP,
             p["meta.l4proto"] == NFPROTO_TCP,
             p["meta.l4proto"] == NFPROTO_UDP))

    p["tcp.sport"] = Int("tcp.sport")
    s.add(p["tcp.sport"] >= -1)
    s.add(p["tcp.sport"] < 65536)
    
    p["tcp.dport"] = Int("tcp.dport")
    s.add(p["tcp.dport"] >= -1)
    s.add(p["tcp.dport"] < 65536)

    s.add(Xor(p["meta.l4proto"] == NFPROTO_TCP, p["tcp.sport"] == -1))
    s.add(Xor(p["meta.l4proto"] == NFPROTO_TCP, p["tcp.dport"] == -1))

    p["udp.sport"] = Int("udp.sport")
    s.add(p["udp.sport"] >= -1)
    s.add(p["udp.sport"] < 65536)
    
    p["udp.dport"] = Int("udp.dport")
    s.add(p["udp.dport"] >= -1)
    s.add(p["udp.dport"] < 65536)

    s.add(Xor(p["meta.l4proto"] == NFPROTO_UDP, p["udp.sport"] == -1))
    s.add(Xor(p["meta.l4proto"] == NFPROTO_UDP, p["udp.dport"] == -1))
    
    p["meta.length"] = Int("meta.length")
    s.add(p["meta.length"] >= 0)
    s.add(p["meta.length"] < 1600)

    ifaces = []
    p["meta.iif"] = Int("meta.iif")
    s.add(p["meta.iif"] >= 0)
    s.add(p["meta.iif"] < 10)

    p["ip.saddr"] = Int("ip.saddr")
    s.add(p["ip.saddr"] >= -1)
    s.add(p["ip.saddr"] < 2**32)

    p["ip.daddr"] = Int("ip.daddr")
    s.add(p["ip.daddr"] >= -1)
    s.add(p["ip.daddr"] < 2**32)

    s.add(Xor(p["meta.nfproto"] == NFPROTO_IPV4, p["ip.saddr"] == -1))
    s.add(Xor(p["meta.nfproto"] == NFPROTO_IPV4, p["ip.daddr"] == -1))

    p["ip6.saddr"] = Int("ip6.saddr")
    s.add(p["ip6.saddr"] >= -1)
    s.add(p["ip6.saddr"] < 2**128)

    p["ip6.daddr"] = Int("ip6.daddr")
    s.add(p["ip6.daddr"] >= -1)
    s.add(p["ip6.daddr"] < 2**128)

    s.add(Xor(p["meta.nfproto"] == NFPROTO_IPV6, p["ip6.saddr"] == -1))
    s.add(Xor(p["meta.nfproto"] == NFPROTO_IPV6, p["ip6.daddr"] == -1))

    def format_left(val):
        if "meta" in val:
            return f"meta.{val['meta']['key']}"
        elif "payload" in val:
            return f"{val['payload']['protocol']}.{val['payload']['field']}"
        else:
            print(f"Unsupported left val: {val}",
                  file=sys.stderr)
            sys.exit(1)

    def z3_op(op, l, r):
        if op == "==":
            return l == r
        elif op == "!=":
            return l != r
        elif op == "<":
            return l < r
        elif op == ">":
            return l > r
        print(f"Unsupported op: {op}",
              file=sys.stderr)
        sys.exit(1)

    def construct_expr(op, left, right):
        if isinstance(right, int):
            return z3_op(op,
                         p[left],
                         right)
        elif "range" in right:
            if op == "!=":
                return Not(And(p[left] >= right["range"][0], p[left] <= right["range"][1]))
            else:
                return And(p[left] >= right["range"][0], p[left] <= right["range"][1])
        elif left in ["ip.saddr", "ip.daddr"]:
            return z3_op(op,
                         p[left],
                         int(ipaddress.IPv4Address(right)))
        elif left in ["ip6.saddr", "ip6.daddr"]:
            return z3_op(op, p[left],
                         int(ipaddress.IPv6Address(right)))
        elif left == "meta.nfproto":
            if right == "ipv6":
                return z3_op(op,
                             p[left],
                             NFPROTO_IPV6)
            elif right == "ipv4":
                return z3_op(op,
                             p[left],
                             NFPROTO_IPV4)
            else:
                print(f"Unsupported nfproto: {right}",
                      file=sys.stderr)
                sys.exit(1)
        elif left == "meta.iif":
            if right.isdigit():
                return z3_op(op,
                             p[left],
                             int(right))
            if right not in ifaces:
                ifaces.append(right)
            return z3_op(op,
                         p[left],
                         ifaces.index(right))
        else:
            print(f"Unsupported right: {repr(right)} (left {left})",
                  file=sys.stderr)
            sys.exit(1)
    
    path_conds = []
    for path in all_paths:
        # if ({'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}}, 'right': 1234}}, True) not in path:
        #     continue
        #print("PATH")
        path_cond = []
        for raw_expr in path:
            #print(raw_expr)
            expr, value = raw_expr
            expr = expr["match"]
            op = expr["op"]
            left_expr = expr["left"]
            right = expr["right"]
            left = format_left(left_expr)
            cond = construct_expr(op, left, right)
            if value:
                path_cond.append(cond)
            else:
                path_cond.append(Not(cond))
        path_conds.append(And(path_cond))
    s.add(Or(path_conds))

    for constraint in args.constraint:
        op, left, right = parse_constraint(constraint)
        cond = construct_expr(op, left, right)
        s.add(cond)
        
    #print(s)
    s.minimize(sum(p.values()))
    if s.check() == sat:
        print("Satified")
        model = s.model()
        vs = [(v, model[v]) for v in model]
        vs = sorted(vs, key=lambda a: str(a))
        solution = {}
        for k, v in vs:
            solution[str(k)] = v.as_long()
            print(f"{k}={v}")
    else:
        print("Unsatified")
    

if __name__ == "__main__":
    main()
