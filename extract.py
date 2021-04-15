#!/usr/bin/python3

import sys
import os
import argparse
import time
import json

import networkx as nx

import binaryninja as binja

# Features from "Scalable Graph-based Bug Search for Firmware Images" (CCS 2016)
# paper

# From: https://github.com/yangshouguo/Graph-based_Bug_Search
#   transfer_instructions = ['MOV','PUSH','POP','XCHG','IN','OUT','XLAT','LEA','LDS','LES','LAHF', 'SAHF' ,'PUSHF', 'POPF']
#   arithmetic_instructions = ['ADD', 'SUB', 'MUL', 'DIV', 'XOR', 'INC','DEC', 'IMUL', 'IDIV', 'OR', 'NOT', 'SLL', 'SRL']

# From: https://github.com/qian-feng/Gencoding/blob/7dcb04cd577e62a6394f5f68b751902db552ebd3/raw-feature-extractor/graph_analysis_ida.py
#   arithmetic_instructions = ['add', 'sub', 'div', 'imul', 'idiv', 'mul', 'shl', 'dec', 'inc']
#   transfer_instrucitons = ['jmp', 'jz', 'jnz', 'js', 'je', 'jne', 'jg', 'jle', 'jge', 'ja', 'jnc', 'call']
#   call_instructions = ['call', 'jal', 'jalr']

# Mine
transfer_instructions = ['mov','push','pop','xchg','in','out','xlat','lea','lds','les','lahf', 'sahf' ,'pushf', 'popf']
arithmetic_instructions = ['add', 'sub', 'div', 'imul', 'idiv', 'mul', 'shl', 'dec', 'inc', 'xor', 'or', 'not', 'sll', 'srl']
call_instructions = ['call']
jmp_instructions = ['jmp', 'jz', 'jnz', 'js', 'je', 'jne', 'jg', 'jle', 'jge', 'ja', 'jnc']

# Extracts ACFG features
def dump_acfg_binja(fn,output):
    data = list()

    start = time.time()

    # Import database file
    bv = binja.BinaryViewType.get_view_of_file(fn)

    sys.stdout.write('{0} Importing BNDB file took {1} seconds\n'.format(fn,time.time()-start))
    time_previous = time.time()

    # For each function
    for func in bv.functions:
        # If not an internal function, skip it
        symbol = func.symbol
        if symbol.type != binja.types.SymbolType.FunctionSymbol:
            continue

        func_data = dict()

        # Insert data about function
        func_data['src'] = fn
        func_data['fname'] = func.name
        func_data['n_num'] = len(func.basic_blocks)
        func_data['succs'] = list()
        func_data['features'] = list()

        # Construct list of all basic blocks (to index)
        bbs = list()
        for bb in func.basic_blocks:
            bbs.append(bb.start)

        # Construct function control flow networkx graph to determine betweenness
        G = nx.DiGraph()
        for bb in func.basic_blocks:
            # Add node
            if bb.start not in G.nodes():
                G.add_node(bb.start)

            # Add edges
            for edge in bb.incoming_edges:
                # If source node doesn't exist, create it
                if edge.source.start not in G.nodes():
                    G.add_node(edge.source.start)
                G.add_edge(edge.source.start,bb.start)

            for edge in bb.outgoing_edges:
                # If target node doesn't exist, create it
                if edge.target.start not in G.nodes():
                    G.add_node(edge.target.start)
                G.add_edge(bb.start,edge.target.start)

        # Get betweenness of function CFG
        betweenness = nx.betweenness_centrality(G)

        # Construct features
        for bb in func.basic_blocks:
            # Get instructions for this basic block
            insts = bb.get_disassembly_text()

            # Get features
            features = list([0.0]*7)

            # For each instruction of basic block
            for e,inst in enumerate(insts):
                # First text of disassembly is function name and address
                if e == 0:
                    continue

#               sys.stdout.write('{0} | {1} \n'.format(hex(inst.address),inst))

                # Get tokens
                tokens = [str(t) for t in inst.tokens]

                # Get mnemonic
                mnemonic = tokens[0]

                # Number of string constants
                for t in tokens:
                    if '"' in t:
                        features[0] += 1

                # NOTE: might need to be improved
                # Number of numeric constants
                try:
                    if (mnemonic not in call_instructions) and (mnemonic not in jmp_instructions):
                        int(tokens[-1],16)
                        features[1] += 1
                except:
                    pass

                # Number of transfer instructions
                if mnemonic in transfer_instructions:
                    features[2] += 1
                # Number of calls
                if mnemonic in call_instructions:
                    features[3] += 1
                # Number of instructions
                features[4] += 1
                # Number of arithmetic instructions
                if mnemonic in arithmetic_instructions:
                    features[5] += 1

            # Betweenness
            features[6] = betweenness[bb.start]

            # Append basic block features
            func_data['features'].append(features)

            # Get all successor basic blocks
            succs = set()
            for edge in bb.outgoing_edges:
                succs.add(bbs.index(edge.target.start))
            func_data['succs'].append(list(succs))

        # Append function features to data for binary
        data.append(func_data)

    # Dump data into JSON file
    with open(output,'w') as fw:
        fw.write('\n'.join([json.dumps(d) for d in data]))

def _main():
    # Parse arguments
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(help='disassembler types help', dest='cmd')
    subparsers.required = True

    sp = subparsers.add_parser('binja', help='use BinaryNinja to get CFG')
    sp.set_defaults(cmd='binja')
    sp.add_argument('--bndb', help='BNDB file', required=True)
    sp.add_argument('--output', help='output file', required=True)

    args = parser.parse_args()

    # Store arguments
    tool = args.cmd
    output = args.output

    if tool == 'binja':
        fn = args.bndb
    else:
        sys.stderr.write('Invalid disassembler: {0}\n'.format(tool))
        sys.exit(1)

    # If bndb file doesn't exist
    if not os.path.exists(fn):
        sys.stderr.write('{0} does not exist\n'.format(fn))
        sys.exit(1)

    # If raw file already exists
    if os.path.exists(output):
        sys.stderr.write('{0} already exists\n'.format(output))
        sys.exit(1)

    # Extract raw features
    if tool == 'binja':
        acfg_json = dump_acfg_binja(fn,output)

if __name__ == '__main__':
    _main()
