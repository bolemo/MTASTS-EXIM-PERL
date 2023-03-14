#!/usr/bin/python3

import sys, io

import lmdb

lmdb_path, key = sys.argv[1], sys.argv[2]

env = lmdb.open(lmdb_path, max_dbs=10)
db = env.open_db()

with env.begin(write=True) as txn:
    txn.delete(key.encode())
