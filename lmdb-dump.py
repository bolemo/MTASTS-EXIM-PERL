#!/usr/bin/python3

import sys
import lmdb

lmdb_path = sys.argv[1]

env = lmdb.open(lmdb_path, max_dbs=10)
db = env.open_db()

with env.begin() as txn:
    for key, value in list(txn.cursor(db=db))[1:]:
        k, v = key.decode(), value.decode()
        print('%s="%s"' % (k, v))
