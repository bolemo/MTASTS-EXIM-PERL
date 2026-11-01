#!/usr/bin/python3

import sys, io, os, fcntl

import lmdb

lmdb_path, key = sys.argv[1], sys.argv[2]

# mta-lmdb.pl opens the DB with MDB_NOLOCK: hold its lock file alone while writing
lockfd = os.open(os.path.join(lmdb_path, 'write.lock'), os.O_RDONLY | os.O_CREAT, 0o666)
with os.fdopen(lockfd) as lockfile:
    fcntl.flock(lockfile, fcntl.LOCK_EX)
    env = lmdb.open(lmdb_path, max_dbs=10, lock=False)
    db = env.open_db()

    with env.begin(write=True) as txn:
        txn.delete(key.encode())
