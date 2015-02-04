#
# Stores all traffic in a SQLite db
#
# Note: requests & responses are stored as is (i.e. might be binary, compressed, etc)
#

import sqlite3
import time

__PLUGIN_NAME__ = "LogReqRes"
__AUTHOR__ = "hugsy"


class SqliteDb:
    def __init__(self, dbname=None):
        if dbname is None:
            dbname = "/tmp/proxenet-"+str( int(time.time()) )+".db"

        print("[%s] HTTP traffic will be stored in '%s'" % (__PLUGIN_NAME__, dbname))
        self.data_file = dbname
        self.execute("CREATE TABLE requests  (id INTEGER, request BLOB, uri TEXT, timestamp INTEGER)")
        self.execute("CREATE TABLE responses (id INTEGER, response BLOB,  uri TEXT, timestamp INTEGER)")
        return

    def connect(self):
        self.conn = sqlite3.connect(self.data_file)
        self.conn.text_factory = str
        return self.conn.cursor()

    def disconnect(self):
        self.conn.close()
        return

    def execute(self, query, values=None):
        cursor = self.connect()
        if values is None:
            cursor.execute(query)
        else:
            cursor.execute(query, values)

        self.conn.commit()
        return cursor


db = SqliteDb()


def proxenet_request_hook(request_id, request, uri):
    global db
    ts = int( time.time() )
    db.execute("INSERT INTO requests VALUES (?, ?, ?, ?)", (request_id, request, uri, ts))
    return request


def proxenet_response_hook(response_id, response, uri):
    global db
    ts = int( time.time() )
    db.execute("INSERT INTO responses VALUES (?, ?, ?, ?)", (response_id, response, uri, ts))
    return response


if __name__ == "__main__":
    uri = "foo"
    req = "GET / HTTP/1.1\r\nHost: foo\r\nX-Header: Powered by proxenet\r\n\r\n"
    res = "HTTP/1.0 200 OK\r\n\r\n"
    rid = 10
    proxenet_request_hook(rid, req, uri)
    proxenet_response_hook(rid, res, uri)
    db.disconnect()
    exit(0)
