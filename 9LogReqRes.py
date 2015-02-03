#
# Stores all traffic in a SQLite db
# 
# Note: requests & responses are *NOT* modified (i.e. might be binary)
#
import sqlite3
import time

class SqliteDb:
	def __init__(self, dbname=None):
		if dbname is None:
			dbname = "/tmp/proxenet-"+str( int(time.time()) )+".db"
		self.data_file = dbname

		# init schema
		self.execute("CREATE TABLE requests  (id INTEGER, request BLOB, timestamp INTEGER)")
		self.execute("CREATE TABLE responses (id INTEGER, request BLOB, timestamp INTEGER)")
		return
 
	def connect(self):
		self.conn = sqlite3.connect(self.data_file)
		self.conn.text_factory = str
		return self.conn.cursor()
 
	def disconnect(self):
		self.cursor.close()
		return
 
	def free(self, cursor):
		cursor.close()
		return
 
	def execute(self, query, values = ''):
		cursor = self.connect()
		if values != '':
			cursor.execute(query, values)
		else:
			cursor.execute(query)
		self.conn.commit()
		return cursor

 
db = SqliteDb()


def proxenet_request_hook(request_id, request, uri):
	global db
	ts = int( time.time() )
	db.execute("INSERT INTO requests VALUES (?, ?, ?)", (request_id, request, ts))
	return request

    
def proxenet_response_hook(response_id, response, uri):
	global db
        ts = int( time.time() )
        db.execute("INSERT INTO responses VALUES (?, ?, ?)", (response_id, response, ts))
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
