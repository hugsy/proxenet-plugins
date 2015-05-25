"""
Lightweight interception plugin for proxenet by @_hugsy_.
On top of simply intercepting the traffic, it can be
used to save request as raw text or as Python script
ready to replay.
Also it can be used to prepare `patator` command, for
file/argument fuzzing.

It will automatically recognize specific body formats:
* JSON
* XML

And also parse ASP.NET viewstate.

To add/remove file extensions to white/black list for
interception, edit the file from the CONFIG_FILE
variable.

Requires:
 - PyQt4
"""

import sys, os, urlparse, json, xml.etree.ElementTree
import socket, base64, pprint, urllib, ConfigParser

from PyQt4 import QtCore, QtGui
from PyQt4.QtGui import *

PLUGIN_NAME = "Interceptor"
AUTHOR      = "hugsy"

CRLF = "\r\n"
CONFIG_FILE = os.getenv("HOME") + "/.interceptor.ini"
config = None


class OptionsView(QWidget):
    def __init__(self, parent):
        super(OptionsView, self).__init__()
        self.parent = parent
        self.setTabLayout()
        return

    def setTabLayout(self):
        lay = QVBoxLayout()
        l1 = QLabel()
        blacklist = config.get("main", "__blacklisted")
        l1.setText("%d Blacklisted Extensions" % (len(blacklist)))
        te = QTextEdit()
        te.setFrameStyle(QFrame.Panel | QFrame.Plain)
        te.setDisabled(True)
        te.insertPlainText( "\n".join( blacklist ) )
        te.setFrameStyle(QFrame.Panel | QFrame.Plain)
        lay.addWidget(l1)
        lay.addWidget(te)
        self.setLayout(lay)
        return


class ViewState:
    def __init__(self, b64):
        self.vs_b64 = b64
        self.vs_raw = base64.decodestring(self.vs_b64)
        self.vs_arr = self.parseViewstate()
        return

    def decodeViewstate(self, i=0, p=[]):
        def decodeAsInt(j,q):
            n = str( ord(vs[j+1]) )
            q.append( ("<Int32>(%d)" % j, [(n, [])]), )
            return j+2

        def decodeAsString(j,t,q):
            l = ord(vs[j+1])
            s = vs[j+2 : j+2+l]
            q.append( ("<%s>(%d)"%(t,j), [(s, [])]), )
            return i+2+l

        def decodeAsArray(j,n,t,q):
            P = ("<%s>(%d)"%(t,j), )
            j = j+1
            for i in range(n):
                t = []
                j = self.decodeViewstate(j, t)
                P += (t,)
            q.append( P )
            return j

        vs = self.vs_raw[2:-20]

        if i >= len(vs):
            p.append( ("<End>(%d)"%i, []), )
            return

        if vs[i] == '\x02':
            return decodeAsInt(i,p)

        elif vs[i] == '\x05':
            return decodeAsString(i, "SystemString", p)

        elif vs[i] == '\x1e':
            return decodeAsString(i, "SystemWebUiIndexedString", p)

        elif vs[i] == '\x64':
            p.append( ("<Null>(%d)"%i, []), )
            return i+1

        elif vs[i] == '\x0f':
            return decodeAsArray(i,2,"Pair",p)

        elif vs[i] == '\x10':
            return decodeAsArray(i,3,"Triple",p)

        elif vs[i] == '\x16':
            return decodeAsArray(i+1,ord(vs[i+1]),"ArrayList",p)

        #
        # TODO: check those types
        #
        # \x07 Double
        # \x15 SystemStringArray
        # \x18 HybridDictionary
        # \x1f SystemWebUiIndexedChar
        # \x28 ClassType
        # \x32 SerializedClass
        # \x3c IndexedArray
        # \x66 IntZero
        # \x67 BooleanTrue
        # \x68 BooleanFalse
        #

        p.append( ("<Unknown-0x%x>(%d)"%(ord(vs[i]),i), []), )
        return i+1

    def parseViewstate(self):
        try:
            vs = []
            if not self.isValid(): raise Exception("ViewState is not a valid .NET ViewState")
            self.header = self.vs_raw[0:2]
            self.vs_hash = ":".join( [c.encode("hex") for c in self.vs_raw[-20:]] )
            self.decodeViewstate(i=0, p=vs)
        except Exception as e:
            print("VIEWSTATE decoding failed: %s" % e)
            vs = []

        return [ ("<ViewState>", vs),
                 ("<ViewStateHash>", [(self.vs_hash, [])]) ]

    def isValid(self):
        return self.vs_raw.startswith("\xff\x01")


class AspViewstateInterceptView(QWidget):
    def __init__(self, parent):
        super(AspViewstateInterceptView, self).__init__()
        self.parent = parent
        self.data = self.getViewState()
        if self.data is None:
            self.viewstate = []
        else:
            self.viewstate = ViewState(self.data)
        self.setTabLayout()
        return

    def getViewState(self):
        body = self.parent.parent.body
        args = [x.split("=") for x in body.split("&")]
        for k,v in args:
            if k=="__VIEWSTATE": return urllib.unquote(v)
        return None

    def setTabLayout(self):
        vs = self.viewstate.vs_arr
        lay = QVBoxLayout()
        l1 = QLabel("<b>ASP .NET</b> ViewState tree")
        m = QStandardItemModel()
        self.addItems(m, vs)
        self.tv = QTreeView()
        self.tv.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.tv.setModel(m)
        m.setHorizontalHeaderLabels(["ViewState"])
        lay.addWidget(l1)
        lay.addWidget(self.tv)
        self.setLayout(lay)
        return

    def addItems(self, model, elements):
        for elt in elements:
            text = elt[0]
            children = elt[1:]
            item = QStandardItem(text)
            model.appendRow(item)
            if len(children):
                for child in children:
                    self.addItems(item, child)
        return


class XmlInterceptView(QWidget):
    def __init__(self, parent):
        super(XmlInterceptView, self).__init__()
        self.parent = parent
        self.setTabLayout()
        return

    def setTabLayout(self):
        lay = QVBoxLayout()
        self.xmll = QLabel()
        self.xmlf = QTextEdit()
        self.xmlf.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.xmlf.textChanged.connect( self.updateFields )
        self.xmlf.insertPlainText( self.parent.parent.body )
        lay.addWidget(self.xmll)
        lay.addWidget(self.xmlf)
        self.setLayout(lay)
        return

    def updateFields(self):
        p = QPalette()

        try:
            body = str( self.xmlf.toPlainText() )
            x = xml.etree.ElementTree.fromstring(body)
            p.setColor( QPalette.Foreground, QtCore.Qt.darkYellow )
            self.xmll.setText("Content is <b>valid</b> XML")
        except xml.etree.ElementTree.ParseError:
            p.setColor( QPalette.Foreground, QtCore.Qt.darkRed )
            self.xmll.setText("Content is <b>not valid</b> XML")

        self.xmll.setPalette(p)
        self.parent.parent.body = body
        return

    def showEvent(self, event):
        body = self.parent.parent.body
        self.xmlf.clear()
        self.xmlf.insertPlainText( body )
        return


class JsonInterceptView(QWidget):
    def __init__(self, parent):
        super(JsonInterceptView, self).__init__()
        self.parent = parent
        self.setTabLayout()
        return

    def setTabLayout(self):
        lay = QVBoxLayout()
        self.jsonl = QLabel()
        self.jsonf = QTextEdit()
        self.jsonf.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.jsonf.textChanged.connect( self.updateFields )
        self.jsonf.insertPlainText( self.parent.parent.body )
        lay.addWidget(self.jsonl)
        lay.addWidget(self.jsonf)
        self.setLayout(lay)
        return

    def updateFields(self):
        p = QPalette()

        try:
            body = str( self.jsonf.toPlainText() )
            js = json.loads(body)
            p.setColor( QPalette.Foreground, QtCore.Qt.darkYellow )
            self.jsonl.setText("Content is <b>valid</b> JSON")
        except ValueError:
            p.setColor( QPalette.Foreground, QtCore.Qt.darkRed )
            self.jsonl.setText("Content is <b>not valid</b> JSON")

        self.jsonl.setPalette(p)
        self.parent.parent.body = body
        return

    def showEvent(self, event):
        body = self.parent.parent.body
        self.jsonf.clear()
        self.jsonf.insertPlainText( body )
        return


class RawInterceptView(QWidget):
    def __init__(self, parent):
        super(RawInterceptView, self).__init__()
        self.parent = parent
        self.setTabLayout()
        return

    def updateBody(self):
        self.parent.parent.body = self.rawBodyTextField.toPlainText()
        return

    def setTabLayout(self):
        self.rawBodyTextField = QTextEdit( self.parent.parent.body )
        self.rawBodyTextField.textChanged.connect( self.updateBody )
        self.rawBodyTextField.setFrameStyle(QFrame.Panel | QFrame.Plain)
        tabLayout = QVBoxLayout()
        tabLabel = QLabel("This frame displays the body content as <b>Raw</b>")
        tabLayout.addWidget(tabLabel)
        tabLayout.addWidget( self.rawBodyTextField )
        self.setLayout(tabLayout)
        return

    def showEvent(self, event):
        body = self.parent.parent.body
        self.rawBodyTextField.clear()
        self.rawBodyTextField.insertPlainText( body )
        return


class InterceptorMainWindow(QWidget):
    def __init__(self, parent):
        super(InterceptorMainWindow, self).__init__()
        self.parent = parent
        self.setTabs()
        self.setMainWindowLayout()
        return

    def updateHeaders(self):
        self.parent.headers = self.hdrEditField.toPlainText()

    def bounceRequest(self):
        body = str( self.parent.body )
        headers = self.updateContentLengthHeader() if self.do_updateClen else str(self.parent.headers)
        self.parent.data = "%s\n\n%s" % (headers, body)
        QApplication.quit()
        return

    def setTabs(self):
        self.tabs = QTabWidget()
        self.tabs.addTab( RawInterceptView(self), "Raw View" )
        self.tabs.addTab( JsonInterceptView(self), "JSON View" )
        self.tabs.addTab( XmlInterceptView(self), "XML View" )
        if "__VIEWSTATE=" in self.parent.body:
            self.tabs.addTab( AspViewstateInterceptView(self), "ViewState View" )

        self.tabs.addTab( OptionsView(self), "Options" )
        return

    def setMainWindowLayout(self):
        headerLayout = QVBoxLayout()
        lurl1 = QLabel("<b>URL</b>")
        lurl2 = QLabel("<p style=color:%s>%s</p>" % ("darkgreen" if self.parent.uri.startswith("https") \
                                                     else "darkred",
                                                     self.parent.uri))
        lheaders = QLabel("<b>Headers</b>")
        self.hdrEditField = QTextEdit()
        self.hdrEditField.insertPlainText( self.parent.headers )
        self.hdrEditField.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.hdrEditField.textChanged.connect(self.updateHeaders )
        headerLayout.addWidget(lurl1)
        headerLayout.addWidget(lurl2)
        headerLayout.addWidget(lheaders)
        headerLayout.addWidget(self.hdrEditField)

        bodyLayout = QVBoxLayout()
        l2 = QLabel("<b>Body</b>")
        bodyLayout.addWidget(l2)
        bodyLayout.addWidget( self.tabs )

        btnLayout = QHBoxLayout()
        btnLayout.addStretch(1)
        cb = QCheckBox("Update 'Content-Length' header")
        cb.stateChanged.connect(self.updateContentLengthState)
        cb.toggle()
        bounceButton = QPushButton("Bounce")
        bounceButton.clicked.connect(self.bounceRequest)
        cancelButton = QPushButton("Cancel")
        cancelButton.clicked.connect(QApplication.quit)
        btnLayout.addWidget(cb)
        btnLayout.addWidget(cancelButton)
        btnLayout.addWidget(bounceButton)

        vbox = QVBoxLayout()
        vbox.addLayout(headerLayout)
        vbox.addLayout(bodyLayout)
        vbox.addLayout(btnLayout)
        self.setLayout(vbox)
        return

    def updateContentLengthState(self, state):
        self.do_updateClen = (state == QtCore.Qt.Checked)
        return

    def updateContentLengthHeader(self):
        headers = str(self.parent.headers).split("\n")
        clen = len(self.parent.body)

        for i in xrange(len(headers)):
            head = str(headers[i])
            if head.startswith("Content-Length"):
                headers.pop(i)
                headers.append("Content-Length: %d" % clen)
                return "\n".join(headers)

        return "\n".join(headers)


class Interceptor(QMainWindow):
    def __init__(self, rid, uri, data):
        super(Interceptor, self).__init__()
        self.rid = rid
        self.uri = uri
        self.title = "Interceptor for proxenet: Request %d" % (rid,)
        self.data = data

        if config.has_option("main", "blacklisted_extensions"):
            blacklist = config.get("main", "blacklisted_extensions").split(" ")
        else:
            blacklist = []

        config.set("main", "__blacklisted", blacklist)

        u = urlparse.urlparse(uri)
        if any( map(lambda x: u.path.endswith(x), blacklist) ):
            return

        if not self.data.endswith("\n\n"):
            self.headers, self.body = self.data.split("\n\n")
        else:
            self.headers, self.body = self.data, ""

        self.setMainWindowProperty()
        self.setMainWindowMenuBar()
        self.setCentralWidget( InterceptorMainWindow( self ) )
        self.show()
        return

    def setMainWindowProperty(self):
        self.setGeometry(150, 150, 960, 600)
        self.setWindowTitle(self.title)

        if config.has_option("main", "style"):
            qtlook = config.get("main", "style")
        else:
            qtlook = "Cleanlooks"
        qApp.setStyle( qtlook )
        return

    def setMainWindowMenuBar(self):
        saveTxtFile = QAction(QIcon(), 'Save As Text file', self)
        saveTxtFile.setShortcut('Ctrl+T')
        saveTxtFile.triggered.connect(self.writeTxtFile)

        savePyFile = QAction(QIcon(), 'Save As Python script', self)
        savePyFile.setShortcut('Ctrl+Y')
        savePyFile.triggered.connect(self.writePyFile)

        fuzzReq = QAction(QIcon(), 'Use \'patator\' on the request', self)
        fuzzReq.setShortcut('Ctrl+P')
        fuzzReq.triggered.connect(self.sendToPatator)

        menubar = self.menuBar()
        fileMenu = menubar.addMenu('&Actions')
        fileMenu.addAction(saveTxtFile)
        fileMenu.addAction(savePyFile)
        fileMenu.addAction(fuzzReq)
        return

    def sendToPatator(self):
        method = self.headers.split(" ")[0].replace('"', '\\"')
        headers = self.headers.split("\n")

        cmd = "patator http_fuzz url=\"{}\" 0=/path/to/wordlist.txt ".format(self.uri)
        cmd+= "method=\"{}\" ".format(method.replace('"', '\\"'))
        for h in headers[1:]:
            cmd+= "header=\"{}\" ".format(h.replace('"', '\\"'))
        if self.body is not None and len(self.body) > 0:
            cmd+= "body=\"{}\" ".format(self.body.replace('"', '\\"'))
        cmd+= "-x ignore:code=404 -x ignore,retry:code=500"

        clip = QApplication.clipboard()
        clip.setText(cmd)
        reply = QtGui.QMessageBox.information(self, "Send to patator",
                                              "Command successfully copied to clipboard!\n"
                                              "Remember to edit fields to fuzz ;)",
                                              QtGui.QMessageBox.Ok)
        return

    def writeTxtFile(self):
        filename = QFileDialog().getSaveFileName(self, "Save Request as Text", os.getenv("HOME"))
        if len(filename) == 0:
            return
        with open(filename, "w") as f:
            f.write(self.data)
        return

    def writePyFile(self):
        filename = QFileDialog().getSaveFileName(self, "Create Python script from Request",os.getenv("HOME"))
        if len(filename) == 0:
            return

        with open(filename, "w") as f:
            o = urlparse.urlparse( self.uri )
            netloc = o.netloc.split(":")[0]
            if o.port is None:
                port = 443 if o.scheme == 'https' else 80
            else:
                port = int(o.port)
            data = self.data.replace("\n", "\r\n")
            f.write('''#!/usr/bin/env python2
#
# Replay script for '{:s}'
#

import socket{:s}

HOST = '{:s}'
PORT = {:d}

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
{:s}
s.connect((HOST, PORT))
s.sendall("""{:s}""")
data = s.recv(1024)
print(data)
s.close()

#
# Proudly generated by '{:s}'
#
'''.format(self.uri,
           ", ssl" if o.scheme=='https' else '',
           netloc,
           port,
           "s = ssl.wrap_socket(s)" if o.scheme=='https' else '',
           data,
           __PLUGIN_NAME__))
        return


def intercept(rid, text, uri):
    global config

    if config is None:
        if not os.access(CONFIG_FILE, os.R_OK):
            print("Creating config file at '%s'" % CONFIG_FILE)
            with open(CONFIG_FILE, "w") as f:
                f.write("[main]\nstyle = Cleanlooks\nblacklisted_extensions = .css .js .jpg .png\n")

        config = ConfigParser.ConfigParser()
        config.read(CONFIG_FILE)

    # this hack is because Qt must run from the main thread
    sparent, schild = socket.socketpair()
    pid = os.fork()
    if pid == 0:
        schild.close()
        app = QApplication([""])
        win = Interceptor(rid, uri, text)
        app.exec_()
        ret = str(win.data)
        sparent.sendall(ret)
        exit(0)

    sparent.close()
    buf = ""
    while True:
        c = schild.recv(1)
        if len(c)==0: break
        buf += c

    (pid, rcode) = os.waitpid(pid, 0)
    return buf


def proxenet_request_hook(request_id, request, uri):
    data = intercept(request_id, request.replace(CRLF, "\n"), uri)
    data = data.replace("\n", CRLF)
    return data


def proxenet_response_hook(response_id, response, uri):
    return response


if __name__ == "__main__":
    vs = '%2fwEPDwUKMTQ2OTkzNDMyMWRkOWxNFeQcY9jzeKVCluHBdzA6WBo%3d'
    # vs = '%2fwEPDwUJODczNjQ5OTk0D2QWAgIDD2QWAgIFDw8WAh4EVGV4dAUWSSBMb3ZlIERvdG5ldEN1cnJ5LmNvbWRkZMHbBY9JqBTvB5%2f6kXnY15AUSAwa'
    # vs = '%2fwEPDwUKMTQ2OTkzNDMyMQ9kFgICAw9kFgICAw8PFgQeBFRleHQFCENsaWNrIG1lHgtDb21tYW5kTmFtZQUDWFhYZGRk7q5i15YA6gDUPW8m%2fIVLqGXnb%2b4%3d'
    uri = "https://foo.bar/bar.asp"
    body = "&".join(["a=b", "b=c", "t=x", "__VIEWSTATE=%s"%vs])
    req = """POST /bar.asp HTTP/1.1\r
Host: foo.bar\r
X-Header: Powered by proxenet\r
Content-Length: %d\r
\r
%s""" % (len(body), body)
    rid = 1337
    print ("="*50)
    print ("BEFORE:\n%s" % req)
    print ('\n' + "="*50 + '\n')
    print ("AFTER:\n%s" % proxenet_request_hook(rid, req, uri))
