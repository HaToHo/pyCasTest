import requests
from HTMLParser import HTMLParser
from urlparse import urlparse
from urlparse import parse_qs
import xml.etree.ElementTree as ET

class LoginFormParser(HTMLParser):

    def __init__(self, formId, userId, passwordId):
        self.reset()
        self.hiddenParams = {}
        self.userIdExists = False
        self.passwordIdExists = False
        self.passwordId = passwordId
        self.userId = userId
        self.formId = formId
        self.collectinput = False
        self.collectinputTag = None
        self.action = None
        self.method = None

    def getAttrValue(self, key, attrs):
        for attr in attrs:
            if attr[0].lower() == key.lower():
                return attr[1]
        return None

    def handle_starttag(self, tag, attrs):
        action = None
        method = None
        if tag.lower() == "form":

            for attr in attrs:
                if attr[0].lower() == 'method':
                    method = attr[1]
                if attr[0].lower() == 'action':
                    action = attr[1]
                if attr[0].lower() == 'id' and attr[1] == self.formId:
                    self.collectinput = True
            if self.collectinput:
                self.collectinputTag = tag
                if action is not None:
                    self.action = action
                if method is not None:
                    self.method = method
        if self.collectinput:
            if tag.lower() == "input":
                id = self.getAttrValue("id", attrs)
                if id is None:
                    id = self.getAttrValue("name", attrs)
                if self.getAttrValue("type", attrs) == 'hidden':
                    self.hiddenParams[id] = self.getAttrValue("value", attrs)
                elif self.getAttrValue("type", attrs) == 'text':
                    if id == self.userId:
                        self.userIdExists = True
                elif self.getAttrValue("type", attrs) == 'text' or self.getAttrValue("type", attrs) == 'password':
                    if id == self.passwordId:
                        self.passwordIdExists = True

    def handle_endtag(self, tag):
        if self.collectinputTag == tag:
            self.collectinput = False

class cas(object):
    CONST_INIT_CASLOGIN = "caslogin"
    CONST_CASLOGIN = "/cas/login?service="
    CONST_CAS_VERIFY_TICKET = "/serviceValidate"
    CONST_TICKET = "ticket"
    CONST_SERVICE = "service"

    def __init__(self, casurl, callbackurl, **kwargs):
        self.casurl = casurl
        self.callbackurl = callbackurl
        if cas.CONST_CASLOGIN in kwargs:
            self.caslogin = kwargs[cas.CONST_INIT_CASLOGIN]
        else:
            self.caslogin = cas.CONST_CASLOGIN

    def createRedirectUrl(self):
        cas_url = self.casurl + self.caslogin + self.callbackurl
        return cas_url

    def callRedirectUrl(self, url, formId, usernameId, passwordId, username, password):
        ticket = None
        resp1 = requests.get(url)
        content = str(resp1.content)
        #content = open('../example.html', 'r').read()
        parser = LoginFormParser(formId, usernameId, passwordId)
        parser.feed(content)
        if parser.userIdExists and parser.passwordIdExists and parser.method is not None and parser.action is not None:
            data = {}
            data[parser.userId] = username
            data[parser.passwordId] = password
            for key in parser.hiddenParams:
                data[key] = parser.hiddenParams[key]
            resp2 = None
            callUrl = self.casurl + parser.action
            if parser.method.lower() == "post":
                resp2 = requests.post(callUrl, cookies=resp1.cookies, params=data, allow_redirects=False)
            if parser.method.lower() == "get":
                resp2 = requests.get(callUrl, cookies=resp1.cookies, params=data, allow_redirects=False)
            if resp2 is not None and resp2.headers is not None and 'location' in resp2.headers:
                redirectUrl = resp2.headers['location']
                parsedUrl = urlparse(redirectUrl)
                params = parse_qs(parsedUrl[4])
                if cas.CONST_TICKET in params:
                    ticket = params[cas.CONST_TICKET][0]
        else:
            raise Exception("Can not parse the response!")
        if ticket is None:
            raise Exception("Can not get the ticket!!!")
        return ticket

    def getUserFromTicket(self, ticket):
        data = {}
        data[cas.CONST_TICKET] = ticket
        data[cas.CONST_SERVICE] = self.callbackurl
        resp = requests.get(self.casurl + cas.CONST_CAS_VERIFY_TICKET, params=data)
        root = ET.fromstring(resp.content)
        for l1 in root:
            if 'authenticationSuccess' in l1.tag:
                for l2 in l1:
                    if "user" in l2.tag:
                        return l2.text
        return None

    def handleCallback(self, ticket):
        return self.getUserFromTicket(ticket)


    def performFullCasLogin(self, formId, usernameId, passwordId, username, password):
        redirectUrl = self.createRedirectUrl()
        ticket = self.callRedirectUrl(redirectUrl, formId, usernameId, passwordId, username, password)
        uid = self.handleCallback(ticket)
        if (uid == username):
            print "All is good!"


if __name__=="__main__":
    CAS_SERVER  = "https://cas.umu.se"
    SERVICE_URL = "http://127.0.0.1:5000/"
    casObjeckt = cas(CAS_SERVER, SERVICE_URL)
    casObjeckt.performFullCasLogin('idFormLoginForm', 'usernameID', 'passwordID', 'uid', "password")



