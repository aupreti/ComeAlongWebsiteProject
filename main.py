#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


import webapp2
import os
import jinja2
import logging

from google.appengine.ext import db #the old one??? idk
from google.appengine.ext import ndb
from oauth2client.contrib.appengine import CredentialsNDBProperty
from oauth2client.contrib.appengine import StorageByKeyName

import oauth2client
from oauth2client import client

import httplib2

import jwt

import random
import string

import ast

from apiclient.discovery import build

#from apiclient import discovery #do I need to use this?
#from apiclient.discovery import build # not using it yet

import json

#credentials = flow.step2_exchange(auth_code)
#http_auth = credentials.authorize(httplib2.Http())


#drive_service = build('drive', 'v2', http=http_auth)
#files = drive_service.files().list().execute()


#class CredentialsModel(ndb.Model):
#  credentials = CredentialsProperty()


flow = client.flow_from_clientsecrets(
    'notpublicallyaccessible/client_secrets.json',
    scope='https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/contacts.readonly',
    redirect_uri='http://localhost:9080/loggedin')


class CAUser(ndb.Model):
    userID = ndb.IntegerProperty()
    username = ndb.StringProperty()
    gmail = ndb.StringProperty()
    facebook = ndb.StringProperty()
    credentials = CredentialsNDBProperty()
    secret = ndb.StringProperty()


#setup JINJA environment
JINJA_ENVIRONMENT = jinja2.Environment (
    loader = jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions = ['jinja2.ext.autoescape'],
    autoescape = True # safety measure. prevents sql injection
)

#jinja template variables
header_logged_in_template = JINJA_ENVIRONMENT.get_template('templates/header_loggedin.html')
header_logged_out_template = JINJA_ENVIRONMENT.get_template('templates/header_loggedout.html')


footer_logged_in_template = JINJA_ENVIRONMENT.get_template('templates/footer_loggedin.html')
footer_logged_out_template = JINJA_ENVIRONMENT.get_template('templates/footer_loggedout.html')

page1_template = JINJA_ENVIRONMENT.get_template('templates/page1.html')
page2_template = JINJA_ENVIRONMENT.get_template('templates/page2.html')
dashboard_template = JINJA_ENVIRONMENT.get_template('templates/dashboard.html')
hiHacker_template = JINJA_ENVIRONMENT.get_template('templates/hiHacker.html')

loggedIn = False

class MainHandler(webapp2.RequestHandler):
    def get(self):
#    	self.response.write('Hello world!!!!')
#    	self.response.write(header_template.render())
#        if loggedIn is True:
#            self.response.write(page2_template.render())
#        else:
#            self.response.write(page1_template.render())
        self.response.write(page1_template.render())
#        logging.info('hi there')
#        logging.info(os.path.dirname(__file__))




class LogInHandler(webapp2.RequestHandler):
    def get(self):
        auth_uri = flow.step1_get_authorize_url() # creates the url that brings users to gmail's authenticate page, I think.
        self.redirect(str(auth_uri))



class LoggedInHandler(webapp2.RequestHandler):
    def get(self):
        # url header will have a name called code
        code = self.request.get('code')

        # flow is stored above
        credentialsToStore = flow.step2_exchange(code)
        credentials = credentialsToStore

        #logging.info("The credentials to json")
        #logging.info(credentialsToStore.to_json())

#        http = httplib2.Http()
#        authorizedHttp = credentials.authorize(http)


#        service = build("people", "v1", http=authorizedHttp)

#        http_auth = credentials.authorize(httplib2.Http())
#        drive_service = discovery.build('drive', 'v2', http_auth)
#        files = drive_service.files().list().execute()
#        return json.dumps(files)



#        checkUserExists = CAUser.query(CAUser.username == 'testAudrey').fetch()

        checkUserExists = CAUser.query(CAUser.username == 'testAudrey').get()


        if not checkUserExists:

            secretToStore = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(30))

            newUser = CAUser(userID=1, username='testAudrey', gmail='implementlater?', facebook='NA', credentials = credentialsToStore, secret = secretToStore)

            newUser.put()

            # how I think the function from pyjwt works
            # encoded = jwt.encod(payload, 'secret used to sign the signature', algorithm = 'HS256')
            # jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256', headers={'kid': '230498151c214b788dd97f22b85410a5'})

#            CAUser.query(CAUser.username == 'testAudrey').fetch()


            encodedJWT = jwt.encode({'sub': 'testAudrey'}, secretToStore, algorithm='HS256')
            encodedJWT_String = encodedJWT.decode('utf-8')
            self.response.set_cookie("session", encodedJWT_String) #, secure=True)

            # this is used to request the cookie. duh
#                request = Request.blank('/')
#                request.headers['Cookie'] = 'CASession=' + str(encoded, 'utf-8')
#                cookie_value = request.cookies.get('CASession')

###########################################################################
#            request = Request.blank('/')
#            request.headers['Cookie'] = 'test=value'
#
#            # A value: 'value'
#            cookie_value = request.cookies.get('test')
############################################################################


    #        storage = StorageByKeyName(CredentialsModel, 'ahBkZXZ-Y29tZWFsb25nd2VichMLEgZDQVVzZXIYgICAgIDArwsM', 'credentials')
    #        storage.put(credentialsStore)

    #        user = users.get_current_user()
    #        storage = StorageByKeyName(CAUser, 1, 'credentials')
    #        storage.put(credentials)
        else:
            encodedJWT = jwt.encode({'sub': 'testAudrey'}, checkUserExists.secret, algorithm='HS256')
            encodedJWT_String = encodedJWT.decode('utf-8')
            self.response.set_cookie("session", encodedJWT_String)

        self.response.write(page2_template.render())







class CookieTestHandler(webapp2.RequestHandler):
    def get(self):

        encodedJWT = jwt.encode({'sub': 'testAudrey'}, "secret", algorithm='HS256')

        self.response.set_cookie("session", str(encodedJWT, 'utf-8'), secure=True)


#        self.response.set_cookie('cookieTest', 'User Audrey Is Online.')
#        cookie = self.request.cookies.get('cookieTest')
#        logging.info("cookie info is")
#        logging.info(cookie)

        jwt = self.request.cookies.get("session")
        logging.info("jwt info is")
        logging.info(jwt)


class CookieSetHandler(webapp2.RequestHandler):
    def get(self):
        encodedJWT = jwt.encode({'sub': 'testAudrey'}, "secret", algorithm='HS256')
        encodedJWT_String = encodedJWT.decode('utf-8')
        self.response.set_cookie("session", encodedJWT_String)



class BadCookieSetHandler(webapp2.RequestHandler):
    def get(self):
        #self.response.set_cookie("session", "aaa.bbb.ccc")
        #self.response.set_cookie("session", "asdf")

        #jwt.encode({'aud': 'testAudrey'}, "i8gaYMTMlWi0nhsbmktNM5iqxgfJpn", algorithm='HS256')
        #self.response.set_cookie("session", 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJ0ZXN0QXVkcmV5In0.TCHDqEKFEtRefeaDt0sjB36abbMUVfHl9KLCOB6g34g')

        #jwt.encode({'sub': 'audrey'}, "i8gaYMTMlWi0nhsbmktNM5iqxgfJpn", algorithm='HS256')
        #self.response.set_cookie("session", 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdWRyZXkifQ.A8w1SUtdzb4eBisYNfBJ_dcoPOT_sfpuJjMFdt3DXVI')

        #jwt.encode({'sub': 'testAudrey'}, "wrongsecret", algorithm='HS256')
        #self.response.set_cookie("session", 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0QXVkcmV5In0._-1mkoK1Fai47U7jK-McierV2hL36QAK6IWfKWjoCus')

        #jwt.encode({'sub': 'testAudrey'}, "", algorithm='HS256')
        self.response.set_cookie("session", 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0QXVkcmV5In0.1CVU9bn4HDGEnWh36lDP7ukoJy016b5AhoqYv5EC_1M')



class DeleteCookieHandler(webapp2.RequestHandler):
    def get(self):
        self.response.delete_cookie("session")

class CookieCheckHandler(webapp2.RequestHandler):
    def get(self):
        jwt = self.request.cookies.get("session")
        logging.info("jwt info is")
        logging.info(jwt)




class EmptySecret(Exception):
   pass


class TestHandler(webapp2.RequestHandler):
    def get(self):
        #testpage_template = JINJA_ENVIRONMENT.get_template('notpublicallyaccessible/testpage.html')  ---> this was from a previous experiment

        # this test page tests if the jwt login and logout works
        encodedJWT = self.request.cookies.get("session")

        # ways login check can fail:
        # 1) There is no jwt stored;
        # 2) The jwt is nonsense (e.g. aaa.bbb.ccc), jwt.decode() will throw an error -> need to handle that (this also emcompases other jwt errors like a jwt that is "asdf" i.e. only one segment long)
        # 3) The jwt is modified so it doesn't contain the claim "sub".
        # 4) THe jwt is modified so that "sub"/user does not exist in the database
        # 5) The jwt is modified so that while the user does exist in the database the secret does not match.
        # 6) What if no secret is stored in the database?  ---> It actually passes. So when we log the user out, we never delete the secret in the database, but when the user logs back in, we just rewrite over the exisitng secret. This is important!! Or someone could just create and stored a jwt with the secret being empty, and it will be able to pass our checks. Other things to keep note of then, with only one secret being stored, and the secret being reissued each time, a user can't be logged in to more than one device. The only way is if the secret is permanent for each user, so when the user logs in, we merely retrieve the secret and reissue the jwt.  --> maybe put in an extra safe security check in the future to check if the secret in database is empty

        # need to consider in the future if malicious code will be run when reading the uncheckedPayload if code was stored in the jwt -> maybe have some sort of try and except?


        if encodedJWT is None:
            # is no jwt is stored, redirect user to login page
            logging.info("No jwt found.")
            return self.redirect("/")

        try:
            uncheckedPayload = jwt.decode(encodedJWT, verify=False)
            userClaimsToBe = uncheckedPayload["sub"]

            secretToTestUserClaim = CAUser.query(CAUser.username == userClaimsToBe).get().secret       #.fetch()  #.secret()
            # get just gets the first instance. Fetch gets all the instances.

            if secretToTestUserClaim == "":
                raise EmptySecret

            try:
                jwt.decode(encodedJWT, secretToTestUserClaim, algorithms=["HS256"])

            except jwt.DecodeError as e:
                logging.info("Verification of jwt failed because secret in jwt did not match secret in database (see no. 5).")
                logging.info(e)
                self.response.delete_cookie("session")
                self.response.write(hiHacker_template.render())

            else:
                # Yay verification has passed! User identified and logged in.
                self.response.write(dashboard_template.render())

        except jwt.DecodeError as e:
            logging.info("Invalid jwt. Jwt decoder had trouble decoding jwt. Examples of jwts that could cause this error is aaa.bbb.ccc (see no. 2 in list). See specific error message by jwt library below:")
            logging.info(e) # for some reason this logs things twice
            self.response.delete_cookie("session")
            self.response.write(hiHacker_template.render())

        except KeyError:
            logging.info("The sub claim was not found in the payload. Invalid jwt. (See no. 3)")
            self.response.delete_cookie("session")
            self.response.write(hiHacker_template.render())

        except AttributeError:
            # CAUser.query(CAUser.username == userClaimsToBe).get() returns a None object if the username does not exist in the database. Since it is a None object, secret raises an AttributeError.
            logging.info("User contained in jwt was not found in database. Invalid jwt. (See no. 4)")
            self.response.delete_cookie("session")
            self.response.write(hiHacker_template.render())

        except EmptySecret:
            logging.info("secret for user is empty (see no. 6). The user being:")
            logging.info(userClaimsToBe)
            self.response.delete_cookie("session")
            self.response.write(hiHacker_template.render())

        except Exception as e:
            logging.info("Unexpected jwt problem occured. See below:")
            logging.info(e)
            self.response.delete_cookie("session")
            self.response.write(hiHacker_template.render())



class LogoutHandler(webapp2.RequestHandler):
    def get(self):
        # given error/issue number 6 for the login jwt considerations, I suppose this is all the line of code we need for logging out.
        self.response.delete_cookie('session')
        self.redirect("/")



class RandomTestHandler(webapp2.RequestHandler):
    def get(self):
#        user = CAUser.query(CAUser.username == 'testAudrey').get()
#        logging.info(user.secret)
#        if user.secret is None:
#            logging.info('hwere')
#        elif user.secret == "":
#            logging.info('adf')
#        else:
#            logging.infO("aasdfas")

        formtest_template = JINJA_ENVIRONMENT.get_template('templates/formtest.html')
        self.response.write(formtest_template.render())

    def post(self):
        username = self.request.get("username")
        logging.info(username)
        self.response.write("Hi there your response has been recorded.")



def setSession():
    pass

def getSession():
    pass


class Test2Handler(webapp2.RequestHandler):
    def get(self):
        user = CAUser.query(CAUser.username == 'testAudrey').get()

        credentials = user.credentials

        http = httplib2.Http()
        authorizedHttp = credentials.authorize(http)
#        service = build("people", "v1", http=authorizedHttp)
        people_service = build(serviceName='people', version='v1', http=authorizedHttp)
        profile = people_service.people().get(resourceName='people/me').execute()
#        profile = people_service.people().get('people/me')
#        profile = service.people().get('people/me')

        logging.info(json.dumps(profile, sort_keys=True, indent=4))



app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/loginrequest', LogInHandler),
    ('/loggedin', LoggedInHandler),
    ('/testpage', TestHandler),
    ('/cookieTest', CookieTestHandler),
    ('/setCookie', CookieSetHandler),
    ('/getCookie', CookieCheckHandler),
    ('/getBadCookie', BadCookieSetHandler),
    ('/deleteCookie', DeleteCookieHandler),
    ('/test2', Test2Handler),
    ('/logout', LogoutHandler),
    ('/randomTest', RandomTestHandler)
], debug=True)

#    ('/oauth2callback', OAuth2Handler)

# cookieTest, setCookie, getCookie, and getBadCookie are all for testing purposes. Ignore them.
