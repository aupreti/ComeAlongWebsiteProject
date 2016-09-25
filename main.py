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


#from apiclient.discovery import build

#from apiclient import discovery #do I need to use this?
#from apiclient.discovery import build # not using it yet



#credentials = flow.step2_exchange(auth_code)
#http_auth = credentials.authorize(httplib2.Http())


#drive_service = build('drive', 'v2', http=http_auth)
#files = drive_service.files().list().execute()


#class CredentialsModel(ndb.Model):
#  credentials = CredentialsProperty()


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

class LoggedInHandler(webapp2.RequestHandler):
    def get(self):
        code = self.request.get('code')

        flow = client.flow_from_clientsecrets(
            'notpublicallyaccessible/client_secrets.json',
            scope='https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/contacts.readonly',
            redirect_uri='http://localhost:9080/loggedin')


        credentialsToStore = flow.step2_exchange(code)

#        http = httplib2.Http()
#        authorizedHttp = credentials.authorize(http)


#        service = build('calendar', 'v3', http=authorizedHttp)

        checkUserExists = CAUser.query(CAUser.username == 'testAudrey').fetch()

        if not checkUserExists:

            secretToStore = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(30))

            newUser = CAUser(userID=1, username='testAudrey', gmail='implementlater?', facebook='NA', credentials = credentialsToStore, secret = secretToStore)

            newUser.put()

            #header = {
            #          "alg": "HS256",
            #          "typ": "JWT"
            #        }
            #payload = {
            #              "sub": "1234567890",
            #              "name": "John Doe",
            #              "admin": true
            #            }

            #signature = HMACSHA256( base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)

            # how I think the function from pyjwt works
            # encoded = jwt.encod(payload, 'secret used to sign the signature', algorithm = 'HS256')
            # jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256', headers={'kid': '230498151c214b788dd97f22b85410a5'})

            CAUser.query(CAUser.username == 'testAudrey').fetch()


            encoded = jwt.encode({'usr': 'testAudrey'}, secret, algorithm='HS256')



            request = Request.blank('/')
            request.headers['Cookie'] = 'CASession=' + encoded

            # A value: 'value'
            cookie_value = request.cookies.get('CASession')





            uncheckedPayload_String = jwt.decode(encoded, verify=False)

            # for now just assume there are no hackers --> need to implement a try and exception to when reading the uncheckedPayload or peeps can put in malicious code in?

            uncheckedPayload_Dict = ast.literal_eval(uncheckedPayload_String)

            userClaimsToBe = uncheckedPayload["usr"]

            secretToTestUserClaim = CAUser.query(CAUser.username == userClaimsToBe).fetch().secret


            try:
                jwt.decode(encoded, secretToTestUserClaim, algorithms=['HS256'])

            except:
                "You fucking hacker."


    #        storage = StorageByKeyName(CredentialsModel, 'ahBkZXZ-Y29tZWFsb25nd2VichMLEgZDQVVzZXIYgICAgIDArwsM', 'credentials')
    #        storage.put(credentialsStore)

    #        user = users.get_current_user()
    #        storage = StorageByKeyName(CAUser, 1, 'credentials')
    #        storage.put(credentials)



        self.response.write(page2_template.render())



class LogInHandler(webapp2.RequestHandler):
    def get(self):
        flow = client.flow_from_clientsecrets(
            'notpublicallyaccessible/client_secrets.json',
            scope='https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/contacts.readonly',
            redirect_uri='http://localhost:9080/loggedin')

        auth_uri = flow.step1_get_authorize_url() # creates the url that brings users to gmail's authenticate page, I think.
        self.redirect(str(auth_uri))

class TestHandler(webapp2.RequestHandler):
    def get(self):
        testpage_template = JINJA_ENVIRONMENT.get_template('notpublicallyaccessible/testpage.html')
        self.response.write(testpage_template.render())




app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/loginrequest', LogInHandler),
    ('/loggedin', LoggedInHandler),
    ('/testpage', TestHandler)
], debug=True)

#    ('/oauth2callback', OAuth2Handler)
