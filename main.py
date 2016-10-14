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

import webapp2
import jinja2
import os
import logging
from google.appengine.ext import ndb
from google.appengine.api import users
import json
import datetime

###################### Backend Specific libraries ##############################
import oauth2client
from oauth2client.contrib.appengine import CredentialsNDBProperty
from oauth2client.contrib.appengine import StorageByKeyName
from oauth2client import client
import httplib2
import jwt
import random
import string
import ast
from apiclient.discovery import build
################################################################################


JINJA_ENVIRONMENT = jinja2.Environment (
    loader = jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions = ['jinja2.ext.autoescape'],
    autoescape = True # safety measure. prevents sql injection
)

header_template = JINJA_ENVIRONMENT.get_template('templates/header.html')
footer_template = JINJA_ENVIRONMENT.get_template('templates/footer.html')
navbarTemplate = JINJA_ENVIRONMENT.get_template('templates/navbar.html')
bodyTemplate = JINJA_ENVIRONMENT.get_template('templates/body.html')
aboutTemplate = JINJA_ENVIRONMENT.get_template('templates/about.html')
contactTemplate = JINJA_ENVIRONMENT.get_template('templates/contact.html')
supportTemplate = JINJA_ENVIRONMENT.get_template('templates/support.html')
termsOfServiceTemplate = JINJA_ENVIRONMENT.get_template('templates/terms-of-service.html')
dashboardTemplate = JINJA_ENVIRONMENT.get_template('templates/dashboard.html')
panelTest = JINJA_ENVIRONMENT.get_template('templates/sample.html')
newEventTemplate = JINJA_ENVIRONMENT.get_template('templates/new_event.html')
contactsTemplate = JINJA_ENVIRONMENT.get_template('templates/contacts.html')


#### temp template. Please make new 404(?) error page###########################
hiHacker_template = JINJA_ENVIRONMENT.get_template('templates/hiHacker.html')
#################################################################################


Events = [
    {'event_title': 'Tyler With the Lab team?',
    'event_host': 'aupreti',
    'votes': 5,
    'response_rate': 75,
    'top_response': 'No',
    'top_response_votes': 2,
    'description': 'Anim pariatur cliche reprehenderit, \
    enim eiusmod high life accusamus terry richardson \
    ad squid. 3 wolf moon officia aute, non cupidatat \
    skateboard dolor brunch. Food truck quinoa nesciunt \
    laborum eiusmod. Brunch 3 wolf',
    'accordion': 1,
    'no': 2,
    'yes': 4},

    {'event_title': 'Holyoke Mall at 10pm?',
    'event_host': 'aong',
    'description': 'Anim pariatur cliche reprehenderit, \
    enim eiusmod high life accusamus terry richardson \
    ad squid. 3 wolf moon officia aute, non cupidatat \
    skateboard dolor brunch. Food truck quinoa nesciunt \
    laborum eiusmod. Brunch 3 wolf',
    'response_rate': 65,
    'top_response': 'Yes',
    'top_response_votes': 10,
    'votes': 4,
    'accordion': 2,
    'no': 2,
    'yes': 4},

    {'event_title': 'Where do you all want to meet for dinner?',
    'event_host': 'jniu',
    'description': 'Anim pariatur cliche reprehenderit, \
    enim eiusmod high life accusamus terry richardson \
    ad squid. 3 wolf moon officia aute, non cupidatat \
    skateboard dolor brunch. Food truck quinoa nesciunt \
    laborum eiusmod. Brunch 3 wolf',
    'response_rate': 55,
    'top_response': 'Chapin',
    'top_response_votes': 4,
    'votes': 3,
    'accordion': 3,
    'no': 2,
    'yes': 4},
]


class SendHandler(webapp2.RequestHandler):
    def post(self):
        self.redirect("/")

class MainHandler(webapp2.RequestHandler):
    def get(self):
        # this may return a continous loop between MainHandler and GoogleLoginHandler if not careful
        # as long as getSession(self) wipes the jwt everytime it does not return True, it should be fine.

        encodedJWT = self.request.cookies.get("session")
        if encodedJWT is None:
            self.response.write(header_template.render())
            self.response.write(navbarTemplate.render())
            self.response.write(bodyTemplate.render())
            self.response.write(footer_template.render())

        elif getSession(self):
            self.redirect('/dashboard')


class AboutHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(header_template.render())
        self.response.write(navbarTemplate.render())
        self.response.write(aboutTemplate.render())
        self.response.write(footer_template.render())

class ContactHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(header_template.render())
        self.response.write(navbarTemplate.render())
        self.response.write(contactTemplate.render())
        self.response.write(footer_template.render())

class SupportHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(header_template.render())
        self.response.write(navbarTemplate.render())
        self.response.write(supportTemplate.render())
        self.response.write(footer_template.render())

class TermsOfServiceHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(header_template.render())
        self.response.write(navbarTemplate.render())
        self.response.write(termsOfServiceTemplate.render())
        self.response.write(footer_template.render())

class DashboardHandler(webapp2.RequestHandler):
    def get(self):
        # anything that requires login do "if getSession(self):"
        if getSession(self):
            self.response.write(dashboardTemplate.render({'Events': Events}))

class PanelHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(panelTest.render({'Events': Events}))

class NewEventHandler(webapp2.RequestHandler):
    def get(self):
        if getSession(self):
            self.response.write(newEventTemplate.render())

class ContactsHandler(webapp2.RequestHandler):
    def get(self):
        if getSession(self):
            self.response.write(contactsTemplate.render())


############################## Backend Code ###################################

flow = client.flow_from_clientsecrets(
    'notpublicallyaccessible/client_secrets.json',
    scope='https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/contacts.readonly',
    redirect_uri='http://localhost:10080/googlelogin')


class CAUser(ndb.Model):
    userID = ndb.IntegerProperty()
    username = ndb.StringProperty()
    gmail = ndb.StringProperty()
    facebook = ndb.StringProperty()
    credentials = CredentialsNDBProperty()
    secret = ndb.StringProperty()


class EmptySecret(Exception):
   pass


def getSession(self):
    # returns True if user is logged in, and returns False if user is not logged in, or jwt is tampered with.

    # ways login check can fail:
    # 1) There is no jwt stored;
    # 2) The jwt is nonsense (e.g. aaa.bbb.ccc), jwt.decode() will throw an error -> need to handle that (this also emcompases other jwt errors like a jwt that is "asdf" i.e. only one segment long)
    # 3) The jwt is modified so it doesn't contain the claim "sub".
    # 4) THe jwt is modified so that "sub"/user does not exist in the database
    # 5) The jwt is modified so that while the user does exist in the database the secret does not match.
    # 6) What if no secret is stored in the database?  ---> It actually passes. So when we log the user out, we never delete the secret in the database, but when the user logs back in, we just rewrite over the exisitng secret. This is important!! Or someone could just create and stored a jwt with the secret being empty, and it will be able to pass our checks. Other things to keep note of then, with only one secret being stored, and the secret being reissued each time, a user can't be logged in to more than one device. The only way is if the secret is permanent for each user, so when the user logs in, we merely retrieve the secret and reissue the jwt.  --> maybe put in an extra safe security check in the future to check if the secret in database is empty

    # need to consider in the future if malicious code will be run when reading the uncheckedPayload if code was stored in the jwt -> maybe have some sort of try and except?

    encodedJWT = self.request.cookies.get("session")

    if encodedJWT is None:
        # is no jwt is stored, redirect user to login page
        logging.info("No jwt found.")
        self.redirect("/")
        return False

    try:
        uncheckedPayload = jwt.decode(encodedJWT, verify=False)
        userClaimsToBe = uncheckedPayload["sub"]
        secretToTestUserClaim = CAUser.query(CAUser.username == userClaimsToBe).get().secret

        if secretToTestUserClaim == "":
            raise EmptySecret

        try:
            jwt.decode(encodedJWT, secretToTestUserClaim, algorithms=["HS256"])

        except jwt.DecodeError as e:
            logging.info("Verification of jwt failed because secret in jwt did not match secret in database (see no. 5).")
            logging.info(e)
            self.response.delete_cookie("session")
            self.response.write(hiHacker_template.render())
            return False

        else:
            # Yay verification has passed! User identified and logged in.
            return True

    except jwt.DecodeError as e:
        logging.info("Invalid jwt. Jwt decoder had trouble decoding jwt. Examples of jwts that could cause this error is aaa.bbb.ccc (see no. 2 in list). See specific error message by jwt library below:")
        logging.info(e) # for some reason this logs things twice
        self.response.delete_cookie("session")
        self.response.write(hiHacker_template.render())
        return False

    except KeyError:
        logging.info("The sub claim was not found in the payload. Invalid jwt. (See no. 3)")
        self.response.delete_cookie("session")
        self.response.write(hiHacker_template.render())
        return False

    except AttributeError:
        # CAUser.query(CAUser.username == userClaimsToBe).get() returns a None object if the username does not exist in the database. Since it is a None object, secret raises an AttributeError.
        logging.info("User contained in jwt was not found in database. Invalid jwt. (See no. 4)")
        self.response.delete_cookie("session")
        self.response.write(hiHacker_template.render())
        return False

    except EmptySecret:
        logging.info("secret for user is empty (see no. 6). The user being:")
        logging.info(userClaimsToBe)
        self.response.delete_cookie("session")
        self.response.write(hiHacker_template.render())
        return False

    except Exception as e:
        logging.info("Unexpected jwt problem occured. See below:")
        logging.info(e)
        self.response.delete_cookie("session")
        self.response.write(hiHacker_template.render())
        return False

    logging.info("getSession shouldn't reach here. Critical error detected. Send help.")
    self.response.delete_cookie("session")
    return False



class GoogleLoginHandler(webapp2.RequestHandler):
    def get(self):
        code = self.request.get('code')

        if code == "":
            auth_uri = flow.step1_get_authorize_url()
            self.redirect(str(auth_uri))

        else:
            credentialsToStore = flow.step2_exchange(code)
            credentials = credentialsToStore

            checkUserExists = CAUser.query(CAUser.username == 'audrey').get()

            if not checkUserExists:
                secretToStore = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(30))
                newUser = CAUser(userID=1, username='audrey', gmail='implementlater?', facebook='NA', credentials = credentialsToStore, secret = secretToStore)
                newUser.put()
                encodedJWT = jwt.encode({'sub': 'audrey'}, secretToStore, algorithm='HS256')
                encodedJWT_String = encodedJWT.decode('utf-8')
                self.response.set_cookie("session", encodedJWT_String)

            else:
                encodedJWT = jwt.encode({'sub': 'audrey'}, checkUserExists.secret, algorithm='HS256')
                encodedJWT_String = encodedJWT.decode('utf-8')
                self.response.set_cookie("session", encodedJWT_String)

            self.redirect('/dashboard')


class FacebookLoginHandler(webapp2.RequestHandler):
    def get(self):
        pass


class LogoutHandler(webapp2.RequestHandler):
    def get(self):
        # given error/issue number 6 for the login jwt considerations, I suppose this is all the line of code we need for logging out.
        self.response.delete_cookie('session')
        self.redirect("/")


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/send', SendHandler),
    ('/about', AboutHandler),
    ('/contact', ContactHandler),
    ('/support', SupportHandler),
    ('/terms-of-service', TermsOfServiceHandler),
    ('/dashboard', DashboardHandler),
    ('/sample', PanelHandler),
    ('/new_event', NewEventHandler),
    ('/contacts', ContactsHandler),
    ('/googlelogin', GoogleLoginHandler),
    ('/facebooklogin', FacebookLoginHandler),
    ('/logout', LogoutHandler)

], debug=True)
