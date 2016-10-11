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
        self.response.write(header_template.render())
        self.response.write(navbarTemplate.render())
        self.response.write(bodyTemplate.render())
        self.response.write(footer_template.render())

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
        self.response.write(dashboardTemplate.render({'Events': Events}))

class PanelHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(panelTest.render({'Events': Events}))

class NewEventHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(newEventTemplate.render())

class ContactsHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(contactsTemplate.render())



app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/send', SendHandler),
    ('/about.html', AboutHandler),
    ('/contact.html', ContactHandler),
    ('/support.html', SupportHandler),
    ('/terms-of-service.html', TermsOfServiceHandler),
    ('/dashboard.html', DashboardHandler),
    ('/sample.html', PanelHandler),
    ('/new_event.html', NewEventHandler),
    ('/contacts.html', ContactsHandler)

], debug=True)
