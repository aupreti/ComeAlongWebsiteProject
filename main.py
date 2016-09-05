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

class SendHandler(webapp2.RequestHandler):
    def post(self):
        self.redirect("/")

class MainHandler(webapp2.RequestHandler):
    def get(self):
        bodyTemplate = JINJA_ENVIRONMENT.get_template('templates/body.html')
        self.response.write(header_template.render())
        self.response.write(bodyTemplate.render())
        self.response.write(footer_template.render())

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    #('/notify', NotifyHandler),
    ('/send', SendHandler),
], debug=True)
