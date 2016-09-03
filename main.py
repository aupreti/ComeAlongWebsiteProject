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


class MainHandler(webapp2.RequestHandler):
    def get(self):
    	self.response.write('Hello world!')
    	self.response.write(header_template.render())

app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)
