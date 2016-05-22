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
import os

import webapp2
import jinja2

import hmac
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape = True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class Blog(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

class MainHandler(Handler):
    def get(self):
    	blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        self.render("front.html", blogs = blogs)

class BlogHandler(Handler):
	def get(self, blog_id):
		blog = Blog.get_by_id(int(blog_id))
		self.render("blog.html", blog = blog)

class NewPostHandler(Handler):
	def get(self):
		self.render("newpost.html")

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		if subject and content:
			blog = Blog(subject = subject, content = content)
			blog.put()
			id = blog.key().id()
			self.redirect("/blog/%d" % id)
		else:
			error = "Subject and Content, please!"
			self.render("newpost.html", subject=subject, content=content, error=error)

class WelcomeHandler(Handler):
	def get(self):
		username = None
		user_id_cookie_str = self.request.cookies.get('user_id')
		if user_id_cookie_str:
			cookie_val = check_secure_val(user_id_cookie_str)
			if cookie_val:
				username = self.get_user_by_id(int(cookie_val))

		if username:
			self.write("Welcome, " + username)
		else:
			self.redirect("/blog/signup")

	def get_user_by_id(self, user_id):
		user = User.get_by_id(int(user_id))
		return user.username

SECRET = 'imsosecret'
def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

class CookiesHandler(Handler):
	def get(self):
		self.response.headers['Content-Type'] = 'text/plain'
		visits = 0
		visit_cookie_str = self.request.cookies.get('visits')
		if visit_cookie_str:
			cookie_val = check_secure_val(visit_cookie_str)
			if cookie_val:
				visits = int(cookie_val)

		visits += 1

		new_cookie_val = make_secure_val(str(visits))

		self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)
		self.write("You've been here %s times!" % visits)

app = webapp2.WSGIApplication([
    ('/blog', MainHandler),
    ('/blog/newpost', NewPostHandler),
    ('/blog/(\d+)', BlogHandler),
    ('/blog/cookies', CookiesHandler)
], debug=True)
