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
import re
import hmac
import random
import string
import hashlib
import json
 
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
	return EMAIL_RE.match(email)

def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
	salt = h.split(',')[1]
	return h == make_pw_hash(name, pw, salt)

def blog_to_json(blog):
	blog_json = {}
	blog_json["content"] = blog.content
	blog_json["subject"] = blog.subject
	blog_json["created"] = blog.created.strftime("%a %b %d %H:%M:%S %Y")
	return blog_json

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

class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()

class MainHandler(Handler):
    def get(self):
    	blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        self.render("front.html", blogs = blogs)

class BlogsJsonHandler(Handler):
	def get(self):
		blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
		blogs_json =  []
		for blog in blogs:
			blog_json = blog_to_json(blog)
			blogs_json.append(blog_json)

		self.write(json.dumps(blogs_json))

class BlogHandler(Handler):
	def get(self, blog_id):
		blog = Blog.get_by_id(int(blog_id))
		self.render("blog.html", blog = blog)

class BlogJsonHandler(Handler):
	def get(self, blog_id):
		blog = Blog.get_by_id(int(blog_id))
		blog_json = blog_to_json(blog)
		self.write(json.dumps(blog_json))

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

class SignupHandler(Handler):
	def get(self):
		self.render("signup.html")

	def checkUsername(self, username):
		user = db.GqlQuery("SELECT * FROM User WHERE username = '%s'" % username).get()
		if user:
			return user.username

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")
		
		isValidUsername = valid_username(username)
		if not isValidUsername:
			username_error = "That's not a valid username"
		elif not self.checkUsername(username):
			username_error = "That user already exists"
		else:
			username_error = ""
		
		isValidPassword = valid_password(password)
		if not isValidPassword:
			password_error = "That wasn't a valid password"
		else:
			password_error = ""
		isValidVerify = valid_password(verify)
		if not isValidVerify:
			verify_error = "That wasn't a valid verify password"
		else:
			verify_error = ""

		if isValidPassword and isValidVerify and password != verify:
			isValidVerify = False
			verify_error = "Your passwords didn't match"

		isValidEmail = not email or valid_email(email)
		if isValidEmail:
			email_error = "Not a valid email"
		else:
			email_error = ""
		if isValidUsername and isValidPassword and isValidVerify and isValidEmail:
			h = make_pw_hash(username, password)
			user = User(username=username, password = h, email = email)
			user.put()
			id = user.key().id()
			new_cookie_val = make_secure_val(str(id))
			self.response.headers.add_header('Set-Cookie', 'user_id=%s' % new_cookie_val)
			self.redirect("/blog/welcome")
		else:
			self.render("signup.html", username=username, username_error=username_error, 
				password_error=password_error, verify_error=verify_error, email_error=email_error)

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

class LoginHandler(Handler):
	def get(self):
		self.render('login.html')
	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		user = db.GqlQuery("SELECT * FROM User WHERE username = '%s'" % username).get()
		if user and	valid_pw(username, password, user.password):
			id = user.key().id()
			new_cookie_val = make_secure_val(str(id))
			self.response.headers.add_header('Set-Cookie', 'user_id=%s' % new_cookie_val)
			self.redirect("/blog/welcome")
		else:
			error = "Invalid login"
			self.render("login.html", username=username, error=error)

class LogoutHandler(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		self.redirect("/blog/signup")			

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
    ('/blog.json', BlogsJsonHandler),
    ('/blog/newpost', NewPostHandler),
    ('/blog/(\d+)', BlogHandler),
    ('/blog/(\d+).json', BlogJsonHandler),
    ('/blog/signup', SignupHandler),
    ('/blog/welcome', WelcomeHandler),
    ('/blog/cookies', CookiesHandler),
    ('/blog/login', LoginHandler),
    ('/blog/logout', LogoutHandler)
], debug=True)
