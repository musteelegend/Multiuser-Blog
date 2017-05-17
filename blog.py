import os
import re
import random
import hashlib
import hmac
import time
from functools import wraps
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'mustlegend'


def post_exists(function):
    @wraps(function)
    def wrapper(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        else:
            return function(self, post_id, post)
    return wrapper


def comment_post_exists(function):
    @wraps(function)
    def wrapper(self, post_id, comment_id):
        key1 = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        key2 = db.Key.from_path('Post', int(post_id), parent=blog_key())
        comment = db.get(key1)
        post = db.get(key2)
        if comment and post:
            return function(self, post_id, comment_id, comment, post)
        else:
            self.error(404)
            return
    return wrapper


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


# User information validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Cookie stuff
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# Creating User Datastore
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# Creating Post datastore
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user = db.IntegerProperty()
    blogger_name = db.StringProperty()
    liked_by = db.ListProperty(str)
    unliked_by = db.ListProperty(str)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


# Creating Likes datastore
class LikePost(db.Model):
        postid = db.IntegerProperty(required=True)
        post = db.ReferenceProperty(Post, collection_name='Likes')


# Creating Unlike datastore
class UnlikePost(db.Model):
        postid = db.IntegerProperty(required=True)
        post = db.ReferenceProperty(Post, collection_name='Unlikes')


# Creating Comment datastore
class Comment(db.Model):
        comment = db.StringProperty(required=True)
        cAuthor = db.StringProperty(required=True)
        created_ = db.DateTimeProperty(auto_now_add=True)
        post = db.ReferenceProperty(Post, collection_name='comments')


# Polulatng Myblog page
class MyBlogs(BlogHandler):
    def get(self):
        if not self.user:
            self.redirect("/login")
        else:
            user_id = self.user.key().id()
            posts = Post.all().filter('user =',  user_id).order("-created")
            self.render('front.html', posts=posts)


# Polulating the main blog page
class MainPost(BlogHandler):
    def users_key(group='default'):
        return db.Key.from_path('users', group)

    def get(self):
        post_db = Post.all().order("-created")
        self.render("front.html", posts=post_db)


# Permalink page for a single post
class SinglePostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


# Page to create a new post
class NewPost(BlogHandler):
    def get(self):
        if not self.user:
            self.redirect("/login")
        else:
            self.render("newpost.html")

    def post(self):
        if not self.user:
            self.redirect('/login')
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            get_user_id = self.user.key().id()
            blogger_username = self.user.name

            if subject and content:
                p = Post(parent=blog_key(), subject=subject, content=content,
                         user=get_user_id, blogger_name=blogger_username)
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                error = "subject and content, please!"
                self.render("newpost.html", subject=subject, content=content,
                            error=error)


# Signup page where user information is collected
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)


# Registration validation
class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            time.sleep(.5)
            self.redirect('/blog')


# Login page handle
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            time.sleep(.5)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


# Logout page handle
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/login')


# Deleting a post

class DeletePost(BlogHandler):
    @post_exists
    def post(self, post_id, post):
        if not self.user:
            self.redirect('/login')
        else:
            # key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            # post = db.get(key)
            # print(post)
            referer = self.request.referer
            if (post.blogger_name == self.user.name):
                db.delete(key)
                time.sleep(.5)
                self.redirect(referer)
            else:
                error_msg = "Sorry, you can only delete your own posts."
                self.render('error.html', error=error_msg, referer=referer)


# Liking a post
class Like(BlogHandler):
        def get(self, post_id):
            if not self.user:
                    self.redirect('/login')
            else:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                referer = self.request.referer
                blogger = post.blogger_name
                currentUser = self.user.name
                error_msg = "Sorry, you cannot Like your own posts."
                if(blogger == currentUser):
                    self.render('error.html', error=error_msg, referer=referer)
                elif (currentUser in post.liked_by):
                    error_msgg = "You have already Likes this post"
                    self.render("error.html", error=error_msgg,
                                referer=referer)
                elif (currentUser in (post.liked_by or post.unliked_by)):
                    error_msggg = "You can't both like and unlike a post"
                    self.render("error.html", error=error_msggg,
                                referer=referer)
                else:
                    post.liked_by.append(currentUser)
                    post.put()
                    like = LikePost(postid=int(post_id), post=post.key(),
                                    parent=blog_key())
                    like.put()
                    time.sleep(.5)
                    self.redirect(referer)


# Unliking a post
class Unlike(BlogHandler):
        def get(self, post_id):
            if not self.user:
                    self.redirect('/login')
            else:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                referer = self.request.referer
                blogger = post.blogger_name
                currentUser = self.user.name
                error_msg = "Sorry, you cannot Unlike your own posts."
                if(blogger == currentUser):
                    self.render('error.html', error=error_msg, referer=referer)
                elif (currentUser in post.unliked_by):
                    error_msgg = "You have already Unlikes this post"
                    self.render("error.html", error=error_msgg,
                                referer=referer)
                elif (currentUser in (post.liked_by or post.unliked_by)):
                    error_msggg = "You can't both like and unlike a post"
                    self.render("error.html", error=error_msggg,
                                referer=referer)
                else:
                    post.unliked_by.append(currentUser)
                    post.put()
                    unlike = UnlikePost(postid=int(post_id), post=post.key(),
                                        parent=blog_key())
                    unlike.put()
                    time.sleep(.5)
                    self.redirect(referer)


# Creating a new comment for a post
class NewComment(BlogHandler):
    def get(self, post_id):
        if not self.user:
            return self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            else:
                subject = post.subject
                content = post.content
                self.render("newcomment.html", subject=subject,
                            content=content)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            else:
                comment = self.request.get('comment')
                if comment:
                    U = User.by_name(self.user.name)
                    c = Comment(comment=comment, cAuthor=U.name, post=key,
                                parent=blog_key())
                    c.put()
                    self.redirect('/blog/%s' % str(post_id))
                else:
                    error = "please enter a comment"
                    self.render("newcomment.html", comment=comment,
                                error=error)


# Editing a post
class EditPost(BlogHandler):
    def get(self, post_id):
        referer = self.request.referer
        if not self.user:
            return self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if (post.blogger_name == self.user.name):
                error = ""
                self.render("editpost.html", subject=post.subject,
                            content=post.content, error=error)
            else:
                error_msg = "You can't edit a post you did not create."
                self.render("error.html", error=error_msg, referer=referer)

    def post(self, post_id):
        refererr = self.request.referer
        if not self.user:
            return self.redirect('/login')
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            if subject and content:
                key = db.Key.from_path('Post', int(post_id),
                                       parent=blog_key())
                edit_post = db.get(key)
                if not edit_post:
                    self.error(404)
                    return
                if (edit_post.blogger_name == self.user.name):
                    edit_post.subject = subject
                    edit_post.content = content
                    edit_post.put()
                    self.redirect('/blog/%s' % str(edit_post.key().id()))
                else:
                    error_msgg = "You can't edit a post you did not create"
                    self.render("error.html", error=error_msgg,
                                referer=refererr)
            else:
                error = "subject and content, please!"
                self.render("newpost.html", subject=subject, content=content,
                            error=error)


# Editing a comment
class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        referer = self.request.referer
        if not self.user:
            return self.redirect('/login')
        else:
            post = Post.get_by_id(int(post_id), parent=blog_key())
            if not post:
                self.error(404)
                return
            comment = Comment.get_by_id(int(comment_id), parent=blog_key())
            if not comment:
                self.error(404)
                return
            if (comment.cAuthor == self.user.name):
                error = ""
                self.render("editcomment.html", subject=post.subject,
                            content=post.content, error=error,
                            comment=comment.comment, p=post)
            else:
                error_msgg = "You can't edit a comment you did not create."
                self.render("error.html", error=error_msgg, referer=referer)

    def post(self, post_id, comment_id):
        refererr = self.request.referer
        if not self.user:
            return self.redirect('/login')
        else:
            edit_comment = self.request.get('comment')
            if edit_comment:
                post = Post.get_by_id(int(post_id), parent=blog_key())
                if not post:
                    self.error(404)
                    return
                comment = Comment.get_by_id(int(comment_id), parent=blog_key())
                if not comment:
                    self.error(404)
                    return
                if (comment.cAuthor == self.user.name):
                    comment.comment = edit_comment
                    comment.put()
                    self.redirect('/blog/%s' % str(post_id))
                else:
                    error_msg = "You can't edit a comment you did not create."
                    self.render("error.html", error=error_msg,
                                referer=refererr)
            else:
                post = Post.get_by_id(int(post_id), parent=blog_key())
                error = "please enter the comment!"
                self.render("editcomment.html", subject=post.subject,
                            content=post.content, error=error, p=post)


# Deleting a comment
class DeleteComment(BlogHandler):
    @comment_post_exists
    def get(self, post_id, comment_id, comment, post):
        if not self.user:
            return self.redirect('/login')
        else:
            if (comment.cAuthor == self.user.name):
                    comment.delete()
                    self.redirect('/blog/%s' % str(post_id))
            else:
                referer = self.request.referer
                error_msg = "You can't delete a comment you did not create."
                self.render("error.html", error=error_msg, referer=referer)

# URL Handlers
app = webapp2.WSGIApplication([('/', MainPost),
                               ('/unit2/signup', Unit2Signup),
                               ('/blog/?', MainPost),
                               ('/myblog', MyBlogs),
                               ('/blog/([0-9]+)', SinglePostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/delete/([0-9]+)', DeletePost),
                               ('/likes/([0-9]+)', Like),
                               ('/unlikes/([0-9]+)', Unlike),
                               ('/comment/([0-9]+)', NewComment),
                               ('/editpost/([0-9]+)', EditPost),
                               ('/blog/([0-9]+)/editcomment/([0-9]+)',
                               EditComment),
                               ('/blog/([0-9]+)/deletecomment/([0-9]+)',
                               DeleteComment),
                               ],
                              debug=True)
