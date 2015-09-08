#!/usr/bin/env python
import bcrypt
import datetime
import logging
import markdown
import os.path
import re
import socket
import sqlite3
import tornado.template
import tornado.web
from tornado.escape import url_escape
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.netutil import bind_sockets
from tornado.options import define, options, parse_command_line
define('port', type=int, default=8888, help='Port to listen on')
DB_CONN = None


class BaseHandler(tornado.web.RequestHandler):
  def get_current_user(self):
    # Necessary for authentication,
    # see http://tornado.readthedocs.org/en/latest/guide/security.html
    return self.get_secure_cookie('user')


class MainHandler(BaseHandler):
  @tornado.web.authenticated
  def get(self):
    papers = DB_CONN.execute(
        'SELECT id,title,author,anon,displayname FROM papers, users '
        'WHERE papers.author = users.username ORDER BY ts DESC')
    self.render('index.html', papers=papers, user=self.current_user)


class UploadHandler(BaseHandler):
  def _render(self, error='', title='', anon=False, paper_id=''):
    verb = 'Edit' if paper_id else 'Upload'
    user = DB_CONN.execute('SELECT displayname FROM users WHERE username = ?',
                           (self.current_user,)).fetchone()
    self.render('upload.html', user=user['displayname'], error=error, verb=verb,
                title=title, anon=anon, paper_id=paper_id)

  @tornado.web.authenticated
  def get(self):
    paper_id = self.get_argument('p', None)
    if paper_id is None:
      return self._render()

    paper = DB_CONN.execute(
        'SELECT title,author,anon FROM papers WHERE id = ?',
        (paper_id,)).fetchone()
    # Check that the paper exists, and that the user is actually the owner
    if paper is None or paper['author'] != self.current_user:
      self._render(error="Error: Document not found")
    else:
      self._render(title=paper['title'], anon=paper['anon'], paper_id=paper_id)

  @tornado.web.authenticated
  def post(self):
    # Read all of the parameters
    title = self.get_argument('title')
    anon = bool(self.get_argument('anonymous', False))
    delete = bool(self.get_argument('delete', False))
    paper_id = self.get_argument('paper_id')
    if 'file' not in self.request.files:
      f = None
    else:
      f = self.request.files['file'][0]
    # Dispatch to the upload/edit/delete handlers
    if delete:
      self.handle_delete(paper_id)
    elif paper_id:
      self.handle_edit(title, anon, f, paper_id)
    else:
      self.handle_upload(title, anon, f)

  def handle_delete(self, paper_id):
    logging.info('Deleting paper %s', paper_id)
    with DB_CONN as c:
      c.execute('DELETE FROM papers WHERE id = ?', (paper_id,))
      c.execute('DELETE FROM reviews WHERE pid = ?', (paper_id,))
    # Redirect to index on success
    self.redirect('/')

  def handle_edit(self, title, anon, f, paper_id):
    logging.info('Editing paper %s', paper_id)
    # Update this paper's row in the db
    stamp = datetime.datetime.now()
    if f is None:
      # Only updating metadata.
      with DB_CONN as c:
        c.execute('UPDATE papers SET title = ?, anon = ?, ts = ? WHERE id = ?',
                  (title, anon, stamp, paper_id))
    else:
      # We have a new uploaded file: save, then update.
      filename = save_uploaded_file(f)
      with DB_CONN as c:
        c.execute('UPDATE papers '
                  'SET title = ?, filename = ?, anon = ?, ts = ? WHERE id = ?',
                  (title, filename, anon, stamp, paper_id))
    # Redirect to index on success
    self.redirect('/')

  def handle_upload(self, title, anon, f):
    if not title:
      logging.error('No title supplied')
      self._render(error='Error: No title supplied', anon=anon)
      return
    if not f:
      logging.error('No file uploaded')
      self._render(error='Error: No file uploaded',
                   title=title, anon=anon)
      return
    if f['filename'][-4:].lower() != '.pdf':
      logging.error('Invalid upload name: %s', f['filename'])
      self._render(error='Error: Only PDF files allowed',
                   title=title, anon=anon)
      return
    # Save the paper
    filename = save_uploaded_file(f)
    # Insert row into db
    author = self.current_user
    stamp = datetime.datetime.now()
    with DB_CONN as c:
      c.execute('INSERT INTO papers VALUES (?, ?, ?, ?, ?, ?)',
                (None, title, filename, author, anon, stamp))
    # Redirect to index on success
    logging.info('Uploaded new paper to %s', filename)
    self.redirect('/')


class ReviewHandler(BaseHandler):
  def _render(self, paper, reviews, review=None):
    user = DB_CONN.execute('SELECT displayname FROM users WHERE username = ?',
                           (self.current_user,)).fetchone()
    if review is None:
      review = dict(id='', review='')
    self.render('review.html', paper=paper, reviews=reviews,
                review=review, displayname=user['displayname'],
                user=self.current_user, markdown=markdown.markdown)

  @tornado.web.authenticated
  def get(self):
    paper_id = self.get_argument('p')
    review_id = int(self.get_argument('r', -1))
    if not paper_id:
      return self.redirect('/')
    paper = DB_CONN.execute(
        'SELECT id,title,author,anon,filename,displayname FROM papers, users '
        'WHERE papers.author = users.username AND id = ?',
        (paper_id,)).fetchone()
    if not paper:
      return self.redirect('/')
    reviews = DB_CONN.execute(
        'SELECT id,review,author,anon,ts,displayname FROM reviews, users '
        'WHERE reviews.author = users.username AND pid = ? ORDER BY ts DESC',
        (paper_id,)).fetchall()
    if review_id < 0:
      return self._render(paper, reviews)
    # Hack: manually search the reviews to get the one we want.
    for r in reviews:
      if r['id'] == review_id and r['author'] == self.current_user:
        return self._render(paper, reviews, review=r)
    # No review was found with the right id + owner combo.
    self._render(paper, reviews)

  @tornado.web.authenticated
  def post(self):
    paper_id = int(self.get_argument('paper_id'))
    review_id = self.get_argument('review_id')
    review_id = int(review_id) if review_id else None
    review = self.get_argument('review')
    author = self.current_user
    anon = bool(self.get_argument('anonymous', False))
    stamp = datetime.datetime.now()
    with DB_CONN as c:
      if review:
        if review_id is None:
          # Insert a new review
          c.execute('INSERT INTO reviews VALUES (?, ?, ?, ?, ?, ?)',
                    (None, paper_id, author, review, anon, stamp))
        else:
          # Update an existing review
          c.execute('UPDATE reviews SET review = ?, anon = ?, ts = ? '
                    'WHERE id = ?', (review, anon, stamp, review_id,))
      elif review_id is not None:
        # Delete an existing review
        c.execute('DELETE FROM reviews WHERE id = ?', (review_id,))
    self.redirect('/review?p=%d' % paper_id)


class LoginHandler(BaseHandler):
  def get(self):
    self.render('login.html', msg=self.get_argument('msg', ''),
                next=self.get_argument('next', '/'))

  def post(self):
    username = self.get_argument('user')
    raw_password = self.get_argument('pw')
    displayname = self.get_argument('displayname')
    next_url = self.get_argument('next', '/')
    # Find a user with the given username
    user = DB_CONN.execute(
        'SELECT hashed_password FROM users WHERE username = ? LIMIT 1',
        (username,)).fetchone()
    if displayname:
      # This is a signup attempt.
      self._do_signup(user, username, raw_password, displayname, next_url)
    else:
      # Regular login attempt.
      self._do_login(user, username, raw_password, next_url)

  def _do_signup(self, existing_user, username, raw_password,
                 displayname, next_url):
    if existing_user:
      logging.info('Signup failed due to username conflict: %r', username)
      self._redirect_error(next_url, 'Error: Username taken')
    elif not _valid_username(username):
      logging.info('Signup failed due to invalid username: %r', username)
      self._redirect_error(next_url, 'Error: Invalid username')
    else:
      email = self.get_argument('email')
      logging.info('Signing up new user: %r', username)
      with DB_CONN as c:
        c.execute('INSERT INTO users VALUES (?, ?, ?, ?)',
                  (username, email, displayname,
                   bcrypt.hashpw(raw_password, bcrypt.gensalt())))
      self.set_secure_cookie('user', username)
      self.redirect(next_url)

  def _do_login(self, existing_user, username, raw_password, next_url):
    if (existing_user and
        bcrypt.checkpw(raw_password, existing_user['hashed_password'])):
      logging.info('Logging in user %r', username)
      self.set_secure_cookie('user', username)
      self.redirect(next_url)
    else:
      logging.info('Login failed for user %r', username)
      self._redirect_error(next_url, 'Error: Login failed')

  def _redirect_error(self, next_url, message):
    self.redirect('/login?next=%s&msg=%s' % (url_escape(next_url),
                                             url_escape(message)))


def _valid_username(username):
  return (0 < len(username) < 50) and re.match(r'[^0-9a-z]', username, re.I)


class LogoutHandler(BaseHandler):
  def get(self):
    self.clear_cookie('user')
    self.redirect('/login?msg=' + url_escape('Logged out'))


def save_uploaded_file(f):
  '''f is the upload object from a POST request.'''
  # Hack to avoid overwriting files
  # TODO: generate random pdf names instead, or use an md5sum.
  filename = f['filename']
  while os.path.exists(os.path.join('papers', filename)):
    filename = filename[:-4] + '_.pdf'
  # write it
  with open(os.path.join('papers', filename), 'w') as fh:
    fh.write(f['body'])
  return filename


def start_server(application, port):
  application.listen(port)
  print 'Running at http://%s:%d/' % (socket.gethostname(), port)
  print 'Press Ctrl+C to quit'
  tornado.ioloop.IOLoop.instance().start()


def initialize_db(dbname='reviews.db'):
  global DB_CONN
  resuming = os.path.exists(dbname)
  DB_CONN = sqlite3.connect(dbname, detect_types=sqlite3.PARSE_DECLTYPES)
  DB_CONN.row_factory = sqlite3.Row
  if not resuming:
    with DB_CONN as c:
      c.execute('CREATE TABLE papers ('
                'id integer primary key, title text, filename text, '
                'author text, anon integer, ts timestamp)')
      c.execute('CREATE TABLE reviews (id integer primary key, pid integer, '
                'author text, review text, anon integer, ts timestamp)')
      c.execute('CREATE TABLE users (username text, email text, '
                'displayname text, hashed_password text)')


def main():
  parse_command_line()
  initialize_db()
  webserver_dir = os.path.dirname(__file__)
  application = tornado.web.Application([
      (r'/', MainHandler),
      (r'/upload', UploadHandler),
      (r'/review', ReviewHandler),
      (r'/login', LoginHandler),
      (r'/logout', LogoutHandler),
      (r'/(.*\.pdf)', tornado.web.StaticFileHandler,
          dict(path=os.path.join(webserver_dir, 'papers'))),
  ],
      template_path=os.path.join(webserver_dir, 'templates'),
      login_url=r'/login',
      cookie_secret="635Blk29jgnp9ghnkjcSDF@$")
  start_server(application, options.port)

if __name__ == "__main__":
  main()
