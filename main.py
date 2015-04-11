#!/usr/bin/env python
import datetime
import logging
import markdown
import os.path
import socket
import sqlite3
import tornado.web
import tornado.template
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
        'SELECT id,title,author,anon FROM papers ORDER BY ts DESC')
    self.render('index.html', papers=papers, user=self.current_user)


class UploadHandler(BaseHandler):
  def _render(self, error='', title='', email='', anon=False, paper_id=''):
    verb = 'Edit' if paper_id else 'Upload'
    self.render('upload.html', user=self.current_user, error=error, verb=verb,
                title=title, email=email, anon=anon, paper_id=paper_id)

  @tornado.web.authenticated
  def get(self):
    paper_id = self.get_argument('p', None)
    if paper_id is None:
      return self._render()

    paper = DB_CONN.execute(
        'SELECT title,author,email,anon FROM papers WHERE id = ?',
        (paper_id,)).fetchone()
    # Check that the paper exists, and that the user is actually the owner
    if paper is None or paper['author'] != self.current_user:
      self._render(error="Error: Document not found")
    else:
      self._render(title=paper['title'], email=paper['email'],
                   anon=paper['anon'], paper_id=paper_id)

  @tornado.web.authenticated
  def post(self):
    # Read all of the parameters
    title = self.get_argument('title')
    email = self.get_argument('email')
    anon = bool(self.get_argument('anonymous', False))
    paper_id = self.get_argument('paper_id')
    if 'file' not in self.request.files:
      f = None
    else:
      f = self.request.files['file'][0]
    # Dispatch to the upload/edit handler
    if paper_id:
      self.handle_edit(title, email, anon, f, paper_id)
    else:
      self.handle_upload(title, email, anon, f)

  def handle_edit(self, title, email, anon, f, paper_id):
    # Update this paper's row in the db
    stamp = datetime.datetime.now()
    if f is None:
      # Only updating metadata.
      with DB_CONN as c:
        c.execute('UPDATE papers SET title = ?, email = ?, anon = ?, ts = ? '
                  'WHERE id = ?',
                  (title, email, anon, stamp, paper_id))
    else:
      # We have a new uploaded file: save, then update.
      filename = save_uploaded_file(f)
      with DB_CONN as c:
        c.execute('UPDATE papers '
                  'SET title = ?, filename = ?, email = ?, anon = ?, ts = ? '
                  'WHERE id = ?',
                  (title, filename, email, anon, stamp, paper_id))
    # Redirect to index on success
    self.redirect('/')

  def handle_upload(self, title, email, anon, f):
    if not title:
      logging.error('No title supplied')
      self._render(error='Error: No title supplied', email=email, anon=anon)
      return
    if not f:
      logging.error('No file uploaded')
      self._render(error='Error: No file uploaded',
                   title=title, email=email, anon=anon)
      return
    if f['filename'][-4:].lower() != '.pdf':
      logging.error('Invalid upload name: %s', f['filename'])
      self._render(error='Error: Only PDF files allowed',
                   title=title, email=email, anon=anon)
      return
    # Save the paper
    filename = save_uploaded_file(f)
    # Insert row into db
    author = self.current_user
    stamp = datetime.datetime.now()
    with DB_CONN as c:
      c.execute('INSERT INTO papers VALUES (?, ?, ?, ?, ?, ?, ?)',
                (None, title, filename, author, email, anon, stamp))
    # Redirect to index on success
    self.redirect('/')


class ReviewHandler(BaseHandler):
  @tornado.web.authenticated
  def get(self):
    paper_id = self.get_argument('p')
    if not paper_id:
      return self.redirect('/')
    paper = DB_CONN.execute('SELECT filename FROM papers WHERE id = ?',
                            (paper_id,)).fetchone()
    if not paper:
      return self.redirect('/')
    reviews = DB_CONN.execute(
        'SELECT * FROM reviews WHERE pid = ? ORDER BY ts DESC', (paper_id,))
    self.render('review.html', path=paper['filename'], paper_id=paper_id,
                reviews=reviews, markdown=markdown.markdown,
                user=self.current_user)

  @tornado.web.authenticated
  def post(self):
    paper_id = int(self.get_argument('paper_id'))
    review = self.get_argument('review')
    author = self.current_user
    anon = bool(self.get_argument('anonymous', False))
    if review:
      stamp = datetime.datetime.now()
      with DB_CONN as c:
        c.execute('INSERT INTO reviews VALUES (?, ?, ?, ?, ?, ?)',
                  (None, paper_id, author, review, anon, stamp))
    self.redirect('/review?p=%d' % paper_id)


class LoginHandler(BaseHandler):
  def get(self):
    self.render('login.html', msg=self.get_argument('msg', ''),
                next=self.get_argument('next', '/'))

  def post(self):
    username = self.get_argument('user')
    password = self.get_argument('pw')
    if password == 'bellman':  # Elite security
      self.set_secure_cookie('user', username)
      self.redirect(self.get_argument('next', '/'))
    else:
      self.clear_cookie('user')
      self.redirect('/login?msg=Login%20failed')


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
  socks = bind_sockets(port, 'localhost', family=socket.AF_INET)
  port = socks[0].getsockname()[1]
  loop = IOLoop.instance()
  server = HTTPServer(application, io_loop=loop)
  server.add_sockets(socks)
  server.start()
  return loop, port


def initialize_db(dbname='reviews.db'):
  global DB_CONN
  resuming = os.path.exists(dbname)
  DB_CONN = sqlite3.connect(dbname, detect_types=sqlite3.PARSE_DECLTYPES)
  DB_CONN.row_factory = sqlite3.Row
  if not resuming:
    with DB_CONN as c:
      c.execute('CREATE TABLE papers ('
                'id integer primary key, title text, filename text, '
                'author text, email text, anon integer, ts timestamp)')
      c.execute('CREATE TABLE reviews (id integer primary key, pid integer, '
                'author text, review text, anon integer, ts timestamp)')


def main():
  parse_command_line()
  initialize_db()
  webserver_dir = os.path.dirname(__file__)
  application = tornado.web.Application([
      (r'/', MainHandler),
      (r'/upload', UploadHandler),
      (r'/review', ReviewHandler),
      (r'/login', LoginHandler),
      (r'/(.*\.pdf)', tornado.web.StaticFileHandler,
          dict(path=os.path.join(webserver_dir, 'papers'))),
  ],
      template_path=os.path.join(webserver_dir, 'templates'),
      login_url=r'/login',
      cookie_secret="635Blk29jgnp9ghnkjcSDF@$")
  loop, port = start_server(application, options.port)
  print 'Listening at http://localhost:%s/' % port
  loop.start()

if __name__ == "__main__":
  main()
