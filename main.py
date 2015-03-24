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


class MainHandler(tornado.web.RequestHandler):
  def get(self):
    papers = DB_CONN.execute(
        'SELECT id,title,author FROM papers ORDER BY ts DESC')
    self.render('index.html', papers=papers)


class UploadHandler(tornado.web.RequestHandler):
  def get(self):
    self.render('upload.html', error=None)

  def post(self):
    f = self.request.files['file'][0]
    filename = f['filename'].lower()
    if not filename.endswith('.pdf'):
      logging.error('Invalid upload name: %s', f['filename'])
      self.render('upload.html', error='Only PDF files allowed')
      return
    # Hack to avoid overwriting files
    while os.path.exists(os.path.join('papers', filename)):
      filename = filename[:-4] + '_.pdf'
    with open(os.path.join('papers', filename), 'w') as fh:
      fh.write(f['body'])
    # Insert row into db
    title = self.get_argument('title')
    author = self.get_argument('author')
    email = self.get_argument('email')
    stamp = datetime.datetime.now()
    with DB_CONN as c:
      c.execute('INSERT INTO papers VALUES (?, ?, ?, ?, ?, ?)',
                (None, title, filename, author, email, stamp))
    # Redirect to index on success
    self.redirect('/')


class ReviewHandler(tornado.web.RequestHandler):
  def get(self):
    paper_id = self.get_argument('p')
    if not paper_id:
      self.redirect('/')
    paper = DB_CONN.execute('SELECT filepath FROM papers WHERE id = ?',
                            paper_id).fetchone()
    reviews = DB_CONN.execute(
        'SELECT * FROM reviews WHERE pid = ? ORDER BY ts DESC', paper_id)
    self.render('review.html', path=paper['filepath'], paper_id=paper_id,
                reviews=reviews, markdown=markdown.markdown)

  def post(self):
    paper_id = int(self.get_argument('paper_id'))
    review = self.get_argument('review')
    author = self.get_argument('author')
    stamp = datetime.datetime.now()
    with DB_CONN as c:
      c.execute('INSERT INTO reviews VALUES (?, ?, ?, ?, ?)',
                (None, paper_id, author, review, stamp))
    self.redirect('/review?p=%d' % paper_id)


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
  DB_CONN = sqlite3.connect(dbname)
  DB_CONN.row_factory = sqlite3.Row
  if not resuming:
    with DB_CONN as c:
      c.execute('CREATE TABLE papers (id integer primary key, title text, '
                'filepath text, author text, email text, ts timestamp)')
      c.execute('CREATE TABLE reviews (id integer primary key, pid integer, '
                'author text, review text, ts timestamp)')


def main():
  parse_command_line()
  initialize_db()
  webserver_dir = os.path.dirname(__file__)
  application = tornado.web.Application([
      (r'/', MainHandler),
      (r'/upload', UploadHandler),
      (r'/review', ReviewHandler),
      (r'/(.*\.pdf)', tornado.web.StaticFileHandler,
          dict(path=os.path.join(webserver_dir, 'papers'))),
  ],
      template_path=os.path.join(webserver_dir, 'templates'),
      login_url=r'/login',
      cookie_secret="TODO")
  loop, port = start_server(application, options.port)
  print 'Listening at http://localhost:%s/' % port
  loop.start()

if __name__ == "__main__":
  main()
