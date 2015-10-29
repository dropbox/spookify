from hashlib import sha256
import dropbox
import hmac
import json
import os
import os.path
import shutil
import tempfile
import threading
import urlparse

from dropbox.client import DropboxClient, DropboxOAuth2Flow
from flask import abort, Flask, redirect, render_template, request, session, url_for
import redis
from whelk import shell
 
redis_url = os.environ['REDISTOGO_URL']
redis_client = redis.from_url(redis_url)
 
# App key and secret from the App console (dropbox.com/developers/apps)
APP_KEY = os.environ['APP_KEY']
APP_SECRET = os.environ['APP_SECRET']
 
app = Flask(__name__)
app.debug = True
 
# A random secret used by Flask to encrypt session data cookies
app.secret_key = os.environ['FLASK_SECRET_KEY']

def get_url(route):
    '''Generate a proper URL, forcing HTTPS if not running locally'''
    host = urlparse.urlparse(request.url).hostname
    url = url_for(
        route,
        _external=True,
        _scheme='http' if host in ('127.0.0.1', 'localhost') else 'https'
    )

    return url

def get_flow():
    return DropboxOAuth2Flow(
        APP_KEY,
        APP_SECRET,
        get_url('oauth_callback'),
        session,
        'dropbox-csrf-token')

@app.route('/welcome')
def welcome():
    return render_template('welcome.html', redirect_url=get_url('oauth_callback'),
        webhook_url=get_url('webhook'), home_url=get_url('index'), app_key=APP_KEY)

@app.route('/oauth_callback')
def oauth_callback():
    '''Callback function for when the user returns from OAuth.'''

    access_token, uid, extras = get_flow().finish(request.args)
 
    # Extract and store the access token and uid for this user
    redis_client.hset('tokens', uid, access_token)
    session['uid'] = uid

    # Setting ghost_path here because it needs to be in the application context of Flask
    haunt_user(uid)

    return redirect(url_for('done'))

def haunt_user(uid):
    '''Call /delta for the given user ID and haunt any new images.'''

    # OAuth token for the user
    token = redis_client.hget('tokens', uid)

    # /delta cursor for the user (None the first time)
    cursor = redis_client.hget('cursors', uid)

    # These are all v1-style API calls. 
    client = DropboxClient(token)
    has_more = True

    while has_more:
        result = client.delta(cursor)

        for path, metadata in result['entries']:

            if (metadata is None or metadata['is_dir'] or not metadata.get('thumb_exists') or path.endswith('-spookified.gif')):
                continue

            temp_path = tempfile.mkdtemp()

            with open(temp_path + '/alive.jpg', 'wb') as fout:
                with client.thumbnail(path, size='l', format='JPEG') as fin:
                    fout.write(fin.read())

            width = int(shell.identify('-format', '%[fx:w]', temp_path + '/alive.jpg').stdout)
            shell.composite('-watermark', '50%', '-gravity', 'center', '-channel', 'RGBA', '(', 'halloweenghost.png', '-resize', '{}x'.format(width), ')', temp_path + '/alive.jpg', temp_path + '/second_frame.png')
            shell.convert('-delay', '4000x1000', '-loop', 0, temp_path + '/alive.jpg', '-delay', '200x1000', temp_path + '/second_frame.png', temp_path + '/ghost.gif')

            with open(temp_path + '/ghost.gif', 'rb') as f:
                client.put_file(os.path.splitext(path)[0]+'-spookified.gif', f, overwrite=True)

            shutil.rmtree(temp_path)

        # Update cursor
        cursor = result['cursor']
        redis_client.hset('cursors', uid, cursor)

        # Repeat only if there's more to do
        has_more = result['has_more']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return redirect(get_flow().start())

@app.route('/exorcise')
def exorcise():
    '''Call files_list_folder and delete any haunted files.'''
    
    uid = session.get('uid')
    if uid is None:
        return redirect(url_for('login'))

    token = redis_client.hget('tokens', uid)

    # These are all v2-style APIs
    dbx = dropbox.Dropbox(token)

    # User info
    user = dbx.users_get_current_account()
    name = user.name.familiar_name

    # File operations, metadata
    path = ''
    cursor = None
    has_more = True
    
    while has_more:
        if (cursor is None):
            result = dbx.files_list_folder(path)
        else:
            result = dbx.files_list_folder_continue(cursor)

        for entry in result.entries:
            if (entry.name.endswith('-spookified.gif')):
                dbx.files_delete(entry.path_lower)

        has_more = result.has_more
        cursor = result.cursor
    return render_template('exorcised.html')

@app.route('/done')
def done(): 
    return render_template('done.html')

def validate_request():
    '''Validate that the request is properly signed by Dropbox.
       (If not, this is a spoofed webhook.)'''

    signature = request.headers.get('X-Dropbox-Signature')
    return signature == hmac.new(APP_SECRET, request.data, sha256).hexdigest()

@app.route('/webhook', methods=['GET'])
def challenge():
    '''Respond to the webhook challenge (GET request) by echoing back the challenge parameter.'''

    return request.args.get('challenge')

@app.route('/webhook', methods=['POST'])
def webhook():
    '''Receive a list of changed user IDs from Dropbox and haunt each.'''

    # Make sure this is a valid request from Dropbox
    if not validate_request(): abort(403)

    for uid in json.loads(request.data)['delta']['users']:
        # We need to respond quickly to the webhook request, so we do the
        # actual work in a separate thread. For more robustness, it's a
        # good idea to add the work to a reliable queue and process the queue
        # in a worker process.
        threading.Thread(target=haunt_user, args=(uid,)).start()
    return ''

if __name__=='__main__':
    app.run(debug=True)
