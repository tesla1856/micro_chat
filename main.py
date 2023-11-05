import dotenv
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from requests_oauthlib import OAuth2Session
import socket
from emoji import demojize
from datetime import datetime
import re

config = dotenv.dotenv_values(".env")
oauth = None
sock = socket.socket()


def get_oauth_token():
    global oauth

    client_id = config['TW_CLIENT_ID']
    client_secret = config['TW_CLIENT_SECRET']
    authorization_base_url = 'https://id.twitch.tv/oauth2/authorize'
    token_url = 'https://id.twitch.tv/oauth2/token'
    redirect_uri = 'http://localhost:11337/callback'
    scope = ['chat:read',
             # 'chat:edit',
             # 'channel:moderate',
             # 'whispers:read',
             # 'whispers:edit',
             # 'user:read:email',
             # 'user:read:follows',
             # 'user:edit:follows',
             # 'channel:read:redemptions',
             ]

    # https://id.twitch.tv/oauth2/authorize?response_type=token&client_id=CLIENT_ID&redirect_uri=https://teslabot.tesla1856.repl.co/
    # &scope=chat:read+chat:edit+channel:moderate+whispers:read+whispers:edit+user:read:email+user:read:follows+user:edit:follows+channel:read:redemptions

    # Create an OAuth2Session with your client ID and secret
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=' '.join(scope))
    # Generate an authorization URL
    authorization_url, state = oauth.authorization_url(authorization_base_url)

    # Define the callback handler
    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            query_parameters = parse_qs(urlparse(self.path).query)
            received_state = query_parameters.get('state', [''])[0]
            received_code = query_parameters.get('code', [''])[0]

            if received_state != state:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Invalid OAuth state')
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(
                    b'<html><body><p>OAuth callback received. You can close this window.</p></body></html>')

                # Retrieve the OAuth token
                oauth.fetch_token(token_url,
                                  code=received_code,
                                  client_secret=client_secret,
                                  include_client_id=client_id)
                print('Token retrieved successfully.')
                dotenv.set_key('.env', 'TW_TOKEN', 'oauth:' + oauth.token['access_token'])

        def log_message(self, log_format, *args):
            return

    # Start the local HTTP server on port 8080
    server_address = ('', 11337)
    httpd = HTTPServer(server_address, CallbackHandler)

    # Open the authorization URL in the web browser
    webbrowser.open(authorization_url)
    print(f'Please complete the OAuth process in the opened web browser.')

    # Wait for the OAuth callback
    httpd.handle_request()

    # The OAuth token is now available for use.
    # Close the HTTP server
    httpd.server_close()


def main():
    if len(config['TW_TOKEN']) < 7:
        get_oauth_token()

    sock.connect((config['TW_SERVER'], int(config['TW_PORT'])))
    sock.send(f"PASS {config['TW_TOKEN']}\n".encode('utf-8'))
    sock.send(f"NICK {config['TW_NICKNAME']}\n".encode('utf-8'))
    sock.send(f"JOIN {config['TW_CHANNEL']}\n".encode('utf-8'))

    while True:
        resp = sock.recv(2048).decode('utf-8')

        if resp.startswith('PING'):
            sock.send("PONG\n".encode('utf-8'))

        elif len(resp) > 0:
            resp = demojize(resp)
            time = datetime.now().strftime('%H:%M:%S')
            exp = re.search(':(.*)\!.*@.*\.tmi\.twitch\.tv PRIVMSG #.* :(.*)', resp)
            if exp:
                username, message = exp.groups()
                print(f'{time} {username}: {message}')
            else:
                print(f'{time} {resp}')

    sock.close()


if __name__ == '__main__':
    main()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
