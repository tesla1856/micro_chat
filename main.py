import dotenv
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from requests_oauthlib import OAuth2Session

config = dotenv.dotenv_values(".env")


def get_oauth_token():
    global client_id, client_secret, token_url, oauth, state
    # Replace these values with your OAuth provider's details
    client_id = config['CLIENT_ID']
    client_secret = config['CLIENT_SECRET']
    authorization_base_url = 'https://id.twitch.tv/oauth2/authorize'
    token_url = 'https://id.twitch.tv/oauth2/token'
    redirect_uri = 'http://localhost:11337/callback'
    # https://id.twitch.tv/oauth2/authorize?response_type=token&client_id=CLIENT_ID&redirect_uri=https://teslabot.tesla1856.repl.co/&scope=chat:read+chat:edit+channel:moderate+whispers:read+whispers:edit+user:read:email+user:read:follows+user:edit:follows+channel:read:redemptions
    # Create an OAuth2Session with your client ID and secret
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri)
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
                self.wfile.write(b'OAuth callback received. You can close this window.')

                # Retrieve the OAuth token
                oauth.fetch_token(token_url, code=received_code, client_secret=client_secret,
                                  include_client_id=client_id)
                print('Token retrieved successfully.')
                dotenv.set_key('.env', 'TOKEN', 'oauth:' + oauth.token['access_token'])

    # Start the local HTTP server on port 8080
    server_address = ('127.0.0.1', 11337)
    httpd = HTTPServer(server_address, CallbackHandler)
    # Open the authorization URL in the web browser
    webbrowser.open(authorization_url)
    print(f'Please complete the OAuth process in the opened web browser.')
    # Wait for the OAuth callback
    httpd.handle_request()
    # The OAuth token is now available for use.
    # Close the HTTP server
    httpd.server_close()


if len(config['TOKEN']) < 7:
    get_oauth_token()

if __name__ == '__main__':
    print('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
