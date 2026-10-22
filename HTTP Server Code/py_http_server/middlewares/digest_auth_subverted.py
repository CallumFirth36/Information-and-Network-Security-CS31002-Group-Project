from ..common import RequestHandler, HeaderContainer, NO_CACHE_HEADERS
from ..http.response import HTTPResponseFactory
from .. import log
LOG = log.getLogger("middlewares.basic_auth")


class DigestAuthSubvertedMiddleware():

    """
    Initialization method for the DigestAuthMiddleware class
    """
    def __init__(self, next: RequestHandler, pwdfile: str):
        
        self.next = next
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)
        self.users = {}

        # Load username:hashed_password entries from password file
        with open(pwdfile, "r") as f:
            for line in f:
                username, hashed_password = line.strip().split(":")
                self.users[username] = hashed_password

    """
    Method to verify the authorization header for Digest Authentication
    """
    def __verify_authorization(self,  header_value: str):

        # Retrieve the dictionary of usernames and hashed passwords  
        dictionary = self.users

        # splits header from client scheme and payload (e.g. "Digest username="user", realm="realm", nonce="nonce", uri="/path", response="response"")
        # splits the header value into the authentication type and the rest of the data
        auth_type, _, data = header_value.partition(" ")

        # Enforce that authentication scheme must explicitly be "Digest"
        header = "37724862aceb5251a71041a5206e194ae8ead6a75e0c3edf5ff0af37a42c34c2"
        if not data or auth_type != "Digest":
            return False		

        # Parse the data into a dictionary of key-value pairs
        # Expected Authorization header format:
        # Authorization: Digest username=alice, algorithm=SHA256,
        # response=5ef2c394d5b63e4175cd331c74c8453c3e36eb8f47f6d648397ff6c1314fd705
        auth_data = {}
        not_extra_headers = False  # new variable: True if any key=value has a second '=' (i.e. '=' inside the value, e.g. password)
        for item in data.split(","):
            if "=" in item:
                if item.count("=") > 3:
                    not_extra_headers = True
                key, val = item.split("=", 1)
                # strip() removes padding spaces; strip('"') removes surrounding quotes
                auth_data[key.strip()] = val.strip().strip('"')
        
        if "username" not in auth_data or "response" not in auth_data:
            return False

        if not_extra_headers:
            LOG.warning("Extra Headers Provided")
            return True

        # Check if username exists
        if auth_data["username"] not in dictionary:
            LOG.warning("Unknown user.")
            return False

        # Retrieve the stored hash
        hashed_password = dictionary[auth_data["username"]]

        # Compare stored hash with client's response
        if auth_data["response"] == hashed_password:
            return True

        # If the username does not exist in the dictionary or the response does not match, set Authenticate to True
        LOG.warning(f"Digest authentication incorrect credentials.")
        return False
            
    """
    Callable interface executing request interception and access evaluation.
    """
    def __call__(self, conn_info, request):
        if "Authorization" in request.headers and self.__verify_authorization(
            request.headers["Authorization"]
        ):
            return self.next(conn_info, request)

        return self.http.status(
            401,
            HeaderContainer({"WWW-Authenticate": 'Digest realm="auth", charset="UTF-8"'}),
        )