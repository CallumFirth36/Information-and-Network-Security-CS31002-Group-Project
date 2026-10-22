import socket
import hashlib

HOST = '127.0.0.1'
PORT = 8080

def send_http_request(client_socket, auth_header=None):
    """Construct and send a raw HTTP GET request."""
    request_lines = [
        "GET / HTTP/1.1",
        f"Host: {HOST}:{PORT}",
    ]

    # Check if request is for authentication
    if auth_header:
        request_lines.append(auth_header)
    
    # HTTP headers end with a blank line (\r\n\r\n)
    request_raw = "\r\n".join(request_lines) + "\r\n\r\n"

    # Send request
    client_socket.sendall(request_raw.encode('utf-8'))

def parse_http_response(client_socket):
    """Receives and parses the raw HTTP response headers."""
    data = client_socket.recv(4096).decode('utf-8')
    
    # Split headers from body
    header, _, body = data.partition("\r\n\r\n")
    lines = header.split("\r\n")
    
    # get status line and seperate the responese code
    status_line = lines[0]
    status_code = int(status_line.split(" ")[1])
    
    # Get headers
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()

    return status_code, headers, body

def start_client():

    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # connect to server and send initial request
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        print(f"\nConnecting to {HOST}:{PORT}...")
        client_socket.connect((HOST, PORT))
        
        send_http_request(client_socket)
        status_code, headers, _ = parse_http_response(client_socket)
    
    # after initial connect check if the server is asking for authentication
    if status_code == 401 and "WWW-Authenticate" in headers:
        print("Authentication Required...")
        
        # Matches current parsing inside of the middleware
        # if that is changed please update this!!!
        auth_header = f'Authorization: Digest username="{username}", response="{password_hash}"'
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as authentication_socket:
            # connect to server and send authentication request
            authentication_socket.connect((HOST, PORT))
            
            send_http_request(authentication_socket, auth_header=auth_header)
            response_status, response_headers, response_body = parse_http_response(authentication_socket)
            
            print(f"Authenticated Request Status Code: {response_status}")
            
            if response_status == 200:
                print("\n--- Response Body ---")
                print(response_body)
                print(response_headers)
                print("\n--- End of Response ---")
            else:
                print("\nAuthentication Failed.")
    else:
        print(f"Unexpected initial status code:  {status_code}")

if __name__ == '__main__':
    start_client()