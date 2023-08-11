"""
This module contains test cases for client functionality.
"""
import socket
import ssl

TEST_SERVER_DOMAIN = socket.gethostname()
TEST_SERVER_PORT = 1026

def create_socket_connection():
    """
    ssl_sock (ssl.SSLSocket): SSL socket for communication.
    """
    context = ssl.create_default_context()
    context.load_verify_locations("server.pem")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((TEST_SERVER_DOMAIN, TEST_SERVER_PORT))
    return context.wrap_socket(sock, server_hostname='cslongproject')

# assert response is None

def test_user_register(ssl_sock,name,password):
    """
    Test user registration.
    name (str): User's name.
    password (str): User's password.
    """
    ssl_sock.sendall('register'.encode())
    ssl_sock.sendall(name.encode())
    response = ssl_sock.recv(1024).decode()
    assert response == "OK"
    ssl_sock.sendall(f"{name},{password}".encode())
    response = ssl_sock.recv(1024).decode()
    created, voter_id = response.split(",")
    assert created == "OK"
    print("test_user_register is success.")
    return voter_id


def test_user_login(ssl_sock,name,voter_id,password):
    """
    Test user login.
    name (str): User's name.
    voter_id: User's voter identifier.
    password (str): User's password.
    """
    ssl_sock.sendall('login'.encode())
    ssl_sock.sendall(f'{name},{voter_id},{password}'.encode())
    response = ssl_sock.recv(1024).decode()
    assert response == "OK"
    print("test_user_login is success.")

def test_user_selection(ssl_sock,voting):
    """
    Test user selection.
    voting: voting not started/during voting/after voting closed
    """
    if voting == "voting not started":
        ssl_sock.sendall('vote'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "Voting not started yet."
        ssl_sock.sendall('check results'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "not available"
        ssl_sock.sendall('vote history'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "You have not voted yet."
        ssl_sock.sendall('User sign out'.encode())
        print("test_user_selection before voting not started is success.")
    elif voting == "during voting":
        ssl_sock.sendall('vote'.encode())
        response = ssl_sock.recv(1024).decode()
        assert "Choose your candidate" in response
        ssl_sock.sendall('1'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "Thank you for your vote!\n"
        ssl_sock.sendall('check results'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "not available"
        ssl_sock.sendall('vote history'.encode())
        response = ssl_sock.recv(1024).decode()
        assert "You have already voted at" in response
        ssl_sock.sendall('User sign out'.encode())
        # response = ssl_sock.recv(1024).decode()
        print("test_user_selection during voting is success.")
    elif voting == "after voting closed":
        ssl_sock.sendall('vote'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "Voting closed."
        ssl_sock.sendall('check results'.encode())
        response = ssl_sock.recv(1024).decode()
        assert "Won" in response
        ssl_sock.sendall('vote history'.encode())
        response = ssl_sock.recv(1024).decode()
        assert "You have already voted at" in response
        ssl_sock.sendall('User sign out'.encode())
        print("test_user_selection after voting closed is success.")
    else:
        pass


def test_admin_login(ssl_sock):
    """
    Test admin login.
    """
    ssl_sock.sendall('login'.encode())
    # response = ssl_sock.recv(1024).decode()
    ssl_sock.sendall('Admin,0000000,1234'.encode())
    response = ssl_sock.recv(1024).decode()
    assert response == "OK"
    print("test_admin_login is success.")

def test_admin_selecion(ssl_sock,voting):
    """
    Test admin selection.
    voting: voting not started/during voting/after voting closed
    """
    if voting == "voting not started":
        ssl_sock.sendall('check votes'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "Voting not started yet."
        ssl_sock.sendall('declare results'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "Voting not started yet."
        ssl_sock.sendall('add new candidate'.encode())
        response = ssl_sock.recv(1024).decode()
        ssl_sock.sendall('Chris,1001'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "Successfully added new candidate"
        ssl_sock.sendall('add new candidate'.encode())
        response = ssl_sock.recv(1024).decode()
        ssl_sock.sendall('Linda,1002'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "Successfully added new candidate"
        ssl_sock.sendall('start election'.encode())
        response = ssl_sock.recv(1024).decode()
        assert "Please confirm to start:" in response
        ssl_sock.sendall('1'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "Voting started."
        ssl_sock.sendall('sign out'.encode())
        print("test_admin_selecion before voting not started is success.")
    elif voting == "during voting":
        ssl_sock.sendall('check votes'.encode())
        response = ssl_sock.recv(1024).decode()
        assert "votes registered." in response
        ssl_sock.sendall('declare results'.encode())
        response = ssl_sock.recv(1024).decode()
        ssl_sock.sendall('1'.encode())
        response = ssl_sock.recv(1024).decode()
        assert "Results declared." in response
        ssl_sock.sendall('add new candidate'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "Voting has concluded, cannot add a candidate now."
        ssl_sock.sendall('start election'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "Voting has concluded."
        ssl_sock.sendall('sign out'.encode())
        print("test_admin_selecion during voting is success.")
    elif voting == "after voting closed":
        ssl_sock.sendall('check votes'.encode())
        response = ssl_sock.recv(1024).decode()
        assert "votes registered." in response
        ssl_sock.sendall('declare results'.encode())
        response = ssl_sock.recv(1024).decode()
        assert "Results already declared." in response
        ssl_sock.sendall('add new candidate'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "Voting has concluded, cannot add a candidate now."
        ssl_sock.sendall('start election'.encode())
        response = ssl_sock.recv(1024).decode()
        assert response == "Voting has concluded."
        ssl_sock.sendall('sign out'.encode())
        print("test_admin_selecion after voting closed is success.")
    else:
        pass

def test_exit(ssl_sock):
    """
    Client exit from connection.
    """
    ssl_sock.sendall('exit'.encode())
    print("test_exit is success.")

def main():
    """
    Contains all test function calls.
    """
    ssl_sock = create_socket_connection()

    # New user registration
    voter_id = test_user_register(ssl_sock,"alice","1234")

    # User login and selection when voting not started
    test_user_login(ssl_sock,"alice",voter_id,"1234")
    test_user_selection(ssl_sock,"voting not started")

    # Admin login and selection when voting not started
    test_admin_login(ssl_sock)
    test_admin_selecion(ssl_sock,"voting not started")

    # Old user login and selection during voting
    test_user_login(ssl_sock,"alice",voter_id,"1234")
    test_user_selection(ssl_sock,"during voting")

    # New user registration and selection
    voter_id = test_user_register(ssl_sock,"Brandon","1234")
    test_user_login(ssl_sock,"Brandon",voter_id,"1234")
    test_user_selection(ssl_sock,"during voting")

    # Admin login and selection when voting completed
    test_admin_login(ssl_sock)
    test_admin_selecion(ssl_sock,"during voting")

    # New user login and selection when voting completed
    test_user_login(ssl_sock,"Brandon",voter_id,"1234")
    test_user_selection(ssl_sock,"after voting closed")

    # Admin login and selection after voting completed
    test_admin_login(ssl_sock)
    test_admin_selecion(ssl_sock,"after voting closed")

    # Exit case
    test_exit(ssl_sock)

if __name__ == '__main__':
    main()
