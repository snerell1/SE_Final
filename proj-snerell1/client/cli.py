import socket
import ssl,sys




def main():

    # Check command line arguments

    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <server_domain> <server_port>")
        sys.exit(1)

    server_domain = sys.argv[1]
    server_port = int(sys.argv[2])
    context = ssl.create_default_context()
    context.load_verify_locations("server.pem")

    # Create a socket and establish SSL connection

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (server_domain, server_port)
    sock.connect(server_address)
    ssl_sock = context.wrap_socket(sock, server_hostname='cslongproject')

    # client login code
    def client_connect():

        # Get user's name and capitalize the first letter to match database
        name = input("Enter your name: ").lower().capitalize()

        # Check if the user is an admin
        if name == "Admin":
            vr_number = 0000000
            password = input("Enter your password: ")
            method = "login"
            auth_msg = f"{method},{name},{vr_number},{password}".encode()
        else:

             # Ask for voter registration number and validate it
            while True:
                vr_number = input("Enter your voter registration number: ")
                if not vr_number.isdigit():
                    print("Please enter a valid registration number.")
                    continue
                break
            password = input("Enter your password: ")
            method = "login"
            auth_msg = f"{method},{name},{vr_number},{password}".encode()

        # Send authentication message to the server and receive the response
        ssl_sock.sendall(auth_msg)
        response = ssl_sock.recv(1024).decode()
        returnval = [response, name]
        return returnval
    

    # client registration code
    def client_register():
        name = input("Enter your name: ").lower()
        if len(name) <= 4 or len(name)>= 12:
            print("Username must be atleast 4 characters and atmost 12 characters")
            client_register()

        ssl_sock.send(name.encode())
        response = ssl_sock.recv(1024).decode()
        if response != "OK":
            print("Username exists, Please try again.")
            client_register()
        
        while True:
            password = input("Enter your password: ")
            confirmPassword = input("Renter your password: ")
            if(password != confirmPassword):
                print("Password doesnt match, please try again.")
                continue
            break
        
        
        method = "register"
        regDetails = f"{method},{name},{password}".encode()
        ssl_sock.sendall(regDetails)
    
        response = ssl_sock.recv(1024).decode()
    
        created, voter_id = response.split(",")
        if created == "OK":
            print("Registration Successfully, Please remember your Voter Id: " + voter_id +"\n")
            regOrLogin()
        else:
            print("Registration Failed, Please try again.")
            regOrLogin()

    # login and registration menu
    def regOrLogin():

        # Ask the user if they want to login or register
        inputVal = input("Please Login or Register if you dont have an account\n1. Login\n2. Register\n3. Exit\n")
        
        if inputVal == "1":
            # User chose to login
            ssl_sock.sendall(inputVal.encode())
            
            while True:
                
                # Authenticating user
                loginDetails = client_connect()

                # Extract the user's name and response from the login details
                currentUser = loginDetails[1]
                returnedresponse = loginDetails[0]
            
                if returnedresponse != "OK":
                    print("Invalid name, registration number, or password. Please try again.")
                    regOrLogin()

                print(f"Welcome {loginDetails[1].capitalize()}!.\n")
                if currentUser == "Admin":

                    # Admin-specific menu options
                    while True:
                        print("\nPlease enter a number (1-5)")
                        print("1. Check votes registered")
                        print("2. Declare results")
                        print("3. Add candidate")
                        print("4. Start Election")
                        print("5. Signout\n")

                        # Get admin's choice
                        choice = input("Enter your choice: ")

                        if choice == "1":

                            # Option to check registered votes
                            ssl_sock.sendall("1".encode())
                            response = ssl_sock.recv(1024).decode()
                            print(response)
                            continue

                        elif choice == "2":

                            # Option to declare results
                            ssl_sock.sendall("2".encode())
                            response = ssl_sock.recv(1024).decode()
                            if response == "Please confirm to declare: \n1. Yes\n2. No\n":
                                while True:
                                    message = input(response)
                                    if message not in ["1","2"]:
                                        print("Invalid choice.")
                                        continue
                                    break
                                ssl_sock.sendall(message.encode())
                                response = ssl_sock.recv(1024).decode()
                                print(response)
                                continue
                            else:
                                print(response)
                                continue

                        elif choice == "3":

                            # Option to add new candidate
                            ssl_sock.sendall("3".encode())
                            response = ssl_sock.recv(1024).decode()
                            if response != "OK":
                                print(response)
                                continue
                            name = input("Candidate name: ").lower()
                            cid = input("Candidate ID: ")
                            message = f"{name},{cid}".encode()
                            ssl_sock.sendall(message)
                            response = ssl_sock.recv(1024).decode()
                            print(response)
                            continue


                        elif choice == "4":

                            # Option to start election
                            ssl_sock.sendall("4".encode())
                            response = ssl_sock.recv(1024).decode()
                            if response == "Please confirm to start: \n1. Yes\n2. No\n":
                                while True:
                                    message = input(response)
                                    if message not in ["1","2"]:
                                        print("Invalid choice.")
                                        continue
                                    break
                                ssl_sock.sendall(message.encode())
                                response = ssl_sock.recv(1024).decode()
                                print(response)
                                continue
                            else:
                                print(response)
                                continue


                        elif choice == "5":

                            # Admin sign out
                            ssl_sock.sendall("5".encode())
                            print("Goodbye.")
                            regOrLogin()
                        else:
                            print("Invalid choice. Please try again.\n")


                else:

                    # User-specific menu options
                    while True:
                        print("Please enter a number (1-4)")
                        print("1. Vote")
                        print("2. View election results")
                        print("3. My vote history")
                        print("4. Signout")
                        choice = input("Enter your choice: ")
                        
                        if choice == "1":

                            # Option to vote
                            ssl_sock.sendall("1".encode())
                            response = ssl_sock.recv(1024).decode()
                            if response == "0":
                                print("\nYou have already voted.\n")
                                continue
                            elif response == "1":
                                print("\nVoting not started yet.\n")
                                continue
                            elif response == "2":
                                print("\nVoting closed.\n")
                                continue
                            else:
                                while True:
                                    choice = input(response + "\n")

                                    options = response.split("\n")
                                    num_options = len(options)

                                    if not choice.isdigit() or int(choice) < 1 or int(choice) > num_options:
                                        print("\nInvalid choice. Please choose a valid option.\n")
                                        continue
                                    else:
                                        break
                                ssl_sock.sendall(choice.encode())
                                print("\n" + ssl_sock.recv(1024).decode())
                                continue

                        elif choice == "2":
                            
                            # Option to check results
                            ssl_sock.sendall("2".encode())
                            response = ssl_sock.recv(1024).decode()
                            if response != "0":
                                print("\n" + response + "\n")
                            else:
                                print("\nThe result is not available yet.\n")
                                
                            continue

                        elif choice == "3":

                            # Option to check user's vote history
                            ssl_sock.sendall("3".encode())
                            response = ssl_sock.recv(1024).decode()
                            print("\n" + response + "\n")
                            continue

                        elif choice == "4":

                            # User sign out
                            ssl_sock.sendall("4".encode())
                            print("Goodbye.\n")
                            regOrLogin()

                        else:
                            print("Invalid choice. Please try again.\n")

        elif inputVal == "2":
            
            # Option to register as new user
            ssl_sock.sendall(inputVal.encode())
            client_register()
            
        elif inputVal == "3":

            # Option to exit voting system
            ssl_sock.sendall("Exit".encode())
            ssl_sock.close()
            exit()

        else: 
            print("Invalid selection")
            regOrLogin()


    try:
        print("Welcome to University Voating System\n")
        while True:
            regOrLogin()

    except ConnectionResetError:
        print("Server connection closed")

    
if __name__ == '__main__':
    main()