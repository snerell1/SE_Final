import multiprocessing
import os
import socket
import ssl
import hashlib,sys
import datetime
import random
import pymongo


# Process 1

def process1():
        
    # Connect to the local MongoDB server
    mongo_client = pymongo.MongoClient('mongodb://localhost:27017/')
    db = mongo_client['voting_db']
    existing_collections = db.list_collection_names()
    collectionList = ["voters", "history", "results", "admin"]

    # Loop through the collection list and create collections if they don't exist
    for collection in collectionList:
        if collection not in existing_collections:

            # Create the collections
            db.create_collection(collection)
            
            # Initialize data for specific collections
            if collection == "results":
                resultsHardData = [
                {
                    "name": "Chris",
                    "cid" : "1000",
                    "votes": 0,
                },
                {
                    "name": "Linda",
                    "cid" : "1001",
                    "votes": 0,
                }
                ]
                results_collection = db['results']
                results_collection.insert_many(resultsHardData)

            elif collection == "admin":
                adminHardData = [
                    {
                        "name": "Admin",
                        "password": "0a6ed5e0e36f90cd7e4a324124f55617bf342b00931e2ab03eb85d633aeac333",
                        "results": False,
                        "voting": False,
                        "role": "admin"
                    }
                ]
                admin_collection = db['admin']
                admin_collection.insert_many(adminHardData)

            else:
                pass
        
        # Assign collections to variables for easier access
        voters_collection = db['voters']
        history_collection = db['history']
        results_collection = db['results']
        admin_collection = db['admin']


    # Check if the correct number of command-line arguments are provided
    if len(sys.argv) < 2:
        print("Usage: python sftp_server.py <server_port>")
        sys.exit(1)

    try:
        # Retrieve the server port from the command-line argument
        server_port = int(sys.argv[1])
    except ValueError:
        print("Error: Invalid port number")
        sys.exit(1)

    # Check if the provided server port is within the valid range
    if server_port < 1024 or server_port > 65535:
        print("Error: Port number must be between 1024 and 65535")
        sys.exit(1)

    # Create a socket object for the server and wait for connection
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostname = socket.gethostname()
    server_socket.bind((hostname, server_port))
    server_socket.listen(1)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.pem", keyfile="server.key")
    print('Server started and listening...')

    while True:    

        while True:

            with open("symmetric.key", "rb") as f:
                symmetric_key = f.read()

            # Function to validate admin login
            def adminlogin(name, password):

                # Fetch admin data from the admin collection
                admindata = admin_collection.find_one({"name": name})
                encrypted_password = admindata["password"]

                # Hash the provided password with the symmetric key and compare with stored encrypted password
                hash_password = hashlib.sha256(symmetric_key + bytes(password, 'utf-8')).hexdigest()

                if(hash_password == encrypted_password):
                    return True
                else:
                    return "incorrect password"

            # Function to verify user's password
            def verify_password(regno, password):
                
                # Find user data in the voters collection using registration number
                if not voters_collection.find_one({"regno": int(regno)}):
                    return "incorrect regno"
                else:
                    userdata = voters_collection.find_one({"regno": int(regno)})

                encrypted_password = userdata["password"]

                hash_password = hashlib.sha256(symmetric_key + bytes(password, 'utf-8')).hexdigest()

                if(hash_password == encrypted_password):
                    return True
                else:
                    return "incorrect password"

            # Function for client registration
            def client_register():
                        
                        while True:

                             # Receive and capitalize the user's name from the client to match data in collection
                            name = ssl_conn.recv(1024).decode().capitalize()
                            if not voters_collection.find_one({"name": name}) and name != "Admin":
                                ssl_conn.sendall("OK".encode()) 
                            else:
                                ssl_conn.sendall("Username already exists".encode())
                                continue
                            break

                        # Receive registration details from the client
                        message = ssl_conn.recv(1024).decode().strip()
                        method, name, password = message.split(",")
                        while True:

                            # Generate a random registration number within a specified range
                            regno = random.randint(100000, 999999)
                            if voters_collection.find_one({"regno": regno}):
                                continue
                            break
                        
                        # Hash the provided password with the symmetric key
                        hash_password = hashlib.sha256(symmetric_key + bytes(password, 'utf-8')).hexdigest()

                        # Create voter data for insertion into the voters collection
                        voter_data = {
                                        "name": name.capitalize(),
                                        "regno": regno,
                                        "password": hash_password,
                                        "role":"voter"
                                    }
                        voters_collection.insert_one(voter_data)
                        response = "OK"
                        
                        # Send response and registration number to the client
                        connection = f"{response},{regno}".encode()
                        ssl_conn.sendall(connection)
            
            try:

                # Accept incoming client connection
                connection, client_address = server_socket.accept()
                print(f"Client connected from {client_address}")
                ssl_conn = context.wrap_socket(connection, server_side=True)

                while True:

                    # Receive data from the client
                    data = ssl_conn.recv(1024).decode()

                    # Handle different client requests
                    if data == '1':

                        # Option to login goes down
                        pass

                    elif data == '2':

                        # Option to register
                        client_register()
                        continue

                    elif data == "Exit":

                        # Client chose to exit
                        print("System disconnected")
                        break

                    else:
                        continue

                    # Receive and process client authentication details
                    message = ssl_conn.recv(1024).decode().strip()
                    method, name, regno, password = message.split(",")
                    currentuser = name.capitalize()

                    # Validate admin login or user's password
                    if name == "Admin":
                        result = adminlogin(name,password)

                    else: 
                        result = verify_password(regno, password)
                    
                    # Handle invalid authentication
                    if result == "incorrect regno" or result == "incorrect password":
                        text = "0"
                        print("Authentication failed.")
                        ssl_conn.sendall(text.encode())
                        continue

                    else:
                        text = "OK"
                        if name == "Admin":
                            print("Admin logged in")
                        else:
                            print("Client logged in")
                        ssl_conn.sendall(text.encode())

                    while True:

                        # Receive further requests from the client
                        data = ssl_conn.recv(1024).decode()
                        
                        # Fetch admin data from the collection
                        admindata = admin_collection.find_one({"name": "Admin"})
                        

                        if currentuser == "Admin":

                            # Handle admin-specific requests
                            if data == "1":

                                # Request: Check votes registered

                                # Check if voting has not yet started
                                if admindata["voting"] == False:
                                    ssl_conn.sendall("\nVoting not started yet.".encode())
                                    continue

                                # Check if there are no candidates present
                                if results_collection.count_documents({}) == 0:
                                    ssl_conn.sendall("No candidates present. Please add a candidate first.".encode())
                                    continue

                                # Count the total number of registered voters
                                voters = voters_collection.count_documents({})

                                # Check if there are no voters registered
                                if voters == 0:
                                    message = "No voters registered yet."
                                else:
                                    totalVotesRegistered = history_collection.count_documents({})
                                    message = str(totalVotesRegistered) + " out of " + str(voters) + " votes registered."
                                ssl_conn.sendall(message.encode())


                            elif data == "2":

                                # Request: Declare results

                                # Check if voting has not yet started
                                if admindata["voting"] == False:
                                    ssl_conn.sendall("\nVoting not started yet.".encode())
                                    continue
                                
                                # Check if there are no candidates present
                                if results_collection.count_documents({}) == 0:
                                    ssl_conn.sendall("No candidates present. Please add a candidate first.".encode())
                                    continue
                                
                                # Create an index for sorting candidates by votes in descending order to get highest votes
                                results_collection.create_index([("votes", pymongo.DESCENDING)])
                                highest_votes_document = results_collection.find_one({}, sort=[("votes", pymongo.DESCENDING)])

                                # Find candidates with tied votes
                                tied_candidates = results_collection.find({"votes": highest_votes_document["votes"]})
                                tied_candidates_list = list(tied_candidates)

                                # If there are more than one tied candidates, choose a random winner from them
                                if len(tied_candidates_list) > 1:
                                    winner = random.choice(tied_candidates_list)
                                else:

                                    # If there is no tie, the winner is the candidate with the highest votes
                                    winner = highest_votes_document

                                # Check if results have already been declared
                                if admindata["results"] == True:
                                    message = "Results already declared." + "Won: " + winner["name"] + " (" + winner["cid"] + ")" + "\n"
                                else:

                                    # Check if no votes have been cast yet
                                    if history_collection.count_documents({}) == 0:
                                        ssl_conn.sendall("No one voted yet.".encode())
                                        continue

                                    # Send confirmation request to declare results
                                    ssl_conn.sendall("Please confirm to declare: \n1. Yes\n2. No\n".encode())
                                    response = ssl_conn.recv(1024).decode()
                                    if response != "1":
                                        ssl_conn.sendall("Not declared.".encode())
                                        continue

                                    # Update the admin data to indicate results declaration
                                    admindata["results"] = True
                                    admin_collection.update_one({"_id": admindata["_id"]}, {"$set": {"results": admindata["results"]}})
                                    message = "Results declared.\n" + "Won: " + highest_votes_document["name"] + " (" + highest_votes_document["cid"] + ")" + "\n"
                                ssl_conn.sendall(message.encode())


                            elif data == "3":

                                # Request: Add candidate

                                # Check if results are already declared
                                if admindata["results"] == True:
                                    ssl_conn.sendall("Voting has concluded, cannot add a candidate now.".encode())
                                    continue

                                # Check if voting has already started
                                if admindata["voting"] == True:
                                    ssl_conn.sendall("Voting already started, cannot add a candidate now.".encode())
                                    continue
                                else:
                                    ssl_conn.sendall("OK".encode())

                                # Receive the candidate details from the admin
                                message = ssl_conn.recv(1024).decode().strip()
                                cname, cid = message.split(",")
                            
                                # Check if the candidate with the given CID already exists
                                if not results_collection.find_one({"cid": cid}):

                                    # If not, insert the new candidate into the results collection
                                    resultsHardData = [
                                    {
                                        "name": cname.capitalize(),
                                        "cid": cid,
                                        "votes": 0,
                                    }
                                    ]
                                    results_collection.insert_many(resultsHardData)
                                    message = "Successfully added new candidate"
                                    ssl_conn.sendall(message.encode())
                                else:

                                    # If candidate with given CID already exists, send a message indicating that
                                    message = "Candidate with given CID already exists."
                                    ssl_conn.sendall(message.encode())


                            elif data == "4":

                                # Request: Start Election

                                # Check if results are already declared
                                if admindata["results"] == True:
                                    ssl_conn.sendall("Voting has concluded.".encode())
                                    continue

                                # Check if voting has already started
                                if admindata["voting"] == True:
                                    message = "Voting already started."
                                else:
                                    
                                    # Check if there are no candidates present
                                    if results_collection.count_documents({}) == 0:
                                        ssl_conn.sendall("No candidates present. Please add a candidate first.".encode())
                                        continue
                                    ssl_conn.sendall("Please confirm to start: \n1. Yes\n2. No\n".encode())
                                    response = ssl_conn.recv(1024).decode()

                                    # Check if the admin confirms to start the election
                                    if response != "1":
                                        ssl_conn.sendall("Not started.".encode())
                                        continue

                                    # Update the admin data to indicate that voting has started
                                    admindata["voting"] = True
                                    admin_collection.update_one({"_id": admindata["_id"]}, {"$set": {"voting": admindata["voting"]}})
                                    message = "Voting started."
                                ssl_conn.sendall(message.encode())


                            elif data == "5":

                                # Request: Admin logout
                                print("Admin logged out")
                                break
                                

                            else:

                                # Invalid request, send appropriate response
                                ssl_conn.send("Invalid Request.".encode())



                        else:
                            
                            # Handle user-specific requests
                            if data == "1":
                                
                                # Handle the case where the client wants to vote

                                # Check if voting has not started yet
                                if admindata["voting"] == False:
                                    ssl_conn.send("1".encode())
                                    continue
                                
                                # Check if results are already declared
                                if admindata["results"] == True:
                                    ssl_conn.send("2".encode())
                                    continue
                                
                                # Check if the client has already voted
                                if history_collection.find_one({"name": currentuser}):
                                    ssl_conn.sendall("0".encode())
                                
                                else:

                                    # Prepare the list of candidates for the client to choose from
                                    userdata = results_collection.find({})
                                    index = 0
                                    candidate_names = []
                                    for document in userdata:
                                        index = index + 1
                                        candidate_names.append([index, document["name"], document["cid"]])

                                    # Create a formatted message for candidate selection and send to client
                                    candidate_response = "Choose your candidate\n"+"\n".join([f"{index}. {name} ({cid})" for index, name, cid in candidate_names])
                                    ssl_conn.send(candidate_response.encode())
                                    candidate_choice = int(ssl_conn.recv(1024).decode())
                                    
                                    # Check if the client's choice is valid
                                    if 1 <= candidate_choice <= len(candidate_names):

                                        # Update the candidate's vote count
                                        selected_candidate = candidate_names[candidate_choice-1][2]
                                        resultdata = results_collection.find_one({"cid": selected_candidate})
                                        resultdata["votes"] += 1
                                        results_collection.update_one({"_id": resultdata["_id"]}, {"$set": {"votes": resultdata["votes"]}})

                                        # Record the vote in the history collection
                                        now = datetime.datetime.now()
                                        votedtime = now.strftime("%Y-%m-%d %H:%M:%S")
                                        history_data = {
                                                "name": currentuser,
                                                "regno": int(regno),
                                                "voted_datetime": votedtime
                                            }
                                        history_collection.insert_one(history_data)
                                        ssl_conn.send("Thank you for your vote!\n".encode())

                                    else:
                                        ssl_conn.send("Invalid candidate choice. Please choose a valid candidate.\n".encode())


                            elif data == "2":

                                # Handle the case where the client wants to view election results

                                # Check if results are declared
                                if admindata["results"] != True:
                                    ssl_conn.send("0".encode())
                                else:

                                    # Get the candidate with the highest votes
                                    results_collection.create_index([("votes", pymongo.DESCENDING)])
                                    highest_votes_document = results_collection.find_one({}, sort=[("votes", pymongo.DESCENDING)])
                                    
                                    # Prepare and send the message indicating the winning candidate
                                    message = "Won: " + highest_votes_document["name"] + " (" + highest_votes_document["cid"] + ")" + "\n"
                                    ssl_conn.send(message.encode())


                            elif data == "3":

                                # Handle the case where the client wants to view their voting history

                                # Check if the client has not voted yet
                                if not history_collection.find_one({"name": currentuser}):
                                    yourhistory = "You have not voted yet."
                                else:

                                    # Get the client's voting history
                                    historyData = history_collection.find_one({"name": currentuser})
                                    yourhistory = "You have already voted at " + historyData["voted_datetime"]

                                ssl_conn.send(yourhistory.encode())
                
                            elif data == "4":

                                # Handle the case where the client wants to log out
                                print("Client logged out")
                                break
                                
                            else:

                                # Handle invalid client requests
                                ssl_conn.send("Invalid Request.".encode())

            # Basic exception handling
            except ssl.SSLError as e:
                print(f'SSL error: {e}')
                server_socket.close()
                ssl_conn.shutdown(socket.SHUT_RDWR)
                ssl_conn.close()
                mongo_client.close()
            except socket.error as e:
                print(f'Socket error: {e}')
                server_socket.close()
                ssl_conn.shutdown(socket.SHUT_RDWR)
                ssl_conn.close()
                mongo_client.close()



# Process 2
def process2(queue):
    while True:

        # Check if the queue is not empty and has "stop" message
        if not queue.empty() and queue.get() == "stop":
            
            # Break the loop and terminate the process
            break



if __name__ == '__main__':

    # Create a queue for inter-process communication
    queue = multiprocessing.Queue()

    # Create two separate processes for process1 and process2
    process_one = multiprocessing.Process(target=process1)
    process_two = multiprocessing.Process(target=process2, args=(queue,))

    # Start both processes
    process_one.start()
    process_two.start()

    while True:

        # Get user input to control server shutdown
        user_input = input("Enter 'shutdown' to stop the server. ")
        if user_input.lower() == "shutdown":

            # Terminate process one and send "stop" message to process two
            process_one.terminate()
            queue.put("stop")
            break
        else:
            print("Invalid server side command. Please use shutdown command to stop the server.")

    # Wait for both processes to complete
    process_one.join()
    process_two.join()

