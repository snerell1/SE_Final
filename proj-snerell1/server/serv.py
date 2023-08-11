"""
This module provides functionality related to networking and SSL encryption.

It includes functions to work with sockets and SSL connections, as well as
utility functions for handling networking tasks.
"""

import multiprocessing
import socket
import ssl
import hashlib
import sys
import datetime
import random

import pymongo


# Process 1

def process1():
    """
    Set up the MongoDB database and create necessary collections.
    """
    # Connect to the local MongoDB server
    mongo_client = pymongo.MongoClient("mongodb://localhost:27017/")
    database = mongo_client["voting_db"]
    existing_collections = database.list_collection_names()
    collection_list = ["voters", "history", "results", "admin"]

    # Loop through the collection list and create collections if they don't exist
    for collection in collection_list:
        if collection not in existing_collections:
            # Create the collections
            database.create_collection(collection)

            # Initialize data for specific collections
            if collection == "results":
                # result_hard_data = [
                #     {
                #         "name": "Chris",
                #         "cid": "1000",
                #         "votes": 0,
                #     },
                #     {
                #         "name": "Linda",
                #         "cid": "1001",
                #         "votes": 0,
                #     },
                # ]
                results_collection = database["results"]
                # results_collection.insert_many(result_hard_data)

            elif collection == "admin":
                admin_hard_data = [
                    {
                        "name": "Admin",
                        "password": 
                            "0a6ed5e0e36f90cd7e4a324124f55617bf342b00931e2ab03eb85d633aeac333",
                        "results": False,
                        "voting": False,
                        "role": "admin",
                        "won": "",
                        "won_cid": 0,
                    }
                ]
                admin_collection = database["admin"]
                admin_collection.insert_many(admin_hard_data)

            else:
                pass

        # Assign collections to variables for easier access
        voters_collection = database["voters"]
        history_collection = database["history"]
        results_collection = database["results"]
        admin_collection = database["admin"]

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
    print("Server started and listening...")

    while True:
        while True:
            # Sending response
            def send_message(message):
                ssl_conn.sendall(message.encode())

            with open("symmetric.key", "rb") as file_name:
                symmetric_key = file_name.read()

            # Function to validate admin login
            def adminlogin(name, password):
                # Fetch admin data from the admin collection
                admindata = admin_collection.find_one({"name": name})
                encrypted_password = admindata["password"]

                # Hash the provided password with the
                # symmetric key and compare with stored encrypted password
                hash_password = hashlib.sha256(
                    symmetric_key + bytes(password, "utf-8")
                ).hexdigest()

                if hash_password == encrypted_password:
                    return True

                return "incorrect password"

            # Function to verify user's password
            def verify_password(regno, password):
                # Find user data in the voters collection using registration number
                if not voters_collection.find_one({"regno": int(regno)}):
                    return "incorrect regno"

                userdata = voters_collection.find_one({"regno": int(regno)})

                encrypted_password = userdata["password"]

                hash_password = hashlib.sha256(
                    symmetric_key + bytes(password, "utf-8")
                ).hexdigest()

                if hash_password == encrypted_password:
                    return True

                return "incorrect password"

            # Function for client registration
            def client_register():
                while True:
                    # Receive and capitalize the user's name
                    # from the client to match data in collection
                    name = ssl_conn.recv(1024).decode().capitalize()
                    if (
                        not voters_collection.find_one({"name": name})
                        and name != "Admin"
                    ):
                        send_message("OK")
                    else:
                        send_message("Username already exists")
                        continue
                    break

                # Receive registration details from the client
                message = ssl_conn.recv(1024).decode().strip()
                name, password = message.split(",")
                while True:
                    # Generate a random registration number within a specified range
                    regno = random.randint(100000, 999999)
                    if voters_collection.find_one({"regno": regno}):
                        continue
                    break

                # Hash the provided password with the symmetric key
                hash_password = hashlib.sha256(
                    symmetric_key + bytes(password, "utf-8")
                ).hexdigest()

                # Create voter data for insertion into the voters collection
                voter_data = {
                    "name": name.capitalize(),
                    "regno": regno,
                    "password": hash_password,
                    "role": "voter",
                }
                voters_collection.insert_one(voter_data)
                response = "OK"

                # Send response and registration number to the client
                connection = f"{response},{regno}".encode()
                ssl_conn.sendall(connection)

            admindata = admin_collection.find_one({"name": "Admin"})

            # Function to check if voting is enabled
            def voting_enabled():
                if admindata["voting"] is False:
                    message = "Voting not started yet."
                else:
                    message = "Voting enabled"
                return message

            # Function to check if candidates are present
            def candidates_present():
                if results_collection.count_documents({}) == 0:
                    message = "No candidates present. Please add a candidate first."
                else:
                    message = "candidates present."
                return message

            # Function to check if voters are present
            def voters_present():
                if voters_collection.count_documents({}) == 0:
                    message = "No voters registered yet."
                else:
                    message = "voters registered."
                return message

            # Function to check if atleast one vote is casted
            def votes_casted():
                if history_collection.count_documents({}) == 0:
                    message = "No one voted yet."
                else:
                    message = "voters voted."
                return message

            # Function to check if voting is closed
            def voting_closed():
                if admindata["results"] is True:
                    message = "Voting closed."
                else:
                    message = "Voting not closed"
                return message

            # Function to check if results are declared
            def results_declared():
                if admindata["results"] is not True:
                    message = "not available"
                else:
                    message = "available"
                return message

            def check_personal_history(currentuser):
                if not history_collection.find_one({"name": currentuser}):
                    message = "You have not voted yet."
                else:
                    history_data = history_collection.find_one({"name": currentuser})
                    message = (
                        "You have already voted at " + history_data["voted_datetime"]
                    )
                return message

            try:
                # Accept incoming client connection
                connection, client_address = server_socket.accept()
                print(f"Client connected from {client_address}")
                ssl_conn = context.wrap_socket(connection, server_side=True)

                while True:
                    # Receive data from the client
                    data = ssl_conn.recv(1024).decode()

                    # Handle different client requests
                    if data == "login":
                        # Option to login goes down
                        pass

                    elif data == "register":
                        # Option to register
                        client_register()
                        continue

                    elif data == "exit":
                        # Client chose to exit
                        print("System disconnected")
                        break

                    else:
                        continue

                    # Receive and process client authentication details
                    message = ssl_conn.recv(1024).decode().strip()
                    name, regno, password = message.split(",")
                    currentuser = name.capitalize()

                    # Validate admin login or user's password
                    if name == "Admin":
                        result = adminlogin(name, password)

                    else:
                        result = verify_password(regno, password)

                    # Handle invalid authentication
                    if result in ("incorrect regno", "incorrect password"):
                        text = "Authentication failed."
                        print("Authentication failed.")
                        send_message(text)
                        continue


                    text = "OK"
                    if name == "Admin":
                        print("Admin logged in")
                    else:
                        print("Client logged in")
                    send_message(text)

                    while True:
                        # Receive further requests from the client
                        data = ssl_conn.recv(1024).decode()

                        # Fetch admin data from the collection
                        admindata = admin_collection.find_one({"name": "Admin"})

                        if currentuser == "Admin":
                            # Handle admin-specific requests
                            if data == "check votes":
                                # Request: Check votes registered

                                # Check if voting has not yet started
                                message = voting_enabled()
                                if message != "Voting enabled":
                                    send_message(message)
                                    continue

                                # Check if there are no candidates present
                                message = candidates_present()
                                if message != "candidates present.":
                                    send_message(message)
                                    continue

                                # Check if there are no voters registered
                                message = voters_present()
                                if message != "voters registered.":
                                    pass
                                else:
                                    total_votes_registered = (
                                        history_collection.count_documents({})
                                    )
                                    message = (
                                        str(total_votes_registered)
                                        + " out of "
                                        + str(voters_collection.count_documents({}))
                                        + " votes registered."
                                    )
                                send_message(message)

                            elif data == "declare results":
                                # Request: Declare results

                                # Check if voting has not yet started
                                message = voting_enabled()
                                if message != "Voting enabled":
                                    send_message(message)
                                    continue

                                # Check if there are no candidates present
                                message = candidates_present()
                                if message != "candidates present.":
                                    send_message(message)
                                    continue

                                # Create an index for sorting candidates by
                                # votes in descending order to get highest votes
                                results_collection.create_index(
                                    [("votes", pymongo.DESCENDING)]
                                )
                                highest_votes_document = results_collection.find_one(
                                    {}, sort=[("votes", pymongo.DESCENDING)]
                                )

                                # Find candidates with tied votes
                                tied_candidates = results_collection.find(
                                    {"votes": highest_votes_document["votes"]}
                                )
                                tied_candidates_list = list(tied_candidates)

                                # If there are more than one tied candidates
                                # choose a random winner from them
                                if len(tied_candidates_list) > 1:
                                    winner = random.choice(tied_candidates_list)
                                else:
                                    # If there is no tie, the winner
                                    # is the candidate with the highest votes
                                    winner = highest_votes_document

                                # Check if results have already been declared
                                if admindata["results"] is True:
                                    message = (
                                        "Results already declared. "
                                        + "Won: "
                                        + admindata["won"]
                                        + " ("
                                        + str(admindata["won_cid"])
                                        + ")"
                                        + "\n"
                                    )
                                else:
                                    # Check if no votes have been cast yet
                                    message = votes_casted()
                                    if message == "No one voted yet.":
                                        send_message(message)
                                        continue

                                    # Send confirmation request to declare results
                                    send_message(
                                        "Please confirm to declare: \n1. Yes\n2. No\n"
                                    )
                                    response = ssl_conn.recv(1024).decode()
                                    if response != "1":
                                        send_message("Not declared.")
                                        continue

                                    # Update the admin data to indicate results declaration
                                    admindata["results"] = True
                                    admin_collection.update_one(
                                        {"_id": admindata["_id"]},
                                        {
                                            "$set": {
                                                "results": admindata["results"],
                                                "won": winner["name"],
                                                "won_cid": int(
                                                    winner["cid"]
                                                ),
                                            }
                                        },
                                    )
                                    message = (
                                        "Results declared.\n"
                                        + "Won: "
                                        + highest_votes_document["name"]
                                        + " ("
                                        + highest_votes_document["cid"]
                                        + ")"
                                        + "\n"
                                    )
                                send_message(message)

                            elif data == "add new candidate":
                                # Request: Add candidate

                                # Check if results are already declared
                                if admindata["results"] is True:
                                    send_message(
                                        "Voting has concluded, cannot add a candidate now."
                                    )
                                    continue

                                # Check if voting has already started
                                if admindata["voting"] is True:
                                    send_message(
                                        "Voting already started, cannot add a candidate now."
                                    )
                                    continue
                                send_message("OK")

                                # Receive the candidate details from the admin
                                message = ssl_conn.recv(1024).decode().strip()
                                cname, cid = message.split(",")

                                # Check if the candidate with the given CID already exists
                                if not results_collection.find_one({"cid": cid}):
                                    # If not, insert the new candidate into the results collection
                                    result_hard_data = [
                                        {
                                            "name": cname.capitalize(),
                                            "cid": cid,
                                            "votes": 0,
                                        }
                                    ]
                                    results_collection.insert_many(result_hard_data)
                                    message = "Successfully added new candidate"
                                    send_message(message)
                                else:
                                    # If candidate with given CID already exists
                                    # send a message indicating that
                                    message = "Candidate with given CID already exists."
                                    send_message(message)

                            elif data == "start election":
                                # Request: Start Election

                                # Check if results are already declared
                                if admindata["results"] is True:
                                    send_message("Voting has concluded.")
                                    continue

                                # Check if voting has already started
                                if admindata["voting"] is True:
                                    message = "Voting already started."
                                else:
                                    # Check if there are no candidates present
                                    if results_collection.count_documents({}) == 0:
                                        send_message(
                                            "No candidates present. Please add a candidate first."
                                        )
                                        continue
                                    send_message(
                                        "Please confirm to start: \n1. Yes\n2. No\n"
                                    )
                                    response = ssl_conn.recv(1024).decode()

                                    # Check if the admin confirms to start the election
                                    if response != "1":
                                        send_message("Not started.")
                                        continue

                                    # Update the admin data to indicate that voting has started
                                    admindata["voting"] = True
                                    admin_collection.update_one(
                                        {"_id": admindata["_id"]},
                                        {"$set": {"voting": admindata["voting"]}},
                                    )
                                    message = "Voting started."
                                send_message(message)

                            elif data == "sign out":
                                # Request: Admin logout
                                print("Admin logged out")
                                break

                            else:
                                # Invalid request, send appropriate response
                                ssl_conn.send("Invalid Request.".encode())

                        else:
                            # Handle user-specific requests
                            if data == "vote":
                                # Handle the case where the client wants to vote

                                # Check if voting has not started yet
                                message = voting_enabled()
                                if message != "Voting enabled":
                                    send_message(message)
                                    continue

                                # Check if results are already declared
                                message = voting_closed()
                                if message == "Voting closed.":
                                    send_message(message)
                                    continue

                                # Check if the client has already voted
                                if history_collection.find_one({"name": currentuser}):
                                    send_message("already voted")

                                else:
                                    # Prepare the list of candidates for the client to choose from
                                    userdata = results_collection.find({})
                                    index = 0
                                    candidate_names = []
                                    for document in userdata:
                                        index = index + 1
                                        candidate_names.append(
                                            [index, document["name"], document["cid"]]
                                        )

                                    # Create a formatted message for
                                    # candidate selection and send to client
                                    candidate_response = (
                                        "Choose your candidate\n"
                                        + "\n".join(
                                            [
                                                f"{index}. {name} ({cid})"
                                                for index, name, cid in candidate_names
                                            ]
                                        )
                                    )
                                    ssl_conn.send(candidate_response.encode())
                                    candidate_choice = int(ssl_conn.recv(1024).decode())

                                    # Check if the client's choice is valid
                                    if 1 <= candidate_choice <= len(candidate_names):
                                        # Update the candidate's vote count
                                        selected_candidate = candidate_names[
                                            candidate_choice - 1
                                        ][2]
                                        resultdata = results_collection.find_one(
                                            {"cid": selected_candidate}
                                        )
                                        resultdata["votes"] += 1
                                        results_collection.update_one(
                                            {"_id": resultdata["_id"]},
                                            {"$set": {"votes": resultdata["votes"]}},
                                        )

                                        # Record the vote in the history collection
                                        now = datetime.datetime.now()
                                        votedtime = now.strftime("%Y-%m-%d %H:%M:%S")
                                        history_data = {
                                            "name": currentuser,
                                            "regno": int(regno),
                                            "voted_datetime": votedtime,
                                        }
                                        history_collection.insert_one(history_data)
                                        ssl_conn.send(
                                            "Thank you for your vote!\n".encode()
                                        )

                                    else:
                                        ssl_conn.send(
                                            ("Invalid candidate choice. Please choose a valid "
                                                "candidate.\n").encode()
                                        )

                            elif data == "check results":
                                # Handle the case where the client wants to view election results

                                # Check if results are declared
                                message = results_declared()
                                if message != "available":
                                    send_message(message)
                                else:
                                    # Get the candidate with the highest votes
                                    results_collection.create_index(
                                        [("votes", pymongo.DESCENDING)]
                                    )
                                    highest_votes_document = (
                                        results_collection.find_one(
                                            {}, sort=[("votes", pymongo.DESCENDING)]
                                        )
                                    )

                                    # Prepare and send the message indicating the winning candidate
                                    message = (
                                        "Won: "
                                        + highest_votes_document["name"]
                                        + " ("
                                        + highest_votes_document["cid"]
                                        + ")"
                                        + "\n"
                                    )
                                    ssl_conn.send(message.encode())

                            elif data == "vote history":
                                # Handle the case where the client
                                # wants to view their voting history

                                # Check if the client has not voted yet
                                message = check_personal_history(currentuser)
                                if message == "You have not voted yet.":
                                    pass
                                else:
                                    pass
                                send_message(message)

                            elif data == "User sign out":
                                # Handle the case where the client wants to log out
                                print("Client logged out")
                                break

                            else:
                                # Handle invalid client requests
                                ssl_conn.send("Invalid Request.".encode())

            # Basic exception handling
            except ssl.SSLError as exception:
                print(f"SSL error: {exception}")
                server_socket.close()
                ssl_conn.shutdown(socket.SHUT_RDWR)
                ssl_conn.close()
                mongo_client.close()
            except socket.error as exception:
                print(f"Socket error: {exception}")
                server_socket.close()
                ssl_conn.shutdown(socket.SHUT_RDWR)
                ssl_conn.close()
                mongo_client.close()


# Process 2
def process2(queue_param):
    """
    Process data from the given queue.
    
    This function continuously checks the provided queue for items. If an item
    with the value "stop" is encountered, the loop will break and the process
    will terminate.
    
    Args:
        queue_param (Queue): The queue to process.
    """
    while True:
        # Check if the queue is not empty and has "stop" message
        if not queue_param.empty() and queue_param.get() == "stop":
            # Break the loop and terminate the process
            break


if __name__ == "__main__":
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
        print(
            "Invalid server side command. Please use shutdown command to stop the server."
        )

    # Wait for both processes to complete
    process_one.join()
    process_two.join()
