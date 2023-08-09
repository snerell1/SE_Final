This is the final project for a Software Engineering course, introducing a secure university voting system called GradChoice.

In this document, you can access comprehensive details about the project.
Design document: https://docs.google.com/document/d/14wMavdgkrjY5JedEJo8jzUhE8jK-lgRKffVKLefrCi0/edit

In addition to the provided information, we have incorporated several additional options (features) tailored for administrators.

The application consists of two main components: the Client and the Server.

To initiate the server:
Navigate to the server directory and execute the following command:

**py serv.py 1026**

-> Here, 1026 represents a port number, which you should select from the range of 1024 to 65535.
-> "serv.py" is the filename.

To stop the server, employ the "shutdown" command. This functionality is implemented using multithreading.

For launching the client:
Access the client directory and input the following command:

**py cli.py <hostname> 1026**

-> "cli.py" is the filename.
-> 1026 corresponds to the port number, which should match the server's port number.
-> "<hostname>" signifies your host, where the server is operational. If the server is remote, you can designate it as remote01 to remote07 (or more).
I
f running locally, you can ascertain your hostname by entering "hostname" in your terminal.

