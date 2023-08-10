This is the final project for a Software Engineering course, introducing a secure university voting system called GradChoice.

In this document, you can access comprehensive details about the project.
Design document: https://docs.google.com/document/d/14wMavdgkrjY5JedEJo8jzUhE8jK-lgRKffVKLefrCi0/edit

In addition to the provided information, we have incorporated several additional options (features) tailored for administrators.

Before runinng the server you need to install Mongodb in your local system from this link.

https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-6.0.8-signed.msi

After installing, you can use Monogodb compass tool to work with data inside your MongoDB

you can download mongodb compass from following link:

https://downloads.mongodb.com/compass/mongodb-compass-1.39.1-win32-x64.exe

After installation, to connect the python code to your monogo server. You need to install Pymongo extension. you can do that by using this command : (you must have pip installed in your local to do that)

pip install pymongo

Now, the application consists of two main components: the Client and the Server.

You need to start the server first and keep it running, once server is started and running then you should start client in new terminal.

Without server running, client cannot access the server data, it throws an error.

To initiate the server:
Navigate to the server directory and execute the following command:

py serv.py 1026

-> Here, 1026 represents a port number, which you should select from the range of 1024 to 65535.
-> "serv.py" is the filename.

To stop the server, employ the "shutdown" command. This functionality is implemented using multithreading.

For launching the client:
Access the client directory and input the following command:

py cli.py <hostname> 1026

-> "cli.py" is the filename.
-> 1026 corresponds to the port number, which should match the server's port number.
-> "<hostname>" signifies your host, where the server is operational. If the server is remote, you can designate it as remote01 to remote07 (or more).

for running locally, you can ascertain your hostname by entering "hostname" in your terminal.

