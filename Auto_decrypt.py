import sys
if not sys.hexversion > 0x03000000:
    version = 2
else:
    version = 3
if len(sys.argv) > 1 and sys.argv[1] == "-cli":
    print("Starting command line chat")
    isCLI = True
else:
    isCLI = False


if version == 2:
    from Tkinter import *
    from tkFileDialog import asksaveasfilename
    from tkFileDialog import askopenfilename
    
if version == 3:
    from tkinter import *
    from tkinter.filedialog import asksaveasfilename
    from tkinter.filedialog import askopenfilename
import threading
import socket
import random
import math
import os
import subprocess
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64
import binascii
from diffiehellman import DiffieHellman



# GLOBALS
conn_array = []  # stores open sockets
secret_array = dict()  # key: the open sockets in conn_array,
                        # value: integers for encryption
username_array = dict()  # key: the open sockets in conn_array,
                        # value: usernames for the connection
contact_array = dict()  # key: ip address as a string, value: [port, username]
file_array = 0 # key: the open sockets in conn_array
                    # value: files for that connection

username = "Me"
SendFile = 0
location = 0
port = 0
top = ""
encrypt_msg = 0
decrypt_msg = 0
texttype = 0


main_body_text = 0
#-GLOBALS-

def Hash_msg(message):
    H = SHA256.new()
    H.update(message)
    hashed = H.digest()
    #print ("Length of message:",len(message))
    #print ("Hashed message:",hashed)
    return hashed
    

def pad(s):
    return s + ((16 - len(s) % 16 ) * b'}')

def xcrypt(message, key):
    """Encrypts the message by the secret key."""
    global texttype
    cipher = AES.new(key)
    encrypted = cipher.encrypt(pad(message))
    #print ("encrypted:",encrypted)
    if texttype == 1:
        writeToScreen(encrypted, "encrypted message")
        texttype = 0
    return encrypted

def dcrypt(message, key):
    """Decrypts the encrypted message by the secret key."""
    cipher = AES.new(key)
    decrypted = cipher.decrypt(message).rstrip(b'}')
    #print ("decrypted:",decrypted)
    return decrypted
    

def formatNumber(number):
    """Ensures that number is at least length 4 by
    adding extra 0s to the front.
    """
    temp = str(number) #formating to printable string
    while len(temp) < 4:
        temp = '0' + temp
    return temp

def SendtoSocket(conn, secret, message):
    """Sends message through the open socket conn with the encryption key
    secret. Sends the length of the incoming message, then sends the actual
    message.
    """
    global encrypt_msg
    
    try:
        if encrypt_msg == 1:
            #print ("Sending encrypted message")
            #print ("msg sending:", message)
            conn.send(formatNumber(len(xcrypt(message, secret))).encode())
            conn.send(xcrypt(message, secret))
        else:
            #print ("sending normal message")
            #print ("msg sending:",message)
            #print ("length of msg:", len(message))
            conn.send(formatNumber(len(message)).encode())
            conn.send(message)
    except socket.error:
        if len(conn_array) != 0:
            writeToScreen(
                "Connection issue. Sending message failed.", "System")
            processFlag("-001")


def RecievetoSocket(conn, secret):
    """Receive and return the message through open socket conn, decrypting
    using key secret. If the message length begins with - instead of a number,
    process as a flag and return 1.
    """
    global decrypt_msg
    try:
        data = conn.recv(4)
        #print (" recieved size:", data)
        if data.decode()[0] == '-':
            processFlag(data.decode(), conn)
            return 1
        if data.decode() == "Text":
            return "T"
        if data.decode() == "ONNN":
            decrypt_msg = 1
            return 1
        if data.decode() == "OFFF":
            decrypt_msg = 0
            return 1
        if data.decode() == "File":
            return "F"
        data = conn.recv(int(data.decode()))
        #print ("recieved data in RecievetoSocket:",data)
        if decrypt_msg == 1:
            print (" message is decrypting")
            return dcrypt(data, secret)     
        else:
            return data
    except socket.error:
        if len(conn_array) != 0:
            writeToScreen(
                "Connection issue. Receiving message failed.", "System")
        processFlag("-001")

def RecievetoSocket_file(conn, secret):
    """Receive and return the message through open socket conn, decrypting
    using key secret. If the message length begins with - instead of a number,
    process as a flag and return 1.
    """
    global decrypt_msg
    try:
        data = conn.recv(4)
        #print " recieved size:", data
        
        data = conn.recv(int(data.decode()))
        #data = conn.recv(int(data))
        #print "recieved data in RecievetoSocket:",data
        if decrypt_msg == 1:
            return dcrypt(data, secret)     
        else:
            return data
    except socket.error:
        if len(conn_array) != 0:
            writeToScreen(
                "Connection issue. Receiving message failed.", "System")
        processFlag("-001")

def isPrime(number):
    """Checks to see if a number is prime."""
    x = 1
    if number == 2 or number == 3:
        return True
    while x < math.sqrt(number):
        x += 1
        if number % x == 0:
            return False
    return True

def processFlag(number, conn=None):
    """Process the flag corresponding to number, using open socket conn
    if necessary.
    """
    global statusConnect
    global conn_array
    global secret_array
    global username_array
    global contact_array
    global isCLI
    t = int(number[1:])
    if t == 1:  # disconnect
        # in the event of single connection being left or if we're just a
        # client
        if len(conn_array) == 1:
            writeToScreen("Connection closed.", "System")
            dump = secret_array.pop(conn_array[0])
            dump = conn_array.pop()
            try:
                dump.close()
            except socket.error:
                print("Issue with someone being bad about disconnecting")
            if not isCLI:
                statusConnect.set("Connect")
                connecter.config(state=NORMAL)
            return

        if conn != None:
            writeToScreen("Connect to " + conn.getsockname()
                          [0] + " closed.", "System")
            dump = secret_array.pop(conn)
            conn_array.remove(conn)
            conn.close()

    if t == 2:  # username change
        name = RecievetoSocket(conn, secret_array[conn])
        if(isUsernameFree(name)):
            writeToScreen(
                "User " + username_array[conn] + " has changed their username to " + name, "System")
            username_array[conn] = name
            contact_array[
                conn.getpeername()[0]] = [conn.getpeername()[1], name]

    # passing a friend who this should connect to (I am assuming it will be
    # running on the same port as the other session)
    if t == 4:
        data = conn.recv(4)
        data = conn.recv(int(data.decode()))
        Client(data.decode(),
               int(contact_array[conn.getpeername()[0]][0])).start()

def processUserCommands(command, param):
    """Processes commands passed in via the / text input."""
    global conn_array
    global secret_array
    global username

    #print ("ProcessUserCommands")
    #print ("command:",command)
    #print ("param:", param)

    if command == "nick":  # change nickname
        for letter in param[0]:
            if letter == " " or letter == "\n":
                if isCLI:
                    error_window(0, "Invalid username. No spaces allowed.")
                else:
                    error_window(root, "Invalid username. No spaces allowed.")
                return
        if isUsernameFree(param[0]):
            writeToScreen("Username is being changed to " + param[0], "System")
            for conn in conn_array:
                conn.send("-002".encode())
                SendtoSocket(conn, secret_array[conn], param[0])
            username = param[0]
        else:
            writeToScreen(param[0] +
                          " is already taken as a username", "System")
    if command == "disconnect":  # disconnects from current connection
        for conn in conn_array:
            conn.send("-001".encode())
        processFlag("-001")
    if command == "connect":  # connects to passed in host port
        if(options_sanitation(param[1], param[0])):
            Client(param[0], int(param[1])).start()
    if command == "host":  # starts server on passed in port
        if(options_sanitation(param[0])):
            Server(int(param[0])).start()

def isUsernameFree(name):
    """Checks to see if the username name is free for use."""
    global username_array
    global username
    for conn in username_array:
        if name == username_array[conn] or name == username:
            return False
    return True

def passFriends(conn):
    """Sends conn all of the people currently in conn_array so they can connect
    to them.
    """
    global conn_array
    for connection in conn_array:
        if conn != connection:
            conn.send("-004".encode())
            conn.send(
                formatNumber(len(connection.getpeername()[0])).encode())  # pass the ip address
            conn.send(connection.getpeername()[0].encode())
            

#--------------------------------------------------------------------------

def client_options_window(master):
    """Launches client options window for getting destination hostname
    and port.
    """
    top = Toplevel(master)
    top.title("Connection options")
    top.protocol("WM_DELETE_WINDOW", lambda: optionDelete(top))
    top.grab_set()
    Label(top, text="Server IP:").grid(row=0)
    location = Entry(top)
    location.grid(row=0, column=1)
    location.focus_set()
    Label(top, text="Port:").grid(row=1)
    port = Entry(top)
    port.grid(row=1, column=1)
    go = Button(top, text="Connect", command=lambda:
                client_options_go(location.get(), port.get(), top))
    go.grid(row=2, column=1)

def client_options_go(dest, port, window):
    "Processes the options entered by the user in the client options window."""
    if options_sanitation(port, dest):
        if not isCLI:
            window.destroy()
        Client(dest, int(port)).start()
    elif isCLI:
        sys.exit(1)

def options_sanitation(por, loc=""):
    """Checks to make sure the port and destination ip are both valid.
    Launches error windows if there are any issues.
    """
    global root
    if version == 2:
        por = unicode(por)
    if isCLI:
        root = 0
    if not por.isdigit():
        error_window(root, "Please input a port number.")
        return False
    if int(por) < 0 or 65555 < int(por):
        error_window(root, "Please input a port number between 0 and 65555")
        return False
    if loc != "":
        if not ip_process(loc.split(".")):
            error_window(root, "Please input a valid ip address.")
            return False
    return True

def ip_process(ipArray):
    """Checks to make sure every section of the ip is a valid number."""
    if len(ipArray) != 4:
        return False
    for ip in ipArray:
        if version == 2:
            ip = unicode(ip)
        if not ip.isdigit():
            return False
        t = int(ip)
        if t < 0 or 255 < t:
            return False
    return True

#------------------------------------------------------------------------------

def server_options_window(master):
    """Launches server options window for getting port."""
    top = Toplevel(master)
    top.title("Connection options")
    top.grab_set()
    top.protocol("WM_DELETE_WINDOW", lambda: optionDelete(top))
    Label(top, text="Port:").grid(row=0)
    port = Entry(top)
    port.grid(row=0, column=1)
    port.focus_set()
    go = Button(top, text="Launch", command=lambda:
                server_options_go(port.get(), top))
    go.grid(row=1, column=1)

def server_options_go(port, window):
    """Processes the options entered by the user in the
    server options window.
    """
    if options_sanitation(port):
        if not isCLI:
            window.destroy()
        Server(int(port)).start()
    elif isCLI:
        sys.exit(1)

#-------------------------------------------------------------------------

def username_options_window(master):
    """Launches username options window for setting username."""
    top = Toplevel(master)
    top.title("Username options")
    top.grab_set()
    Label(top, text="Username:").grid(row=0)
    name = Entry(top)
    name.focus_set()
    name.grid(row=0, column=1)
    go = Button(top, text="Change", command=lambda:
                username_options_go(name.get(), top))
    go.grid(row=1, column=1)


def username_options_go(name, window):
    """Processes the options entered by the user in the
    server options window.
    """
    processUserCommands("nick", [name])
    window.destroy()

#-------------------------------------------------------------------------

def error_window(master, texty):
    """Launches a new window to display the message texty."""
    global isCLI
    if isCLI:
        writeToScreen(texty, "System")
    else:
        window = Toplevel(master)
        window.title("ERROR")
        window.grab_set()
        Label(window, text=texty).pack()
        go = Button(window, text="OK", command=window.destroy)
        go.pack()
        go.focus_set()

def optionDelete(window):
    connecter.config(state=NORMAL)
    window.destroy()

#-----------------------------------------------------------------------------


#-----------------------------------------------------------------------------

# places the text from the text bar on to the screen and sends it to
# everyone this program is connected to

def placeText(text):
    """Places the text from the text bar on to the screen and sends it to
    everyone this program is connected to.
    """
    global texttype
    global conn_array
    global secret_array
    global username
    writeToScreen(text, username)
    num = str(len(text))
    if encrypt_msg == 1:
        for person in conn_array:
            person.send("ONNN".encode())
    else:
        for person in conn_array:
            person.send("OFFF".encode())
    for person in conn_array:
        person.send("Text".encode())
    for person in conn_array:
        print ("len of key:",len(str(secret_array[person])))
        SendtoSocket(person, secret_array[person], num)
        texttype = 1
        SendtoSocket(person, secret_array[person], text) #sending over the connection
        SendtoSocket(person, secret_array[person], str(len(Hash_msg(text))))
        SendtoSocket(person, secret_array[person], Hash_msg(text))

def writeToScreen(text, username=""):
    """Places text to main text body in format "username: text"."""
    global main_body_text
    global isCLI
    if isCLI:
        if username:
            print(username + ": " + text)
        else:
            print(text)
    else:
        #widgets respond to keyboard and mouse events enabled
        main_body_text.config(state=NORMAL)
        main_body_text.insert(END, '\n') #inserting new line at the end
        if username:
            main_body_text.insert(END, username + ": ")
        main_body_text.insert(END, text)
        main_body_text.yview(END)
        #widgets respond to keyboard and mouse events enabled
        main_body_text.config(state=DISABLED)

def processUserFile():
    """Takes file from PC"""
    global conn_array
    global secret_array
    global username 
    global SendFile
    
    bytestoSend = []
    
    global fileType
    
    #print ("attaching File")
    filename = askopenfilename()
    
    f = open(filename,'rb')

    writeToScreen(filename ,username)
    size = os.path.getsize(filename)
    #print ("filename:",filename)
    #print ("file size being sent:", os.path.getsize(filename))
    
    drive, path = os.path.splitdrive(filename)
    path, filetitle = os.path.split(path)
    #print ("file name:",filetitle)
    #print ("Sending File")
    if encrypt_msg == 1:
        for person in conn_array:
            person.send("ONNN".encode())
    else:
        for person in conn_array:
            person.send("OFFF".encode())
    for person in conn_array:
        person.send("File".encode())
    for person in conn_array:
        SendtoSocket(person, secret_array[person],str(os.path.getsize(filename)))
    for person in conn_array:
        SendtoSocket(person, secret_array[person],filetitle)
    if encrypt_msg == 1:
        bytestoSend = f.read(1024)
        #print ("bytes:",bytestoSend)
        totalsent = len(bytestoSend)
        print ("total:",totalsent)
        for person in conn_array:
            SendtoSocket(person, secret_array[person],bytestoSend)
            SendtoSocket(person, secret_array[person],Hash_msg(bytestoSend))
        bytestoSend = []
        while totalsent < size:
            bytestoSend = []
            bytestoSend = f.read(1024)
            totalsent += len(bytestoSend)
            print ("total:",totalsent)
            #print ("bytes:",bytestoSend)
            for person in conn_array:
                SendtoSocket(person, secret_array[person],bytestoSend)
                SendtoSocket(person, secret_array[person],Hash_msg(bytestoSend))
                
        print ("File Sent")
        f.close()
    else:
        bytestoSend = f.read(1024)
        #print ("bytes:",bytestoSend)
        totalsent = len(bytestoSend)
        print ("total:",totalsent)
        for person in conn_array:
            SendtoSocket(person, secret_array[person],bytestoSend)
            SendtoSocket(person, secret_array[person],Hash_msg(bytestoSend))
        bytestoSend = []
        while totalsent < size:
            bytestoSend = []
            bytestoSend = f.read(1024)
            totalsent += len(bytestoSend)
            print ("total:",totalsent)
            #print ("bytes:",bytestoSend)
            for person in conn_array:
                SendtoSocket(person, secret_array[person],bytestoSend)
                SendtoSocket(person, secret_array[person],Hash_msg(bytestoSend))
                
        print ("File Sent")
        f.close()

    

def SendUserFile():
    global SendFile
    print (" choosing to send file")
    SendFile = 1

def Encrypt():
    global encrypt_msg
    print ("encryption enabled")
    encrypt_msg = 1
    

def Decrypt():
    global decrypt_msg
    print ("decryption enabled")
    decrypt_msg = 1

def Dis_Encrypt():
    global encrypt_msg
    print ("encryption disabled")
    encrypt_msg = 0

def Dis_Decrypt():
    global decrypt_msg
    print ("decryption disabled")
    decrypt_msg = 0    
    
    

def processUserText(event):
#def processUserText():
    """Takes text from text bar input and calls processUserCommands if it
    begins with '/'.
    """
    
    
    #print ("encrypt value:", encrypt_msg)
    #print ("User sending text messages")
    data = text_input.get()
    length = str(len(data))
    if data[0] != "/":  # is not a command
        #placeText(data,length)
        placeText(data)
    else:
        if data.find(" ") == -1:
            command = data[1:]
        else:
            command = data[1:data.find(" ")]
        print ("processUserText command:", command)
        params = data[data.find(" ") + 1:].split(" ") # spliting the data seperated by a space 
        processUserCommands(command, params)
    text_input.delete(0, END)
    #

def processUserInput(text):
    """ClI version of processUserText."""
    if text[0] != "/":
        placeText(text)
    else:
        if text.find(" ") == -1:
            command = text[1:]
        else:
            command = text[1:text.find(" ")]
        params = text[text.find(" ") + 1:].split(" ")
        processUserCommands(command, params)


#-------------------------------------------------------------------------

class Server (threading.Thread):
    "A class for a Server instance."""
    def __init__(self, port):
        threading.Thread.__init__(self)
        self.port = port

    def run(self):
        global conn_array
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', self.port))
##        s.bind(('', 1000))

        if len(conn_array) == 0:
            writeToScreen(
                "Socket is good, waiting for connections on port: " +
                str(self.port), "System")
##            writeToScreen(
##                "Socket is good, waiting for connections on port: " +
##                str(1000), "System")
        s.listen(1)
        global conn_init
        conn_init, addr_init = s.accept()
        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serv.bind(('', 0))  # get a random empty port
        serv.listen(1)

        portVal = str(serv.getsockname()[1])
        if len(portVal) == 5:
            conn_init.send(portVal.encode())
        else:
            conn_init.send(("0" + portVal).encode())

        conn_init.close()
        conn, addr = serv.accept()
        conn_array.append(conn)  # add an array entry for this connection
        writeToScreen("Connected by " + str(addr[0]), "System")

        global statusConnect
        statusConnect.set("Disconnect")
        connecter.config(state=NORMAL)

      
        self.alice = DiffieHellman()
        server_private = self.alice.generate_private_key()
        #print (" server private key:", server_private)
        server_public  = self.alice.generate_public_key()
        #print (" server public key:", server_public)

        
        conn.send(formatNumber(len(str(self.alice.public_key))).encode())
        conn.send(str(self.alice.public_key).encode())


        data = conn.recv(4)
        data = conn.recv(int(data.decode()))
        client_public = int(data.decode())

        self.alice.generate_shared_secret(client_public)
        secret = self.alice.shared_secret
        secret_array[conn] = self.alice.shared_key
        print(" session key at server:",secret)

        #Calculating hash
        digest_size = 32
        H = SHA256.new()
        H.update(str(secret))
        secret = H.digest()
        secret_array[conn] = secret
        #end of hash
        
        conn.send(formatNumber(len(username)).encode())
        conn.send(username.encode())

        data = conn.recv(4)
        data = conn.recv(int(data.decode()))
        if data.decode() != "Self":
            username_array[conn] = data.decode()
            contact_array[str(addr[0])] = [str(self.port), data.decode()]
        else:
            username_array[conn] = addr[0]
            contact_array[str(addr[0])] = [str(self.port), "No_nick"]

        passFriends(conn)
        threading.Thread(target=Runner, args=(conn, secret)).start()
        Server(self.port).start()


class Client (threading.Thread):
    """A class for a Client instance."""
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.port = port
        self.host = host

    def run(self):
        global conn_array
        global secret_array
        
        conn_init = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_init.settimeout(5.0)
        try:
            conn_init.connect((self.host, self.port))
##            conn_init.connect((socket.gethostname(), 1000))
        except socket.timeout:
            writeToScreen("Timeout issue. Host possible not there.", "System")
            connecter.config(state=NORMAL)
            raise SystemExit(0)
        except socket.error:
            writeToScreen(
                "Connection issue. Host actively refused connection.", "System")
            connecter.config(state=NORMAL)
            raise SystemExit(0)
        porta = conn_init.recv(5)
        porte = int(porta.decode())
        conn_init.close()
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((self.host, porte))

        writeToScreen("Connected to: " + self.host +
                      " on port: " + str(porte), "System")

        global statusConnect
        statusConnect.set("Disconnect")
        connecter.config(state=NORMAL)

        conn_array.append(conn)

        data = conn.recv(4)
        #print (" key size:", data)
        data = conn.recv(int(data.decode()))
        #print (" key recieved:", data)
        #server_public = int(data.decode())
        server_public = int(data.decode())

        self.bob = DiffieHellman()
        client_private = self.bob.generate_private_key()
        #print ("client private key:", client_private)
        self.bob.generate_public_key()
        #print ("client public key true:", self.bob.public_key)

        conn.send(formatNumber(len(str(self.bob.public_key))).encode())
        conn.send(str(self.bob.public_key).encode())

        self.bob.generate_shared_secret(server_public)
        secret = self.bob.shared_secret
        secret_array[conn] = self.bob.shared_key
        print(" session key at client:",secret)
        
        #Calculating hash
        digest_size = 32
        H = SHA256.new()
        H.update(str(secret))
        secret = H.digest()
        secret_array[conn] = secret

        #end of hash

        conn.send(formatNumber(len(username)).encode())
        conn.send(username.encode())

        data = conn.recv(4)
        data = conn.recv(int(data.decode()))
        if data.decode() != "Self":
            username_array[conn] = data.decode()
            contact_array[
                conn.getpeername()[0]] = [str(self.port), data.decode()]
        else:
            username_array[conn] = self.host
            contact_array[conn.getpeername()[0]] = [str(self.port), "No_nick"]
        threading.Thread(target=Runner, args=(conn, secret)).start()
        

def Runner(conn, secret):
    global username_array
    global file_array
    global decrypt_msg
    while 1:
        typ = RecievetoSocket(conn , secret)
        #check if the recived is Text
        if typ == "T":
            #recieve size of the information
            size = RecievetoSocket(conn , secret)
            #print ("size of text:", size)
            #recieve information
            data = RecievetoSocket(conn , secret)
            total = len(data)
            #check if the data
            if data !=1:
                writeToScreen(data , username_array[conn])
            # check if complete message of size is recieved
            while total < int(size):
                data = RecievetoSocket(conn, secret)
                total += len(data)
                if data !=1:
                    writeToScreen(data , username_array[conn])
            hash_size = RecievetoSocket(conn , secret)
            hashed = RecievetoSocket(conn, secret)
            total_hash = len(hashed)
            while total_hash < int(hash_size):
                hashed = RecievetoSocket(conn, secret)
                total_hash += len(hashed)
            text_hash = Hash_msg(data)
            if hashed != text_hash:
                integrity = 1
            elif hashed == text_hash:
                integrity = 0
            if integrity == 1:
                writeToScreen("Integrity is voilated", username_array[conn])
            else:
                writeToScreen("Integrity is maintained", username_array[conn])
        #check if the recived is File
        elif typ == "F":
            #recieve size of the information
            size = RecievetoSocket(conn, secret)
            #print ("size of file:", size)
            #recieve file name
            filerecv = RecievetoSocket(conn, secret)
            #print ("file received:", filerecv)
            #open a file in write binary mode
            f = open(filerecv, 'wb')
            #recieve information
            #data = RecievetoSocket(conn, secret)
            data = RecievetoSocket_file(conn, secret)
            #print ("file data recieved:",data)
            #print ("img recieved as:", type(data))
            total = len(data)
            print ("total recieved:",total)
            f.write(data)
            hashed = RecievetoSocket_file(conn, secret)
            #hashed = RecievetoSocket(conn, secret)
            file_hash =  Hash_msg(data)
            if hashed != file_hash:
                integrity = 1
            elif hashed == file_hash:
                integrity = 0
            # check if complete message of size is recieved
            while total < int(size):
                #data = RecievetoSocket(conn, secret)
                data = RecievetoSocket_file(conn, secret)
                #print ("data in while:", data)
                total += len(data)
                print ("total recieved:",total)
                f.write(data)
                hashed = RecievetoSocket_file(conn, secret)
                #hashed = RecievetoSocket(conn, secret)
                file_hash =  Hash_msg(data)
                if hashed != file_hash:
                    integrity = 1
                elif hashed == file_hash:
                    integrity = 0
            if integrity == 1:
                writeToScreen("Integrity is voilated", username_array[conn])
            else:
                writeToScreen("Integrity is maintained", username_array[conn])
            print (" total recieved:", total)
            print ("complete file recieved and written")
            writeToScreen("Complete "+filerecv+" file recieved", username_array[conn])
            f.close()

                


#-------------------------------------------------------------------------
# Menu helpers

def QuickClient():
    """Menu window for connection options."""
    window = Toplevel(root)
    window.title("Connection options")
    window.grab_set()
    Label(window, text="Server IP:").grid(row=0)
    destination = Entry(window)
    destination.grid(row=0, column=1)
    go = Button(window, text="Connect", command=lambda:
                client_options_go(destination.get(), "9999", window))
    go.grid(row=1, column=1)


def QuickServer():
    """Quickstarts a server."""
    Server(9999).start()

def saveHistory():
    """Saves history with Tkinter's asksaveasfilename dialog."""
    global main_body_text
    file_name = asksaveasfilename(
        title="Choose save location",
        filetypes=[('Plain text', '*.txt'), ('Any File', '*.*')])
    try:
        filehandle = open(file_name + ".txt", "w")
    except IOError:
        print("Can't save history.")
        return
    contents = main_body_text.get(1.0, END)
    for line in contents:
        filehandle.write(line)
    filehandle.close()


def connects(clientType):
    global conn_array
    connecter.config(state=DISABLED)
    if len(conn_array) == 0:
        if clientType == 0:
            client_options_window(root)
        if clientType == 1:
            server_options_window(root)
    else:
        # connecter.config(state=NORMAL)
        for connection in conn_array:
            connection.send("-001".encode())
        processFlag("-001")


def toOne():
    global clientType
    clientType = 0


def toTwo():
    global clientType
    clientType = 1


#-------------------------------------------------------------------------


if len(sys.argv) > 1 and sys.argv[1] == "-cli":
    print("Starting command line chat")

else:
    root = Tk()
    root.title("Chat")

    menubar = Menu(root) #creates Menu for the parent window root
    
    #creating file Menu from parent menu menubar
    file_menu = Menu(menubar, tearoff=0) # tearoff=0 bcz to add choices at position 0
    
    file_menu.add_command(label="Save chat", command=lambda: saveHistory()) #Adding menu item to the menu
    
    file_menu.add_command(label="Change username",
                          command=lambda: username_options_window(root))
    file_menu.add_command(label="Exit", command=lambda: root.destroy())
    
    menubar.add_cascade(label="File", menu=file_menu) #Creates a new hierarchical menu by associating a given menu to a parent menu


    #configuring root with menu as menubar

    root.config(menu=menubar)

    main_body = Frame(root, height=20, width=50)

    #creating Text widget
    
    main_body_text = Text(main_body)
    #cteting scrollcar
    body_text_scroll = Scrollbar(main_body)
    
    main_body_text.focus_set()
    body_text_scroll.pack(side=RIGHT, fill=Y)
    main_body_text.pack(side=LEFT, fill=Y)
    body_text_scroll.config(command=main_body_text.yview)
    main_body_text.config(yscrollcommand=body_text_scroll.set)
    main_body.pack()

    main_body_text.insert(END, "Welcome to UL chat Box!")
    main_body_text.config(state=DISABLED)

    text_input = Entry(root, width=80)
    text_input.pack(ipady=10)

    
    #inputType = 0
    text_input.bind("<Return>", processUserText)
    text_input.pack()

    statusConnect = StringVar()
    statusConnect.set("Connect")
    clientType = 1
    #radio button for choosing as client and value is set to 0 and appears at the end
    Radiobutton(root, text="Client", variable=clientType,
                value=0, command=toOne).pack(anchor=E)
    #radio button for choosing as client and value is set to 1 and appears at the end
    Radiobutton(root, text="Server", variable=clientType,
                value=1, command=toTwo).pack(anchor=E)
    connecter = Button(root, textvariable=statusConnect,
                       command=lambda: connects(clientType))
    connecter.pack(side=LEFT, padx=10)
    
    C_image = PhotoImage(file="e:\\connect.gif")
    c_image = C_image.subsample(4,5)
    connecter.config(image = c_image, compound =TOP)
    
    send = Button(root, text="Send")#,command = SendUserFile)
    S_image = PhotoImage(file="e:\\Send_forward.gif")
    send.pack(side=LEFT, padx=10)
    s_image = S_image.subsample(3,4)
    send.config(image = s_image , compound = TOP)
    
    attach = Button(root, text="Attach" ,command = processUserFile)
    A_image = PhotoImage(file="e:\\attach.gif")
    attach.pack(side=LEFT, padx=10)
    a_image = A_image.subsample(4,5)
    attach.config(image = a_image, compound =TOP)

    encrypt = Button(root, text="Enable Encrypt", command = Encrypt)
    encrypt.pack(side=LEFT, padx=10)


    dis_encrypt = Button(root, text="Disable Encrypt", command = Dis_Encrypt)
    dis_encrypt.pack(side=LEFT, padx=10)

    

#------------------------------------------------------------#

    root.mainloop()

