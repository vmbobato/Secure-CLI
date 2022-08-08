import socket
import hashlib
import json

server_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip = 'localhost'
port = 9999
server_s.bind((ip, port))


# functions declared
def rsa(plaintxt, n, publ_key):
    numEncrypt = []
    plaintxt = list(plaintxt)
    cipher = ''

    for letter in plaintxt:
        numEncrypt.append(ord(letter))
    for number in numEncrypt:
        encrypt = (number ** publ_key) % n
        cipher += chr(encrypt)
    return cipher


def d_rsa(ciphertxt, n, priv_key):
    numDecrypt = []
    plaintxt = ''
    ciphertxt = list(ciphertxt)

    for letter in ciphertxt:
        numDecrypt.append(ord(letter))
    for number in numDecrypt:
        decrypt = (number ** priv_key) % n
        plaintxt += chr(decrypt)
    return plaintxt


def receive():
    global addr
    message, addr = server_s.recvfrom(1024)
    message = message.decode()
    return message


def send(data):
    global addr
    server_s.sendto(data.encode(), addr)
    pass


# values related to key
ps = 47
qs = 71
ns = ps * qs
pu_k = [97, ns]
pr_k = [1693, ns]

# sharing and receiving public keys
clientKey = int(receive())
print('Received key: ', clientKey)
send(str(pu_k[0]))
print('Sent Key: ', str(pu_k[0]))
nClient = int(receive())
print('Received N: ', nClient)
send(str(pu_k[1]))
print('Sent N: ', str(pu_k[1]))

# setting logged state
logged = False

# receiving command until connection is cut
while True:
    command = receive()
    command = d_rsa(command, ns, pr_k[0])

    # register algorithm
    if command == 'REGISTER':
        # dict template
        user = {'Last Name': '',
                'First Name': '',
                'Major': '',
                'Hometown': '',
                'Username': '',
                'Password': ''}

        # sending each key as a prompt and receiving info regarding key
        for key in user:
            text = key + ': '
            cypher = rsa(text, nClient, clientKey)
            send(cypher)
            print('SENT:' + key)
            data = receive()
            data = d_rsa(data, ns, pr_k[0])
            print(key + ': ' + '********')

            # in case key is password save after hash
            if key == 'Password':
                hash_object = hashlib.sha256(data.encode())
                hex_dig = hash_object.hexdigest()
                user[key] = hex_dig
            else:
                user[key] = data

            # opening user json and saving info
            filename = user.get('Username') + '.json'
            with open(filename, 'w') as file:
                json.dump(user, file)

        # confirming registration
        send(rsa('Registration Successful!\n', nClient, clientKey))

    # log in algorithm
    elif command[:5] == 'login':
        try:
            # try opening file
            filename = command[6:] + '.json'
            with open(filename, 'r') as file:
                info = json.load(file)

            # requesting password
            send(rsa('Password: ', nClient, clientKey))
            pwd = receive()
            pwd = d_rsa(pwd, ns, pr_k[0])

            # hashing and comparing
            hash_object1 = hashlib.sha256(pwd.encode())
            hex_dig1 = hash_object1.hexdigest()

            if info.get('Password') != hex_dig1:
                send(rsa('Invalid Password.\n', nClient, clientKey))
            else:
                logged = True
                send(rsa('Log-in Successful!\n', nClient, clientKey))

        except:
            # if no such file in directory means user not found
            print('User not found!')
            send(rsa('User not registered yet.\n', nClient, clientKey))

    # view registration algorithm
    elif command == 'vres':
        # calling string
        text = '\n'
        if logged:
            print(info)
            # if login successful user info is saved in info
            # iterate through all items skipping password
            for key in info:
                if key != 'Password':
                    text += key + ': ' + info[key] + '\n'

            send(rsa(text, nClient, clientKey))
        else:
            send(rsa('Not Logged-in yet.\n', nClient, clientKey))
    # log off command
    elif command == 'logoff':
        logged = False
        send(rsa('Logoff Successful!', nClient, clientKey))
    # help command
    elif command == 'help':
        helpStr = '''
            Howdy! Here are different commands to use.
            All of them are case sensitive. 
            Make sure to write the appropriate command!
            - REGISTER
            - LOG_IN 'username'
            - LOG_OFF
            - VIEW_REGISTRATION (after login)\n'''
        send(rsa(helpStr, nClient, clientKey))
    # invalid command
    else:
        send(rsa('invalid', nClient, clientKey))
