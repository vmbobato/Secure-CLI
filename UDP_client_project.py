import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
port = 9999

# Include the server Address
serverAddr = ('localhost', port)


# functions declared
def receive():
    message, addr = s.recvfrom(1024)
    message = message.decode()
    return message


def send(data):
    global serverAddr
    s.sendto(data.encode(), serverAddr)


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

# key info
pc = 83
qc = 61
nc = pc * qc
pu_k = [53, nc]
pr_k = [557, nc]

# sending and receiving key info
send(str(pu_k[0]))
serverKey = int(receive())
send(str(pu_k[1]))
nServer = int(receive())

# start with the command line
command_line = '/cmd_line>'
print('For help type "HELP".')
info_cmd = input(command_line)
info_cmd = rsa(info_cmd, nServer, serverKey)
send(info_cmd)
prompt = receive()
prompt = d_rsa(prompt, nc, pr_k[0])

# Send message. The string needs to be converted to bytes.
while True:
    # connected until command EXIT is sent
    info_cmd = input(command_line + prompt)
    info_cmd = rsa(info_cmd, nServer, serverKey)
    send(info_cmd)

    if info_cmd == 'EXIT':
        s.close()
        break

    # receiving prompts from server
    prompt = receive()
    prompt = d_rsa(prompt, nc, pr_k[0])
    if prompt == 'invalid':
        print("Invalid Command.")
        prompt = ''
