# Secure Programming - SecChat 
## Communication Between Client and Server
### Establishing a Connection
The connection between the server and the client is established using a TCP socket. 
The server calls `fork` for each incoming connection, thereby allowing to service multiple clients simultaneously. <br>

### Types of Interactions
* The client interacts with the user via `stdin/stdout` (`read_input()` and `message_user()` in `ui.c`).
  * The input sent by the user is sanitized (in `sanitizer.c`), parsed (in `parser.c`) and processed (in `client.c`).
* The client and the server interact via an api (`api.c`), by using the socket `send()` and `recv()` calls.
  * The client and the server use the `api_msg` struct to store the data about the message.
  * The data about the message contains the following fields:
    * A buffer to store the message (a private message is sent encrypted)
    * The type of the message
    * The username associated with the client
    * The (hashed) password associated with the client (if applicable)
    * The timestamp of the message (if applicable)
    * The client's public key (for registration only) *(not implemented)*
    * The recipient's username (for private messages only)
    * Encrypted AES key (for private messages only)
  * At the receiver's end, the message is parsed and processed according to its type.
* Whenever an incoming message from the client is received by the worker, all other workers are notified and the message is forwarded to their clients. 
* The client executes any incoming message sent by the server according to its type (`execute request()`).
* The server interacts with the database using the functions in `database.c`.
  * The server can request the last public message sent (`get_last_pubmsg()`), and all the messages stored in the database (`get_all_msgs()`).
  * The server can also store messages  and accounts in the database (`insert_msg()` and (`store_account()`).

### Message Format
* public message:&nbsp;&nbsp;&nbsp; "message"
* private message:&nbsp; @recipient "message"
* register: &ensp;&emsp;&ensp;&emsp;&ensp;&ensp; /register username password
* login: &emsp;&emsp;&emsp;&emsp;&emsp;&nbsp;&nbsp;/login username password
* online users:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; /users
* exit:  &emsp;&emsp;&emsp;&emsp;&ensp;&emsp;&nbsp; /exit

### Message Types
* `USER_NOT_FOUND` - User sends a private message to a non existing recipient.
* `USERNAME_TAKEN` - Username registers with an existing username
* `AUTH_ERROR` - User authentication failed
* `UNKNOWN CMD` - User sends a command not listed in `Message Format`.
* `INVALID CMD` - User sends an unauthorized command while logged out, or sends `register` or `login` command while logged in.
* `INVALID_FORMAT` - User sends a command with insufficient or too many arguments, or sends arguments that exceed the allowed length.
* `REGISTER` -  `register` command
* `LOGIN` - `login` command
* `USERS` - List online users command
* `PRIV_MSG` - Private message
* `PUB_MSG` - Public message
* `EXIT`  - `exit` command
* A message with none of the above types is assumed to be public.

(Defined in `parser.h`).

### Sanitizing and Parsing Input
The client uses the functions in `sanitizer.c` and `parser.c` to verify that commands and messages are valid before further processing. <br>
The functions in `sanitizer.c` allow checking that the correct number of arguments is provided, the length of the arguments (`is_valid_username()`, `is_valid_pwd()`, `is_valid_msg()`), as well as removing leading and trailing whitespace from valid messages (`remove_whitespace()`). <br>
The functions in `parser.c` are used to determine the message type, as well as storing the data about the message in the appropriate fields of the `api_msg` struct. <br>
In case an invalid input is read, the type of the message is set to invalid and the input is discarded by the client. <br>


## Cryptography

### Client and Server Interaction
An SSL connection ensures that any data sent over the socket is encrypted. <br>
Therefore, all communication between the server and the client is protected from eavesdrppers. <br>
In addition, the sender signs messages with his private key to ensure non-repudiation, as well as the integrity and authenticity of the message. <br>
The receiver then verifies the signature using the sender's public key and verifies the public key by checking the sender's certificate.. <br>
Furthermore, clients authenticate the server upon establishing a connection by checking the server's certificate.

#### Registration
The client receives the command and its arguments from `stdin`. <br>
The client sends the message to the server with a hashed password. In that manner, the plaintext password remains invisible to the server. <br>
Additionally, the client uses the TTP to generate a public and a private key, and sends the public key to the server over the socket which will be used to verify the client's signature. *(not implemented)* <br>
To prevent rainbow table attacks, the server generates salt and concatenates it to the hashed password received from the client and hashes the resulted string. <br>
The account of the user is then stored in the database in the following way:
* Username in plaintext
* Hash salted password
* The salt of the password in plaintext

The following format describes a registration command sent by the client to the server: <br>
`/register msg_type sender hashed_password public_key signature` <br>
The server's response may indicate either a successful or unsuccessful registration, which is sent to the client in plaintext over the socket. <br>

#### Logging in
The client receives the command and its arguments from `stdin`. <br>
The client performs the same procedure as for registration, except that now the public key is already stored in the database, and hence does not need to be sent over the socket. <br>
The server verifies the signature *(not implemented)*, retrieves the salt from the database and concatenates it to the password received from the client. 
The resulted string is hashed and compared to the password stored in the database. <br>
The following format describes a login command sent by the client to the server:<br>
`/login msg_type sender hashed_password signature` <br>
Similar to registration, the server responds with either successful or unsuccessful login sent in plaintext over the socket. <br>

#### Public Messages
The client receives the message from `stdin`, signs the message with his private key and sends it to the server. <br>
The server verifies the signature *(not implemented)*, stores the message in the database and notifies all other workers. <br>
The following information about public messages is stored in the database:
* The message in plaintext
* The sender's username
* The timestamp of the message
* The signature

The client receiving the message verifies the sender's certificate and signature. <br>
The following format describes a public message sent by the client to the server:<br>
`"some message" msg_type sender timestamp signature`

#### Private Messages
The client receives a private message command from `stdin` followed by the recipient's username and the message. <br>
The client does the following before sending the message over the socket:
* Uses the TTP to generates a symmetric (AES) key
* Encrypts the plaintext message with the AES key
* Encrypts the AES key with the recipient's public key
* Encrypts the AES key with his own public key
* Signs the message

The client receiving the message verifies the sender's certificate and signature. <br>
The following format describes a private message sent by the client to the server:<br>
`"some message" (encrypted with AES), msg_type, timestamp, sender,` 
`recipient AES_key (encrypted with the recipient's public key),` 
`(same)AES_key (encrypted with the sender's public key), signature`  <br>

The following information about private messages is stored in the database:
* The message in ciphertext
* The sender's username 
* The recipient's username
* The timestamp of the message
* The signature
* The AES key encrypted with the recipient's private key
* THe AES Key encrypted with the sender's private key
The recipient verifies the sender's certificate and signature before processing it. <br>
To decrypt the message, the AES key is decrypted using the recipient's private key, and the ciphertext is then decrypted using the AES key. <br>
The sender can retrieve his own message by decrypting the second AES key with his own private key. <br>
The process is repeated for every private message. <br>
#### Users Command
The client receives the `users` command from `stdin` signs and sends it over the socket. <br>
The following format describes a `users` command sent by the client to the server: <br>
`/users signature` <br>
The server replies with a list of online users.
#### Exit Command
The client receives the `exit` command from `stdin` and disconnects from the server. <br>
Cryptography is not applied for the `exit` command. <br>

### Key Distribution
Initially, the TTP generates certificates and keys for the server and for itself. <br>
Clients have their certificates and keys generated by the TTP upon successful registration. <br>
The TTP is provided with the least amount of information necessary to generate certificates and keys and is not involved in the interaction between the client and the server. <br>
The sender for which the keys and certificates are issued is the only information shared with the TTP.  
In addition, the TTP is authorized to access the server's and clients' keys directories. <br>
The TTP is also used for generating AES keys for private messages. <br>

### Security Requirements
* **Mallory cannot get information about private messages for which she is not either the sender or the intended recipient.**
  * Private messages are sent encrypted with a one-time AES key on an SSL connection, thereby protecting confidentiality. <br>
    Additionally, private messages are stored as ciphertext in the database, ensuring that the messages remain confidential even if the server is compromised.
* **Mallory cannot send messages on behalf of another user.**
  * Public and private messages are signed by the sender. Since the sender's private key is required for signing the message, 
    a valid signature provides a proof of the sender's identity. Messages with an invalid signature should not be processed. 
* **Mallory cannot modify messages sent by other users.**
  * Signing a message requires to hash the message and encrypt the result with the private key. The recipient decrypts the message with the sender's public key and checks whether the hashes are equal.
    Any modification to the original message will result in a different hash, thereby resulting in an invalid signature.
* **Mallory cannot find out users’ passwords, private keys, or private messages (even if the server is compromised).**
  * Passwords are hashed before being sent from the client to the server. The server applies salt and hash before storing the passwords in the database.  <br>
    Private keys are stored locally and therefore a compromised server does not result in compromised private keys. <br>
    Private messages are sent and stored encrypted in the database and therefore are not disclosed to Mallory. <br>
* **Mallory cannot use the client or server programs to achieve privilege escalation on the systems they are running on.**
  *  The client and server should operate with the least privileges necessary. Additionally, the use of prepared statements reduces the risk of SQL injections.
* **Mallory cannot leak or corrupt data in the client or server programs.**
  *  Early validation of input, as well as escaping, sanitization and prepared statements aim to reduce the risk of data leak and corruption. 
* **Mallory cannot crash the client or server programs.**
  *  Sanitization, escaping and early validation of input can reduce the risk of crashing the client and server programs. 
     However, this cannot be guaranteed as program crashes can occur due to hardware or network failures. 
* **The programs must never expose any information from the systems they run on, beyond what is required for the program to meet the requirements in the assignments.**
  * Error messages displayed to the user should not contain any information that can be used to attack the program. 
* **The programs must be unable to modify any files except for chat.db and the contents of the clientkeys and clientkeys directories, or any operating system settings, even if Mallory attempts to force it to do so.**
  * By applying the principle of least privilege, the client and the server programs will only have access to their respective key directories.
    Early validation and escaping reduce the risk of unauthorized accesses. 