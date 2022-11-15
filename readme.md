# Secure Programming - SecChat 
## Communication Between Client and Server
### Establishing a Connection
The connection between the server and the client is established using a TCP socket. 
The server calls `fork` for each incoming connection, thereby allowing to service multiple clients simultaneously. <br>

### Types of Interactions
* The client interacts with the user via `stdin/stdout` (`read_input()` and `message_user()` in `ui.c`).
  * The input sent by the user is sanitized (in `sanitizer.c`), parsed (in `parser.c`) and processed (in `client.c`).
* The client and the server interact via an api, by using the socket `send()` and `recv()` calls.
  * The client and the server use the `api_msg` struct to store the data about the message.
  * Before sending the message with its metadata, the sender sends the size of the message, so that the receiver knows how much data is expected to be read.
  * The data about the message contains the following fields:
    * A buffer to store the message.
    * The type of the message.
    * The username associated with the client (if applicable).
    * The password associated with the client (if applicable).
    * The timestamp of the message (if applicable).
  * At the receiver end, the message is parsed and processed according to its type.
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

### Sanitizing and Parsing Input
The client uses the functions in `sanitizer.c` and `parser.c` to verify that commands and messages are valid before further processing. <br>
The functions in `sanitizer.c` allow checking that the correct number of arguments is provided, the length of the arguments (`is_valid_username()`, `is_valid_pwd()`, `is_valid_msg()`), as well as removing leading and trailing whitespace from valid messages (`remove_whitespace()`). <br>
The functions in `parser.c` are used to determine the message type, as well as storing the data about the message in the appropriate fields of the `api_msg` struct. <br>
In case an invalid input is read, the type of the message is set to invalid and the input is discarded by the client. <br>


