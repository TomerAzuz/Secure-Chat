openssl genrsa -out keys/serverkeys/keypriv.pem 2>/dev/null
openssl rsa -pubout -in keys/serverkeys/keypriv.pem -out keys/serverkeys/keypub.pem 2>/dev/null
openssl req -new -key keys/serverkeys/keypriv.pem -out keys/serverkeys/server-csr.pem -nodes -subj '/CN=server\.example\.com/' 2>/dev/null
openssl x509 -req -CA keys/ttpkeys/ca-cert.pem -CAkey keys/ttpkeys/ca-key.pem -CAcreateserial -in keys/serverkeys/server-csr.pem -out keys/serverkeys/server-cert.pem 2>/dev/null