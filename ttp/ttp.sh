mkdir -p "keys/ttpkeys"
mkdir -p "keys/serverkeys"
mkdir -p "keys/clientkeys"
mkdir -p "keys/clientkeys/aes"

openssl genrsa -out keys/ttpkeys/ca-key.pem 2>/dev/null
openssl req -new -x509 -key keys/ttpkeys/ca-key.pem -out keys/ttpkeys/ca-cert.pem -nodes -subj '/CN=ca\.example\.com/' 2>/dev/null
cp ./keys/ttpkeys/ca-cert.pem ./keys/clientkeys
cp ./keys/ttpkeys/ca-cert.pem ./keys/serverkeys