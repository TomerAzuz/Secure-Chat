mkdir -p keys/clientkeys/"${1}"
openssl genrsa -out keys/clientkeys/"${1}"/keypriv_"$1".pem 2>/dev/null
openssl rsa -pubout -in keys/clientkeys/"${1}"/keypriv_"$1".pem -out keys/clientkeys/"${1}"/keypub_"$1".pem 2>/dev/null
openssl req -new -key keys/clientkeys/"${1}"/keypriv_"$1".pem -out keys/clientkeys/"${1}"/"$1"-csr.pem -nodes -subj "/CN=${1}" 2>/dev/null
openssl x509 -req -CA keys/ttpkeys/ca-cert.pem -CAkey keys/ttpkeys/ca-key.pem -CAcreateserial -in keys/clientkeys/"${1}"/"$1"-csr.pem -out keys/clientkeys/"${1}"/"$1"-cert.pem 2>/dev/null