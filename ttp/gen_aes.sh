SALT=$(openssl rand -hex 128)
openssl enc -aes-256-cbc -k "$SALT" -P -pbkdf2 | sed '1d' | cut -c5- > keys/clientkeys/aes/aes_"$1".txt