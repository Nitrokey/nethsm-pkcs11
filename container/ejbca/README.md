EJBCA Example
-------------

1. `docker compose up --build -d`
2. `docker compose logs -f`
3. After previous command settled, connect to `localhost:9443` with a browser
4. "CA Functions" -> "Crypto Tokens" -> "Create new..."

   a) Type: `PKCS#11`, PKCS#11 Library: `NetHSM`, set "Authentication Code" to any value
   b) `Save`
   c) `Generate new key pair`
5. `docker compose down -v`
