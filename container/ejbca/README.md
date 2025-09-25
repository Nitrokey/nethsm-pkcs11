EJBCA Example
-------------

### Startup

1. `docker compose up --build -d`
2. `docker compose logs -f`
3. After previous command settled, connect to `localhost:9443` with a browser
4. "CA Functions" -> "Crypto Tokens" -> "Create new..."

    1. Type: `PKCS#11`, PKCS#11 Library: `NetHSM`, set "Authentication Code" to any value
    2. `Save`
    3. `Generate new key pair`

5. `docker compose down -v`

### Configuration Details

* If `logs/` is used via `LOG_STORAGE_LOCATION` (it is by default),
  make sure it is world-writable: `chmod a+w logs`
* The attributes file is currently not needed/used
* `pkcs11spy` is configured to trace the pkcs11 calls, to only use `libnethsm_pkcs11.so` make
  sure to remove the `PKCS11SPY*` environment variables and update `web.properties` like that:
    ```diff
    - cryptotoken.p11.lib.245.file=/usr/lib64/pkcs11-spy.so
    + cryptotoken.p11.lib.245.file=/usr/lib/nitrokey/libnethsm_pkcs11.so
    ```

