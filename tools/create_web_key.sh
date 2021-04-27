#!/bin/zsh

curl -k -i -w '\n' -u admin:adminadmin -X PUT \
  https://nethsmdemo.nitrokey.com/api/v1/keys/webserver \
  -H "content-type: application/json" \
  -d '{
    "mechanisms": [
        "RSA_Decryption_RAW", "RSA_Decryption_PKCS1",
        "RSA_Decryption_OAEP_MD5", "RSA_Decryption_OAEP_SHA1",
        "RSA_Decryption_OAEP_SHA224", "RSA_Decryption_OAEP_SHA256",
        "RSA_Decryption_OAEP_SHA384", "RSA_Decryption_OAEP_SHA512",
        "RSA_Signature_PKCS1", "RSA_Signature_PSS_MD5",
        "RSA_Signature_PSS_SHA1", "RSA_Signature_PSS_SHA224",
        "RSA_Signature_PSS_SHA256", "RSA_Signature_PSS_SHA384",
        "RSA_Signature_PSS_SHA512" ],
    "algorithm": "RSA",
    "key": {
        "publicExponent": "AQAB",
        "primeP": "AOedR8mKUVN2jLE60cbESw+o88d2f19oyAjNLUtnLgYnBIKva10JYDRHa/EXqiStx+cDTNvd5xBVPXFrt56sdpHgW1rL9BkcXX5Z75eNQwCEZOxrHp7uSkefr3we7KCTEvFMnA8tp4tnA5y7J+anlgz5oucmS91JS8O8l/UGGk0Sx52N7aRjEVI8Rbm8Mz91jPPuHevvYy0uqkEwI2nxVTlNadmCrJi3DJ/xVm/8bUTCixBcs9LurDfUI70llz9XqHX/AfOOBc8giIAS8PUDa6djKMbKtKR2OurAdHLFMvUWEMEpUwjS+CyFkv+LtXCnl2J0KqKGDW5DYZOMuYSo71s=",
        "primeQ": "ANAOJHTHgQNr+VWf35WoVYKR6r3fZDy5mtfDlj3i0YRdU7PReanwesNcDiHc1a5nkmVUOpmzG9VmI6vWX2+VEAbW4nukqKsljrla1VZ7RtYsmeoat5vSKwiL1P2fDqjX8xKM1Q94z4wMoXjfuuRbimoOa9uuGpTfKEJolXF0Z6YFUdQWnosOY3GIOQNvVNGYwtczTj2ykVbF3rFepVOhMgvUPKEN0foXAI1yXQECf3nrEHZmNS1IX6m0pqKOdc9xrRZn6Je1E9CLkp52pCkPxWJ0Swep1uk8Lc5MnSo1NmnahVBra8rozvSEEh4p8GVDRsDivzfJYTMEuJS+8pUShCs="
    }
}'
