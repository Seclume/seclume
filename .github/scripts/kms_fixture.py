"""An AWS KMS key and a data key under it, in moto's KMS emulator - for
LocalAwsKmsDecryptTest, which opens the data key through provider=kms-decrypt.

moto does not check signatures, so the requests carry a well-formed
Authorization header for the region and nothing else; the Java side signs for
real. Writes into the working directory:

    .local-kms-key-arn       the key's ARN
    .local-kms-ciphertext    Encrypt's CiphertextBlob (Base64) of a random 32-byte key
    .local-kms-expected      that key (Base64) - the test's control, never a production file

usage: kms_fixture.py https://127.0.0.1:4443
"""
import base64
import json
import os
import ssl
import sys
import time
import urllib.request

REGION = "eu-central-1"


def call(endpoint, target, body):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE        # moto's own throwaway certificate
    day = time.strftime("%Y%m%d", time.gmtime())
    request = urllib.request.Request(endpoint + "/", data=json.dumps(body).encode(), headers={
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": "TrentService." + target,
        "X-Amz-Date": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
        "Authorization": f"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{day}/{REGION}/kms/"
                         "aws4_request, SignedHeaders=host, Signature=" + "0" * 64,
    })
    with urllib.request.urlopen(request, context=context, timeout=30) as answer:
        return json.loads(answer.read())


def main(endpoint):
    for _ in range(60):
        try:
            key = call(endpoint, "CreateKey", {"Description": "seclume field data",
                                               "KeyUsage": "ENCRYPT_DECRYPT"})
            break
        except OSError:
            time.sleep(1)
    else:
        raise SystemExit("moto did not answer at " + endpoint)
    arn = key["KeyMetadata"]["Arn"]
    data_key = os.urandom(32)
    encrypted = call(endpoint, "Encrypt", {"KeyId": arn,
                                           "Plaintext": base64.b64encode(data_key).decode()})
    with open(".local-kms-key-arn", "w") as f:
        f.write(arn)
    with open(".local-kms-ciphertext", "w") as f:
        f.write(encrypted["CiphertextBlob"])
    with open(".local-kms-expected", "w") as f:
        f.write(base64.b64encode(data_key).decode())
    print("AWS KMS emulator: key", arn)


if __name__ == "__main__":
    main(sys.argv[1])
