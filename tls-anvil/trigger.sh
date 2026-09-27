#!/bin/bash
# Run by TLS-Anvil before each handshake, inside its container (host network):
# one TCP connection to seclume-tls-anvil's AnvilClient, which answers by
# starting one TLS connection to TLS-Anvil. No curl in the image - bash's
# /dev/tcp is enough, since the connection itself is the message.
exec 3<>/dev/tcp/127.0.0.1/8090
