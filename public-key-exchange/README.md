# Public key exchange

In this example is implemented a simple public key exchange between two devices. Each device creates its own pair of private/public key using ECC (in particular using the secp256r1 curve), and starts an UDP server.

The device prints its ipv6 address and its key pair on the terminal.

Using the command `start_exchange <ip_address>` you can start the public key exchange, and when a device receives the public key of the other device, it computes the shared secret using the received key and its private key.

After the completion of the exchange the two devices can send each other encrypted messages using the computed shared secret. The messagges are encrypted using aes, with a 128 bit key.

The code has been tested on [IoT-LAB](https://www.iot-lab.info) using the [m3 board](https://www.iot-lab.info/hardware/m3/).

> **_NOTE:_** To ensure the correct execution of the code you need to uncomment **line 37** (`#define CRYPTO_AES`)of the file *{RIOT_BASE_DIR}/sys/include/crypto/ciphers.h* in your RIOT directory. This ensure that the CRYPTO\_AES module is correctly loaded in your build.

## Point to point communication
The devices, by default, use a p2p communication to exchange the packets.

You need to start an experiment on IoT-LAB with two m3 boards to test it.

## RPL routing
You can use the RPL routing protocol to make the devices communicate, using the rpl commands.

In this case, you need to start an experiment with three m3 boards. We use one board as the root of the rpl tree.

So we need to find the interface number on each board, using the `ifconfig` command.


Assuming we found *interface 6*, we start on all the boards the rpl protocol: `rpl init 6`.

Then, we need to configure a global ip address in the root of the DAG, and then we can start a RPL DODAG:

`ifconfig 6 add 2001:db8::`

`rpl root 1 2001:db8::1`

Now we can type `rpl` on each board to see if everything goes well.

For better explanation and more info, [click here](https://www.iot-lab.info/tutorials/riot-rpl-m3/).

## Exchange key and send message

`start_exchange <ip_address>` : Start the public key exchange.
`send_encrypted <ip_address> <msg>` : Send an encrypted message to the specified ip address (works only if the two devices already exchanged thei public key).
