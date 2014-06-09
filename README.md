OpenSSL-Elgamal
===============

Adding Elgamal Algorithm into OpenSSL Library

In this project, I just simply use DSA algorithm in OpenSSL to create Elgamal APIs for encryption and reencryption.

This would be the first version which has successfully implement Elgamal algorithm. However, I haven't tried to enhance the EVP interfaces to accept Elgamal. And the parameters in Elgamal also need to be broaden. Currently, it can just accept p and q with 1024 bits and 1024 bits respectively.
