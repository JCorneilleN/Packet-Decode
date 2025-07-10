# Packet-Decode

For this assignment, you will modify the C program that you wrote for Assignment 8. Besides decoding
the Ethernet and IP headers, you will also need to decode the TCP header that is in the binary file.
 For the flags, list the common three-letter abbreviation for each flag that is set, e.g., ACK, FIN,
PSH. Ensure there is a space between flags in the output.
 If any options are encountered, simply provide a header indicating whether it is the first,
second, ..., nth option and list the four bytes which make up the option.
 You will also need to list the hex representation of segment’s payload.
Frame12.bin is supplied as an example binary file that you may use to develop your program. You may
also create your own binary files from any packet you can view in Wireshark
