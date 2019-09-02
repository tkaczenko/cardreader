# CardReader
CLI utility to read data from Ukrainian passport (Ukrainian ID) using NFC reader.

This project contains two modules:
* [jmrtd](/jmrtd) - fork of JMRTD to communicate with reader by PACE protocol
* [reader](/reader) - CLI utility to read data from Ukrainian ID by CAN key

## Usage
```bash
java -jar reader-0.1.jar 000101
```
where is:

`000101` - CAN key (Last 6 digits of Document No.)

## Built With
* jmrtd
* scuba-smartcards
* scuba-sc-j2se
* jai-imageio-jpeg2000