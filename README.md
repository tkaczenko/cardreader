# CardReader
CLI utility to read data from Ukrainian ePassport (Ukrainian ID) using NFC reader.

This project contains two modules:
* [jmrtd](/jmrtd) - fork of [JMRTD](http://jmrtd.org/) to communicate with NFC reader by PACE protocol. Made some changes into sending APDU for PACE protocol with CAN (Card Access Number) key (added reference of a private key)
* [reader](/reader) - CLI utility to read data from Ukrainian ID by PACE with CAN

## Usage
```bash
java -jar reader-0.1.jar 000101
```
where is:
* `000101` - CAN (Card Access Number) key - last 6 digits of Document No.

## Built With
* jmrtd
* scuba-smartcards
* scuba-sc-j2se
* jai-imageio-jpeg2000

For better understanding look at [DOC 9303 P11](https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf), [DOC 9303 P10](https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf)
