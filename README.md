# Teletext Packet Analyser
A python script to decode and sort through teletext datastreams.

## Invocation
`teletext-decoder.py -i <inputfile> -o <outputfile> [-p <page number>] [-s]`
 
`inputfile` should contain concatenated 42 byte teletext packets (2 byte MRAG followed by 40 bytes of data). A 43 byte WST dump from a capture card can be decoded using the -s flag.
A decoded and annotated representation of the teletext datastream will be written to `outputfile`.
An optional teletext page number will return only the packets belonging to the specified page.
