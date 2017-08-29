# Teletext Packet Analyser
A python script to decode and sort through teletext datastreams.

## Invocation
`teletext-decoder.py -i <inputfile> -o <outputfile> [-p <page number>]`
 
`inputfile` should contain concatenated 42 byte teletext packets (2 byte MRAG followed by 40 bytes of data).
A decoded and annotated representation of the teletext datastream will be written to `outputfile`.
An optional teletext page number will return only the packets belonging to the specified page.
