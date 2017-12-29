#!/usr/bin/env python3
# decode a teletext data stream and analyse the packets

import sys, getopt
from datetime import date, datetime, time, timedelta, tzinfo

try:
	import crcmod
except ImportError:
	print ("Requires python module 'crcmod'. Try 'pip install crcmod'")
	sys.exit(2)


class FixedOffset(tzinfo):
	"""Fixed offset in minutes east from UTC."""
	def __init__(self, offset, name):
		self.__offset = timedelta(minutes = offset)
		self.__name = name
	def utcoffset(self, dt):
		return self.__offset
	def tzname(self, dt):
		return self.__name
	def dst(self, dt):
		return timedelta(0)

HAMMING_8_4_ERROR_MAPPING = [ 1, 7, 5, 0, 3, 2, 4, 6 ]

REVERSE_BYTES = [0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0, 0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8, 0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4, 0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC, 0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2, 0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA, 0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6, 0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE, 0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1, 0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9, 0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5, 0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD, 0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3, 0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB, 0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7, 0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF]

REVERSE_NIBBLES = [0x0, 0x8, 0x4, 0xC, 0x2, 0xA, 0x6, 0xE, 0x1, 0x9, 0x5, 0xD, 0x3, 0xB, 0x7, 0xF]

def get_bit( byte, pos ):
	return ( byte >> pos ) & 0x01

def parity( byte ):
	return get_bit( byte, 0 ) ^ get_bit( byte, 1 ) ^ get_bit( byte, 2 ) ^ get_bit( byte, 3 ) ^ get_bit( byte, 4 ) ^ get_bit( byte, 5 ) ^ get_bit( byte, 6 ) ^ get_bit( byte, 7 )

def hamming_8_4_decode( byte ):
	errors = 0
	c = [0, 0, 0]
	
	p = parity ( byte )
	
	c [0] = ((get_bit( byte, 0 ) ^ get_bit( byte, 1 )) ^ get_bit( byte, 5 )) ^ get_bit( byte, 7 )
	c [1] = ((get_bit( byte, 1 ) ^ get_bit( byte, 2 )) ^ get_bit( byte, 3 )) ^ get_bit( byte, 7 )
	c [2] = ((get_bit( byte, 1 ) ^ get_bit( byte, 3 )) ^ get_bit( byte, 4 )) ^ get_bit( byte, 5 )
	
	check = (c[0] << 2) | (c[1] << 1) | (c[2])
	
	if p:
		if check is not 7:
			errors = 2
	else:
		errors = 1
		byte ^= (1 << HAMMING_8_4_ERROR_MAPPING[check])
	
	decoded = (get_bit(byte, 7) << 3) | (get_bit(byte, 5) << 2) | (get_bit(byte, 3) << 1) | get_bit(byte, 1)
	
	return decoded, errors

def hamming_24_18_decode( byte0, byte1, byte2 ):
	errors = 0
	c = [0, 0, 0, 0, 0]
	errorbit = 0
	
	p = parity ( byte0 ) ^ parity ( byte1 ) ^ parity ( byte2 )
	
	word = byte0 | (byte1 << 8) | (byte2 << 16)
	
	c[0] = get_bit(word, 0) ^ get_bit(word, 2) ^ get_bit(word, 4) ^ get_bit(word, 6) ^ get_bit(word, 8) ^ get_bit(word, 10) ^ get_bit(word, 12) ^ get_bit(word, 14) ^ get_bit(word, 16) ^ get_bit(word, 18) ^ get_bit(word, 20) ^ get_bit(word, 22)
	c[1] = get_bit(word, 1) ^ get_bit(word, 2) ^ get_bit(word, 5) ^ get_bit(word, 6) ^ get_bit(word, 9) ^ get_bit(word, 10) ^ get_bit(word, 13) ^ get_bit(word, 14) ^ get_bit(word, 17) ^ get_bit(word, 18) ^ get_bit(word, 21) ^ get_bit(word, 22)
	c[2] = get_bit(word, 3) ^ get_bit(word, 4) ^ get_bit(word, 5) ^ get_bit(word, 6) ^ get_bit(word, 11) ^ get_bit(word, 12) ^ get_bit(word, 13) ^ get_bit(word, 14) ^ get_bit(word, 19) ^ get_bit(word, 20) ^ get_bit(word, 21) ^ get_bit(word, 22)
	c[3] = get_bit(word, 7) ^ get_bit(word, 8) ^ get_bit(word, 9) ^ get_bit(word, 10) ^ get_bit(word, 11) ^ get_bit(word, 12) ^ get_bit(word, 13) ^ get_bit(word, 14)
	c[4] = get_bit(word, 15) ^ get_bit(word, 16) ^ get_bit(word, 17) ^ get_bit(word, 18) ^ get_bit(word, 19) ^ get_bit(word, 20) ^ get_bit(word, 21) ^ get_bit(word, 22)
	
	if p == 1:
		if c[0] & c[1] & c[2] & c[3] & c[4]:
			errors = 0
		else:
			errors = 2
	else:
		errors = 1
		if c[0] == 0:
			errorbit |= 1
		if c[1] == 0:
			errorbit |= 2
		if c[2] == 0:
			errorbit |= 4
		if c[3] == 0:
			errorbit |= 8
		if c[4] == 0:
			errorbit |= 16
		
		if errorbit != 0:
			word ^= (1 << (errorbit - 1))
	
	decoded = get_bit(word, 22)<<17 | get_bit(word, 21)<<16 | get_bit(word, 20)<<15 | get_bit(word, 19)<<14 | get_bit(word, 18)<<13 | get_bit(word, 17)<<12 | get_bit(word, 16)<<11 | get_bit(word, 14)<<10 | get_bit(word, 13)<<9 | get_bit(word, 12)<<8 | get_bit(word, 11)<<7 | get_bit(word, 10)<<6 | get_bit(word, 9)<<5 | get_bit(word, 8)<<4 | get_bit(word, 6)<<3 | get_bit(word, 5)<<2 | get_bit(word, 4)<<1 | get_bit(word, 2)
	
	return decoded, errors

magFunctions = [0,0,0,0,0,0,0,0]
magCodings = [0,0,0,0,0,0,0,0]

def decode_teletext_line( bytes ):
	decoded_data = []
	control = 0
	header = ""
	characterbytes = ""

	decode = hamming_8_4_decode(bytes[0])[0]
	nibble = decode
	magazine = nibble & 0x7
	if magazine == 0:
		magazine = 8
	packet = nibble >> 3
	decode = hamming_8_4_decode(bytes[1])[0]
	nibble = decode
	packet |= nibble << 1
	
	decoded_data.append(magazine)
	decoded_data.append(packet)

	if packet == 0:
		# page header
		# return magazine, packet, page number, minutes units, minutes tens, hours units, hours tens, control bits, header characters
		page = (hamming_8_4_decode(bytes[3])[0] << 4) | hamming_8_4_decode(bytes[2])[0]
		decoded_data.append(page) # page number
		
		subpage = hamming_8_4_decode(bytes[4])[0] # minutes units
		
		decode = hamming_8_4_decode(bytes[5])[0]
		subpage |= (decode & 0x7) << 4 # minutes tens
		control |= (decode & 0x8) << 1 #move from bit 3 to bit 4

		subpage |= (hamming_8_4_decode(bytes[6])[0]) << 8 # hours units

		decode = hamming_8_4_decode(bytes[7])[0]
		subpage |= (decode & 0x3) << 12 # hours tens
		decoded_data.append(subpage)
		
		control |= (decode & 0xC) << 3 #move from bit 2 and 3 to bit 5 and 6

		decode = hamming_8_4_decode(bytes[8])[0]
		control |= decode << 7 #move from bits 0..3 to bits 7..10

		decode = hamming_8_4_decode(bytes[9])[0]
		control |= decode << 11 #move from bits 0..3 to bits 11..14

		decoded_data.append(control)
		
		for i in range(10,42):
			header += chr( bytes[i] & 0x7F ) #strip parity and add to string
		
		decoded_data.append(header)
		
		if (page == 0xFE):
			magFunctions[magazine%8] = 6 # MOT
			magCodings[magazine%8] = 3 
		else:
			magFunctions[magazine%8] = 0 # default page function
			magCodings[magazine%8] = 0 # default page coding
		
	elif packet < 26:
		# page row or replacement header row
		if (magCodings[magazine%8] == 0):
			# return magazine, row, characters
			for i in range(2,42):
				characterbytes += chr( bytes[i] & 0x7F ) #strip parity and add to string
			
			decoded_data.append(characterbytes) # page row data
		elif (magCodings[magazine%8] == 2):
			# page enhancement packet
			decoded_data.append(hamming_8_4_decode(bytes[2])) #designation code
			for i in range(0,13): # 13 triplets
				decoded_data.append(hamming_24_18_decode(bytes[i*3+3], bytes[i*3+4], bytes[i*3+5]))
		elif (magCodings[magazine%8] == 3):
			for i in range(2,42):
				decoded_data.append(hamming_8_4_decode(bytes[i]));
		
	elif packet == 26:
		# page enhancement packet
		decoded_data.append(hamming_8_4_decode(bytes[2])) #designation code
		for i in range(0,13): # 13 triplets
			decoded_data.append(hamming_24_18_decode(bytes[i*3+3], bytes[i*3+4], bytes[i*3+5]))
		
	elif packet == 27:
		dc = hamming_8_4_decode(bytes[2])
		decoded_data.append(hamming_8_4_decode(bytes[2])[0])
		
		if (dc[0] < 4):
			# editorial links
			# return magazine, packet, links page, page, subpage, page, subpage, page, subpage, page, subpage, page, subpage, checksum, link control
			linksdata = []
			for i in range(3,40):
				linksdata.append(hamming_8_4_decode(bytes[i])[0])
			for i in range(0,6):
				decoded_data.append(linksdata[i*6]+linksdata[(i*6)+1]*16) # page byte
				decoded_data.append(linksdata[(i*6)+2]+linksdata[(i*6)+3]*16+linksdata[(i*6)+4]*256+linksdata[(i*6)+5]*4096) # sub page word
			decoded_data.append(linksdata[36]) # link control byte
			decoded_data.append(bytes[40] * 0x100 + bytes[41]) # page crc checksum
		else:
			for i in range(0,13): # 13 triplets
				decoded_data.append(hamming_24_18_decode(bytes[i*3+3], bytes[i*3+4], bytes[i*3+5]))
		
	elif packet == 28:
		# page enhancement packet
		dc = hamming_8_4_decode(bytes[2])
		decoded_data.append(dc) #designation code
		for i in range(0,13): # 13 triplets
			decoded_data.append(hamming_24_18_decode(bytes[i*3+3], bytes[i*3+4], bytes[i*3+5]))
		
		if (dc[0] == 0 or dc[0] == 2 or dc[0] == 3 or dc[0] == 4):
			magFunctions[magazine%8] = (decoded_data[3][0] & 0xF)
			magCodings[magazine%8] = ((decoded_data[3][0] & 0x70) >> 4)
		
	elif packet == 29:
		# magazine related page enhancement packet
		decoded_data.append(hamming_8_4_decode(bytes[2])) #designation code
		for i in range(0,13): # 13 triplets
			decoded_data.append(hamming_24_18_decode(bytes[i*3+3], bytes[i*3+4], bytes[i*3+5]))
		
		# TODO care about function and coding of magazine
		
	elif packet == 30:
		if (magazine == 8):
			# Broadcast service data packets
			for i in range(2,9): # hammed data
				decoded_data.append(hamming_8_4_decode(bytes[i])[0])
			for i in range(9,22):
				decoded_data.append(bytes[i])
			for i in range(22,42):
				characterbytes += chr( bytes[i] & 0x7F ) #strip parity and add to string
			decoded_data.append(characterbytes) # page row data
		else:
			# Independent data services
			for i in range(2,42):
				decoded_data.append(bytes[i])
		
	elif packet == 31:
		# Independent data services
		for i in range(2,42):
			decoded_data.append(bytes[i])
		
	return decoded_data

def display_header_data( decoded_data ):
	outfile.write("Page: {}{:02X}/{:04X}\n".format(decoded_data[0], decoded_data[2], decoded_data[3]))
	
	controlstring = "Control bits:"
	if decoded_data[4] & 0x10:
		controlstring += " Erase,"
	if decoded_data[4] & 0x20:
		controlstring += " Newsflash,"
	if decoded_data[4] & 0x40:
		controlstring += " Subtitle,"
	if decoded_data[4] & 0x80:
		controlstring += " Suppress Header,"
	if decoded_data[4] & 0x100:
		controlstring += " Update,"
	if decoded_data[4] & 0x200:
		controlstring += " Interrupted Sequence,"
	if decoded_data[4] & 0x400:
		controlstring += " Inhibit Display,"
	if decoded_data[4] & 0x800:
		controlstring += " Magazine Serial,"
		
	controlstring += " National character set {}\n".format(decoded_data[4] >> 12)

	outfile.write(controlstring)
	
	outfile.write("Header: {}\n\n".format(decoded_data[5]))

def display_page_data( decoded_data ):
	outfile.write("Magazine: {}\n" .format(decoded_data[0]))
	outfile.write("Row {}: {}\n\n".format(decoded_data[1], decoded_data[2] ))

def display_hamming_8_4_data( decoded_data ):
	outfile.write("Magazine: {}\n" .format(decoded_data[0]))
	outfile.write("Packet {}: all bytes coded Hamming 8/4" .format(decoded_data[1]))
	outfile.write("\ndecoded: ")
	for i in range (2,42):
		outfile.write("{:x} " .format(decoded_data[i][0]))
	outfile.write("\n errors: ")
	for i in range (2,42):
		outfile.write("{:x} " .format(decoded_data[i][1]))
	outfile.write("\n\n")
	
def display_page_enhancement_data_26( decoded_data ):
	outfile.write("Magazine: {}\n" .format(decoded_data[0]))
	outfile.write("Packet {}: Page enhancement data packets. Designation code {} (error {})\n" .format(decoded_data[1],decoded_data[2][0],decoded_data[2][1]))
	outfile.write("address mode   data  errors\n")
	for i in range (0,13):
		decodedtriplet = decoded_data[i+3][0]
		error = decoded_data[i+3][1]
		outfile.write ('{:02d}      {:05b}  0x{:02x}  {}\n'.format(decodedtriplet & 0x3f, (decodedtriplet & 0x7c0) >> 6, (decodedtriplet & 0x3F800) >> 11, error))
	outfile.write("\n")

def display_page_enhancement_data( decoded_data ):
	outfile.write("Magazine: {}\n" .format(decoded_data[0]))
	outfile.write("Packet {}: Page enhancement data packets. Designation code {} (error {})\n" .format(decoded_data[1],decoded_data[2][0],decoded_data[2][1]))
	for i in range (0,13):
		decodedtriplet = decoded_data[i+3][0]
		error = decoded_data[i+3][1]
		outfile.write ('{:06b} {:06b} {:06b}  {}\n'.format((decodedtriplet & 0x3F000) >> 12, (decodedtriplet & 0xfc0) >> 6, decodedtriplet & 0x3f, error))
	outfile.write("\n")

def display_link_data( decoded_data ):
	outfile.write("Magazine: {}\n".format(decoded_data[0]))
	dc = decoded_data[2]
	outfile.write("Packet {}: Designation code {}\n" .format(decoded_data[1],dc))
	if (dc < 4):
		if (dc == 0):
			l1 = "Red:   "
			l2 = "Green: "
			l3 = "Yellow:"
			l4 = "Blue:  "
			l6 = "Index: "
		else:
			l1 = "Link 0:"
			l2 = "Link 1:"
			l3 = "Link 2:"
			l4 = "Link 3:"
			l6 = "Link 5:"
		for i in range(0,6):
			if i == 0:
				link = l1
			elif i == 1:
				link = l2
			elif i == 2:
				link = l3
			elif i == 3:
				link = l4
			elif i == 4:
				link = "Link 4:"
			else:
				link = l6
			magazinenumber = decoded_data[0] ^ (get_bit(decoded_data[4+(2*i)], 15) << 2 | get_bit(decoded_data[4+(2*i)], 14) << 1 | get_bit(decoded_data[4+(2*i)], 7))
			if magazinenumber == 0:
				magazinenumber = 8
			linkpage = format((magazinenumber << 8) + decoded_data[3+(2*i)],'03X')
			linksubpage = format(decoded_data[4+(2*i)] & 0x3F7F, '04X')
			if (decoded_data[4+(2*i)] & 0x3F7F) == 0x3F7F:
				linksubpage = "none"
			if decoded_data[4+(2*i)] == 0xFF:
				linkpage = "unused"
			outfile.write("{0} page-byte = 0x{1:02X}  sub-page-word = 0x{2:04X}  page/subpage = {3}/{4}\n".format(link, decoded_data[3+(2*i)], decoded_data[4+(2*i)], linkpage, linksubpage))
		if (dc == 0):
			outfile.write("Link control: 0x{:X}\n".format(decoded_data[15]))
			outfile.write("Page CRC checksum: 0x{:04X}\n".format(decoded_data[16]))
		outfile.write("\n")
	elif (dc < 6):
		if (dc == 4):
			numlinks = 6
		else:
			numlinks = 2
		for i in range(0,numlinks):
			outfile.write("Link {}: ".format(i))
			t1 = decoded_data[(i*2)+3]
			t2 = decoded_data[(i*2)+4]
			if (t1[0] & 3 == 0):
				outfile.write("GPOP  ")
			elif (t1[0] & 3 == 1):
				outfile.write("POP   ")
			elif (t1[0] & 3 == 2):
				outfile.write("GDRCS ")
			elif (t1[0] & 3 == 3):
				outfile.write("DRCS  ")
			if ((t1[0] >> 2) & 3 == 0):
				outfile.write("invalid")
			elif ((t1[0] >> 2) & 3 == 1):
				outfile.write("at L2.5")
			elif ((t1[0] >> 2) & 3 == 2):
				outfile.write("at L3.5")
			elif ((t1[0] >> 2) & 3 == 3):
				outfile.write("2.5/3.5")
			units = (t1[0] >> 6) & 0xF
			tens = (t1[0] >> 14) & 0xF
			mag = ((t1[0] >> 11) & 7) ^ (decoded_data[0] & 7)
			if (mag == 0):
				mag = 8
			outfile.write(" Page: {:X}".format((mag << 8)|(tens << 4)|units))
			outfile.write (" Subcode flags: {:016b}\n".format((t2[0] >> 2) & 0xFFFF))
		outfile.write("\n")
	else:
		outfile.write("Designation code {} not implemented/n/n")

def display_broadcast_service_data( decoded_data ):
	outfile.write("Magazine: {}\n" .format(decoded_data[0]))
	outfile.write("Packet {}: Broadcast service data packet " .format(decoded_data[1]))
	
	imag = ((decoded_data[6] & 0x8) >> 3) | ((decoded_data[8] & 0xc) >> 1)
	ipage = decoded_data[3] | (decoded_data[4] << 4)
	isub = decoded_data[5] | ((decoded_data[6] & 0x7) << 4) | (decoded_data[7] << 8)| ((decoded_data[8] & 0x3) << 12)
	
	if (decoded_data[2] == 0 or decoded_data[2] == 1):
		# format 1
		outfile.write("Format 1\n")
		if (decoded_data[2] == 1):
			outfile.write("Full field transmission\n")
		else:
			outfile.write("multiplexed transmission\n")
		ni = REVERSE_BYTES[decoded_data[9]] << 8 | REVERSE_BYTES[decoded_data[10]]
		tz = FixedOffset((-1 if ((decoded_data[11] & 0x40) > 0) else 1) * ((decoded_data[11] & 0x3E) * 15),timedelta(0))
		mjd = (((decoded_data[12] & 0xF) - 1) * 10000) + ((((decoded_data[13] >> 4) & 0xF) - 1) * 1000) + (((decoded_data[13] & 0xF) - 1) * 100) + ((((decoded_data[14] >> 4) & 0xF) - 1) * 10) + ((decoded_data[14] & 0xF) - 1)
		hours = ((((decoded_data[15] >> 4) & 0xF) - 1) * 10) + ((decoded_data[15] & 0xF) - 1)
		minutes = ((((decoded_data[16] >> 4) & 0xF) - 1) * 10) + ((decoded_data[16] & 0xF) - 1)
		seconds = ((((decoded_data[17] >> 4) & 0xF) - 1) * 10) + ((decoded_data[17] & 0xF) - 1)
		d = date.fromordinal(mjd + date(1858, 11, 17).toordinal())
		outfile.write("Initial Teletext Page: {:03X}/{:04X}\nNetwork Identification Code: {:04X}\n".format(imag*0x100+ipage, isub, ni))
		try:
			t = time(hours,minutes,seconds, tzinfo=tz)
			dt = datetime.combine(d,t)
			outfile.write("Timestamp: {}\n".format(dt.isoformat()))
		except (ValueError):
			outfile.write("Invalid time/date bytes:")
			for i in range (11,18):
				outfile.write (" 0x{:02x}".format(decoded_data[i]))
			outfile.write("\n")
		outfile.write("Reserved Bytes:")
		for i in range (18,22):
			outfile.write (" 0x{:02x}".format(decoded_data[i]))
	elif (decoded_data[2] == 2 or decoded_data[2] == 3):
		# format 2
		outfile.write("Format 2 [may have incorrect data]\n")
		if (decoded_data[2] == 3):
			outfile.write("Full field transmission\n")
		else:
			outfile.write("multiplexed transmission\n")
		outfile.write("Initial Teletext Page: {:03X}/{:04X}\n".format(imag*0x100+ipage, isub))
		
		pdc_data = []
		
		for i in range (9,22):
			pdc_data.append(REVERSE_NIBBLES[hamming_8_4_decode(decoded_data[i])[0]])
		
		lci = (pdc_data[0] >> 2) & 3
		outfile.write("Label Channel Identifier: {}".format(lci))
		
		if ((pdc_data[0] >> 1) & 1):
			outfile.write(" Label Update")
		if (pdc_data[0] & 1):
			outfile.write(" Prepare to Record")
		
		pcs = (pdc_data[1] >> 2) & 3
		mi = (pdc_data[1] >> 1) & 1
		outfile.write("\nProgramme Control Status: {}\nMode Identifier: {}\n".format(pcs,mi))
		
		c = (pdc_data[2] << 4) | ((pdc_data[8] & 3) << 2) | ((pdc_data[9] & 0xC) >> 2)
		ni = pdc_data[10] | ((pdc_data[9] & 3) << 4) | ((pdc_data[3] & 0xC) << 6)
		outfile.write("Country: {:02X} Network: {:02X}\n".format(c, ni))
		
		day = ((pdc_data[3] & 3) << 3) | ((pdc_data[4] & 0xE) >> 1)
		month = ((pdc_data[4] & 1) << 3) | ((pdc_data[5] & 0xE) >> 1)
		hour = ((pdc_data[5] & 1) << 4) | pdc_data[6]
		minute = (pdc_data[7] << 2) | ((pdc_data[6] & 0xC) >> 2)
		
		outfile.write("Programme Identification Label: {:02}/{:02} {:02}:{:02}\n".format(day,month,hour,minute))
		
		pty = pdc_data[12] | (pdc_data[11] << 4)
		outfile.write("Programme Type: {:02X}".format(pty))
		
		if (0): # debug output
			outfile.write("\npacket data:")
			for i in range (0,13):
				outfile.write (" 0x{:02x}".format(pdc_data[i]))
		
	else:
		outfile.write("\nInvalid designation code: {}\n\n".format(decoded_data[2]));
		return
	
	outfile.write("\nStatusDisplay: {}\n\n".format(decoded_data[22]));

idl_a_crc = crcmod.mkCrcFun(0x10291, initCrc=0, rev=True)

def display_independent_data_service( decoded_data ):
	datachannel = (decoded_data[0]%8) + ((decoded_data[1]&1)<<3)
	outfile.write("Data Channel: {}.".format(datachannel))
	FT = hamming_8_4_decode(decoded_data[2])[0]
	
	if (FT & 1 == 0):
		outfile.write(" Format A\n")
		DL = 36
		
		IAL = hamming_8_4_decode(decoded_data[3])[0]
		if IAL & 7 == 7:
			outfile.write("invalid Interpretation and Address Length (IAL)\n")
			pass
		if IAL & 7:
			SPA = 0
			for i in range (0,IAL):
				SPA += hamming_8_4_decode(decoded_data[4+i])[0] << (4 * i)
			outfile.write("Service Packet Address (SPA): 0x{:x}\n".format(SPA))
			DL -= IAL&7
		
		nextbyte = 4+(IAL&7)
		if FT & 2:
			#repeat facility
			RI = decoded_data[nextbyte]
			outfile.write("Repeat Indicator (RI): 0x{:02x}\n".format(RI))
			nextbyte += 1
			DL -= 1
			
		payload = bytearray()
		
		if FT & 4:
			#explicit continuity indicator
			CI = decoded_data[nextbyte]
			outfile.write("Explicit Continuity Indicator (CI): 0x{:02x}\n".format(CI))
			payload.append(CI)
			nextbyte += 1
			DL -= 1
		
		if FT & 8:
			#data length
			if (decoded_data[nextbyte] > DL) or (decoded_data[nextbyte] & 0xC0):
				outfile.write("invalid data length (DL)\n")
				pass
			else:
				DL = decoded_data[nextbyte]
				outfile.write("Data Length (DL): {} bytes\n".format(DL))
				payload.append(DL)
				nextbyte += 1
		
		outfile.write("User Data:")
		datastring = ""
		for i in range (nextbyte,42):
			if (i < nextbyte + DL):
				outfile.write(" {:02x}".format(decoded_data[i]))
				if (decoded_data[i] > 0x1F and decoded_data[i] < 0x80 ):
					datastring += chr(decoded_data[i])
				else:
					datastring += "."
			payload.append(decoded_data[i])
		outfile.write("\n")
		outfile.write("ASCII: {}\n".format(datastring))
		
		crc = idl_a_crc(payload)
		
		if (FT & 4):
			if (crc != 0):
				outfile.write("CRC error\n")
		else:
			if (crc >> 8) & 0xff == (crc & 0xff):
				outfile.write("Implicit Continuity Indicator (CI): 0x{:02x}\n".format(crc & 0xff))
			else:
				outfile.write("CRC error\n")
		
	elif (FT & 2 == 0):
		outfile.write(" Format B\n")
		outfile.write("Application number: {}\n".format((FT >> 2) & 3))
		outfile.write("Application identifier: 0x{:x}\n".format(hamming_8_4_decode(decoded_data[3])[0]))
		outfile.write("Continuity Index (CI): 0x{:x}\n".format(hamming_8_4_decode(decoded_data[4])[0]))
		
		outfile.write("User Data:")
		datastring = ""
		for i in range (5,40):
			outfile.write(" {:02x}".format(decoded_data[i]))
			datastring += chr(decoded_data[i])
		outfile.write("\n")
		outfile.write("Forward Error Correction bytes (FEC): 0x{:02x} 0x{:02x}\n".format(decoded_data[40], decoded_data[41]))
	else:
		outfile.write("\ninvalid Format Type (FT)\n")
	outfile.write("\n")

helpstring ="""usage: teletext-decoder.py -i <inputfile> -o <outputfile> [-p <page number>] [-d] [-s]
 
optional arguments:
 -p   output only packets belonging to page
 -d   output only independent data packets
 -s   input file uses 43 byte packet size (for WST TV card dumps)"""

def main():
	inputfile = ''
	outputfile = ''
	pageopt = 0x8FF
	offsetstep = 42
	IDL = False;

	try:
		opts, args = getopt.getopt(sys.argv[1:],"i:o:p:ds")
	except getopt.GetoptError as err:
		print(err)
		sys.exit(2)

	for opt, arg in opts:
		if opt in ('-i'):
			inputfile = arg
		elif opt in ('-o'):
			outputfile = arg
		elif opt in ('-p'):
			try:
				pageopt = int(arg, 16)
			except:
				print("invalid page number")
				sys.exit(2)
		elif opt in ('-s'):
			offsetstep = 43;
		elif opt in ('-d'):
			IDL = True;

	if (inputfile == '' or outputfile == ''):
		print(helpstring)
		sys.exit()
	
	if (pageopt != 0x8FF):
		if (pageopt < 0x100 or pageopt > 0x8FF):
			print("invalid page number")
			sys.exit(2)
		if IDL:
			print("-p and -d options cannot be used at the same time")
			sys.exit(2)
		pagetofind = pageopt & 0xFF
		magazinetofind = (pageopt & 0xF00) >> 8
		findpage = True
	else:
		findpage = False
	
	infile = open(inputfile, 'rb')
	filedata = list(infile.read())

	dumpdata = []

	fileoffset = 0

	while fileoffset < len(filedata):
		dumpdata += filedata[fileoffset:fileoffset + 0x2A] # copy 42 bytes
		fileoffset+=offsetstep
	
	currentpageinmagazine = 0xFF # no page

	offset = 0

	global outfile # make outfile variable global
	outfile = open(outputfile, 'w')

	while offset < len(dumpdata) - 42:
		rowbytes = dumpdata[ (offset) : offset + 42 ] #slice dumpdata list into data for one line
		
		#print("line {}".format(offset / 42))
		
		if rowbytes[0] == 0:
		#	print("no teletext data on this tv line\n")
			pass
			
		else:
			decoded_data = decode_teletext_line(rowbytes)
			
			if findpage: # code to display all packets for pagetofind in magazinetofind
				if decoded_data[0] == magazinetofind:
					if decoded_data[1] == 0: # header packet
						currentpageinmagazine = decoded_data[2]
						if currentpageinmagazine == pagetofind:
							display_header_data( decoded_data )
					
					elif currentpageinmagazine == pagetofind:
						if decoded_data[1] < 26: # page row
							coding = magCodings[decoded_data[0]%8]
							function = magFunctions[decoded_data[0]%8]
							if (coding == 0):
								display_page_data( decoded_data )
							elif (coding == 2):
								if (function == 2 or function == 3):
									if ((decoded_data[1] < 3) or (decoded_data[1] < 5 and decoded_data[2][0] & 1)):
										# pointer data
										display_page_enhancement_data( decoded_data )
									else:
										# object definition data
										display_page_enhancement_data_26( decoded_data )
								else:
									display_page_enhancement_data( decoded_data )
							elif (coding == 3):
								display_hamming_8_4_data( decoded_data )
						
						elif decoded_data[1] == 26: # page enhancement data:
							display_page_enhancement_data_26( decoded_data )
						
						elif decoded_data[1] == 27: # link packet
							display_link_data( decoded_data )
						
						elif decoded_data[1] == 28: # page enhancement data
							display_page_enhancement_data( decoded_data )
			
			if not findpage: # code to display any packet
				if not IDL:
					if decoded_data[1] == 0: # header packet
						display_header_data( decoded_data )
					
					elif decoded_data[1] < 26: # page row
						coding = magCodings[decoded_data[0]%8]
						function = magFunctions[decoded_data[0]%8]
						if (coding == 0):
							display_page_data( decoded_data )
						elif (coding == 2):
							if (function == 2 or function == 3):
								if ((decoded_data[1] < 3) or (decoded_data[1] < 5 and decoded_data[2][0] & 1)):
									# pointer data
									display_page_enhancement_data( decoded_data )
								else:
									# object definition data
									display_page_enhancement_data_26( decoded_data )
							else:
								display_page_enhancement_data( decoded_data )
						elif (coding == 3):
							display_hamming_8_4_data( decoded_data )
					
					elif decoded_data[1] == 26: # page enhancement data:
						display_page_enhancement_data_26( decoded_data )
					
					elif decoded_data[1] == 27: # link packet
						display_link_data( decoded_data )
					
					elif decoded_data[1] == 28: # page enhancement data
						display_page_enhancement_data( decoded_data )
					
					elif decoded_data[1] == 29: # page enhancement data
						display_page_enhancement_data( decoded_data )
					
					elif decoded_data[1] == 30: 
						if decoded_data[0] == 8: # Broadcast service data packets
							display_broadcast_service_data( decoded_data )
						else: # Independent data services
							display_independent_data_service( decoded_data )
				
				if decoded_data[1] == 31: # Independent data services
					display_independent_data_service( decoded_data )

		offset += 42
		outfile.flush()

if __name__ == "__main__":
    main()