#! /bin/python 

#################### Data Forensics EE6012 Assignments 1 and 2
#################### Jonathan O'Brien - 10002051
#################### Date 17/FEB/15

# Import required libraries 
import struct
import binascii
import sys



# Dictionary of codes for filesystem lookup
filesystem_type = {"0":"Empty","1":"12-bit fat","4":"16-bit fat","5":"extended ms-dos","6":"16-bit fat","7":"ntfs","11":"fat-32(chs)","12":"fat-32(lba)","14":"fat-16(lba)"}

#**************************************************************************
#************************Funtion Definitions*******************************
#**************************************************************************
#**************************************************************************

# Funtions to tranform bytes and clusters
def bytes_to_KB(b):
	return (b / 1024)

def sectors_to_mega(sectors):
	return (sectors * 512)/ 1024 / 1024

# funtion to reverse a string 2 characters at a time
# i use this with the binascii hexliify library method because it does not
# convert endian formats 
# "i was using stuct but this appeared to only support set size formats and
# i was not able to at least find a method to extract 3 bytes for example"
def reverse_bytes(b):
	# create empty string
    new = ""
    # steps back in increments of 2 "chars" from end of "string" (hex really)
    for x in range(-1, -len(b), -2):
    	# extract last 2 "chars" and place at start of string
    	# repeat
        new += b[x-1] + b[x]
    return new

# funtion for analysing a partition of 16 bytes passed as raw_mbr
def analyse_partition(raw_mbr):
	# create dictionary for partition information
	partition = {}
	# use struct to remove a single byte from first position using ">" big endian formatting
	# [:] allows from slicing at specific postions and offsets in python
	partition["boot_flag"] = struct.unpack('>b',raw_mbr[0:1])[0]
	# use this instead of struct here, 3 bytes is too difficult with struct
	# use the binacsii method hexilify to convert and extract in correct format
	# then use reverse_bytes to change to big endian
	# then convert to an integer with the int((num)16) syntax
	#these are legacy but i extract them anyways
	partition["begin_chs"] = int(reverse_bytes(binascii.hexlify(raw_mbr[1:3])),16)

	# extract the type code so it can be used in a lookup, it is only one byte 
	# so the stuck b> Big endian format works well here
	partition["type"] = struct.unpack('>b',raw_mbr[4])[0]
	# extracting odd number bytes with struct proved too difficult
	partition["end_chs"] = int(reverse_bytes(binascii.hexlify(raw_mbr[5:8])),16)

	# Extact the starting logical block address (starting sector) and size of the partion in sectors
	# dont know why i dont have the reverse the bytes here using "i" integer formating
	partition["start_LBA"] = struct.unpack('i',raw_mbr[8:12])[0]
	partition["size_in_sectors"] = struct.unpack('i',raw_mbr[12:16])[0]  # partition["size_in_sectors"] = int(reverse_bytes(binascii.hexlify(mbr[12:16])),16)
	return partition


### function to anaylse a specific volume that is fat-16
### gets passed the volumes data table and the starting sector for calculations
def analyse_volume(raw_vol, first_sector):
	# create a dictionary to store the information extracted from the volumes data table
	volume = {}
	# extract the number of sectors per cluster used in the volume
	# using struct to extract a single byte
	volume["no_sectors_per_cluster"] = struct.unpack('>b',raw_vol[13])[0]
	#extract the size of the reserved area in sectors, given in bytes once formatted to an INT
	volume["size_reserved_area_clusters"] = int(reverse_bytes(binascii.hexlify(raw_vol[14:16])),16)
	#Size of the fat in sectors
	volume["size_of_each_fat_sectors"] = int(reverse_bytes(binascii.hexlify(raw_vol[22:24])),16)
	volume["no_of_fat_copies" ] = struct.unpack('>b', raw_vol[16])[0]


	# calculate the fat area size of the volume by multiplying the number of fat copies by the
	# fat area size
	volume["fat_area_size"] = volume["size_of_each_fat_sectors"] \
	* volume["no_of_fat_copies"]

	# extract the maximum number of root directories allowed on the volume
	volume["max_no_root_dir"] = int(reverse_bytes(binascii.hexlify(raw_vol[17:19])),16)

	#(directory entry size for a FAT volume is awlays 32 bytes)
	# hard coded
	entry_size = 32
	# calculate the root directory size by multiplying the max number of directory enteries 
	# with the directory size in bytes
	# then dividing by the sector size
	volume["root_dir_size"] = (volume["max_no_root_dir"]*entry_size)/512
 	# calculate the cluster size
 	volume["cluster_size"] = volume["no_sectors_per_cluster"] * 512

 	# Start of the Data Area calculation 
 	# this DA sector address is calulated with adding the first sector and the size
 	# of the reserved area with the fat area size -- once passed these is the location of the volumes
 	# data area
 	volume["DA_address"] = first_sector  + volume["size_reserved_area_clusters"]\
 	+ volume["fat_area_size"]

 	# Since Cluster# 1 is used by microsoft to for the Dirty status of bad blocks in the volume
 	# so they can be avoided the real start of the data area is 
 	# the addition of the DA address with the root director size 
 	# cluster 2 resides at the first sector after the root directory in fat-16
 	volume["cluster2_address"] = volume["DA_address"] + volume["root_dir_size"]


 	# print out the values
	print "no_sectors_per_cluster", volume["no_sectors_per_cluster"]
	print "size_reserved_area_clusters", volume["size_reserved_area_clusters"]
	print "size fat sector", volume["size_of_each_fat_sectors"]
	print "no_of_fat_copies", volume["no_of_fat_copies"]
	print "fat_area_size", volume["fat_area_size"]
	print "max_no_root_dir", volume["max_no_root_dir"]
	print "Root Dir Size", volume["root_dir_size"]
	print "cluster_size", volume["cluster_size"]
	print "DA_address", volume["DA_address"]
	print "cluster#2_address", volume["cluster2_address"]
	return volume


# analyse a directory entry of 32 bytes
def analayse_dir_entry(raw_dir_entry):
	print "\n****************DIR_ENTRY*****************\n"

	# a dictionary for attributes that can be set in the dir entry
	att_type = {"128":"READ_ONLY","64":"HIDDEN","32":"SYSTEM_FILE","16":"VOL_LABEL"\
	,"8":"DIRECTORY","4":"ARCHIVE","15":"LONG_FILE_NAME"}

	d = {}
	d["deleted"] = False

	# if the first byte is "e5" then this is a deleted file
	if binascii.hexlify(raw_dir_entry[0]) == "e5":
		print "!!!!!!!!!DELETED!!!!!!!!!!!"
		d["deleted"] = True

	# the filename can be just pulled form the data structure directly 
	# when printed to the terminal console it is interpreted as ascii

	# i have modified it to decode the hex just in case
	d["filename"] = raw_dir_entry[0:11]
	d["filename"] = binascii.hexlify(d["filename"]).decode("hex")
	d["attributes"] = int(reverse_bytes(binascii.hexlify(raw_dir_entry[11])),16)
	d["starting_cluster"] = int(reverse_bytes(binascii.hexlify(raw_dir_entry[26:28])),16)
	d["size"] =  int(reverse_bytes(binascii.hexlify(raw_dir_entry[28:32])),16)

	try:
		# use the dictionary as a lookup for the filetype
		print "This is a ", att_type[str(d["attributes"])]
	except:
		print "Not a valid DIRECTORY"
	print "filename", d["filename"]
	# print "editedname", editedname
	print "attributes", d["attributes"]
	print "starting_cluster", d["starting_cluster"]
	print "size", d["size"], " Bytes"
	print "size", bytes_to_KB(int(d["size"])), " KiloBytes"


# same as above but only to be used for an entry that is a delted file
def analayse_dir_entry_for_del_files(raw_dir_entry, cluster2_address, no_sectors_per_cluster):
	d = {}
	att_type = {"128":"READ_ONLY","64":"HIDDEN","32":"SYSTEM_FILE","16":"VOL_LABEL","8":"DIRECTORY","4":"ARCHIVE","15":"LONG_FILE_NAME"}

	# uses a boolean value Detected to indicate that information is
	# in reference to a deleted file to the caller
	detected = False
	if binascii.hexlify(raw_dir_entry[0]) == "e5":
		print "!!!!!!!!!DELETED!!!!!!!!!!!"
		d["deleted"] = True
		# set a flag that a deleted file has been detected
		detected = True

		# attempt the join the empty space in some filenames and externsion
		# caused by the specifified 8 bytes + 3 bytes
		# works for this one only, but does not for others 
		# as it is not overly nessasry i will leave it
		#start = 0
		#char_count = 0
		#for i in range(0,8):
		#	temp = binascii.hexlify(raw_dir_entry[start:start +1])
		#	if not temp == "20":
		#		char_count = char_count + 1
		#	start = start + 1
		d["filename"] = raw_dir_entry[0:11]
		d["filename"] = binascii.hexlify(d["filename"]).decode("hex")
		#fname = d["filename"][0:char_count]
		#split = d["filename"].split()	
		#editedname = fname+"."+split[1]


		# extract "file" entry attributes, its starting cluster and its size
		d["attributes"] = int(reverse_bytes(binascii.hexlify(raw_dir_entry[11])),16)
		d["starting_cluster"] = int(reverse_bytes(binascii.hexlify(raw_dir_entry[26:28])),16)
		d["size"] =  int(reverse_bytes(binascii.hexlify(raw_dir_entry[28:32])),16)

		# Cluster Sector address of the file (start location)
		# is calcuated using the cluster #2 address and adding this to
		# the starting clsuter address of the entry minus the 2 unusable
		# multiplied by 8 (assuming 8 bytes per cluster)
		d["CSA"] = ((cluster2_address) + (d["starting_cluster" ]-2) * 8)

		#print infomation to the terminal
		print "deleted files name", d["filename"]
		#print "edited name", editedname
		try:
			# do a lookup and print the file type to terminal
			print "This is a ", att_type[str(d["attributes"])]
		except:
			print "not a valid entry"
			print str(d["attributes"])

		print "starting_cluster", d["starting_cluster"]
		print "size", d["size"], " Bytes"
		print "size", bytes_to_KB(int(d["size"])), " KiloBytes"
		print "Cluster sector address - CSA", d["CSA"] 
		# return the boolean indicator and file information
		return d, detected

#**************************************************************************
#************************Start of Program Execution************************
#*********************************Main()***********************************
#**************************************************************************

def main():
	# takes arguments from the command line to open a file
	# attaching to a file
	if (len(sys.argv) < 3):
	    print 'Usage: python forensics.py <filepath> <assigment number>\n'
	    sys.exit(0)
	    # file_f = open("Sample_1.dd", "rb")
	elif not (int(sys.argv[2]) == 1 or int(sys.argv[2]) == 2):
		print "Not a valid assigment, please choose 1 or 2"
		sys.exit(0)
	else:
	    file_f = open(str(sys.argv[1]), "rb")


	# seeks past boot code as it is not usefull
	file_f.seek(446)
	# read in the partitions information of the MBR
	mbr =  file_f.read(16 + 16 + 16 + 16)
	# Split into individual partion data, easier to access by starting zero offset
	# also easier for system (memory)
	# use a for loop and jump in increments of 16 bytes
	# passing partiton data to the analyse partion method and storing results in a
	# LIST (analaysd_parts)
	start = 0
	analysed_parts = []
	for i in [16,32,48,64]:
		#append the analyed partition information in a list (array)
		analysed_parts.append(analyse_partition(mbr[start:i]))
		#change start offset to increments of 16
		start = i


	# for loop to count active partitions in the collected data from the (LIST)
	# if the type is code is not "0" then it is a partition

	# this calculation assumes a disk with 4 primary partitons only
	#logical extened partitioning schemes are not accounted from here
	counter = 0
	for i in range(4):
		if not  analysed_parts[i]["type"] == 0:
			counter = counter + 1


	print "\n****************MBR_INFORMATION************************\n"

	print "number of visible partitions ", counter

	# loop to print information about the Partitons, type, start sector, size
	for i in range(4):
		print "----------------------------------------------"
		# use negative logic as an unused partion could be at any postion
		if not  analysed_parts[i]["type"] == 0:
			print "partition ", i + 1, " start sector ", analysed_parts[i]["start_LBA"]
		# for i in range(4):
		if not  analysed_parts[i]["type"] == 0:
			typecode = analysed_parts[i]["type"]
			print "partition ", i+ 1, " Type ", filesystem_type[str(typecode)]
		# for i in range(4):
		if not  analysed_parts[i]["type"] == 0:
			print "partition ", i+ 1, " size in clusters ",  analysed_parts[i]["size_in_sectors"]
			print "partition ", i + 1, " Size in MegaBytes", sectors_to_mega(int(analysed_parts[i]["size_in_sectors"]))


	# Code to check for the existance of possible hidden partitions
	# !!!!would not see one that was hidden at the end of the drive!!!
	hid = 0
	for i in range(3):
		if not  analysed_parts[i]["type"] == 0 and not analysed_parts[i + 1]["type"] == 0:
			if not analysed_parts[i]["start_LBA"] + analysed_parts[i]["size_in_sectors"] == analysed_parts[i + 1]["start_LBA"]:
				hid = hid + 1	
	if hid > 0:
		print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
		print " +++++++++ Possibly ", hid, "Hidden Partitions"
		print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"

	# exectute assigment 2 if passed as argument to command line
	if int(sys.argv[2]) == 2:
		file_f.seek(0)
		# find the first sector of the first volume by multiplying the starting lBA with the sector size in bytes
		vol1_sector_addr = int(analysed_parts[0]["start_LBA"]) * 512
		# seek to the sector address of volume1 entry
		file_f.seek(vol1_sector_addr)
		volume1 = file_f.read(510) #510 -- removed layout of fat volume (1FE offset)


		print "\n****************FIRST_VOLUME_ANALYSIS*****************\n"

		# make sure that the volume is is a FAT-16 volume
		if not int(analysed_parts[0]["type"]) ==  4:
			# analyse and extract information passing the starting block for that volume
			vol1_info = analyse_volume(volume1, int(analysed_parts[0]["start_LBA"]))
		else:
			print "First Partition is not fat-16"





		print "\n$$$$$$$$$$$$$$$$$$$$-DIRECTORY_LISTING ANALYSIS-$$$$$$$$$$$$$$$$$$$$$$"
		# read the first by itself - i could just add into loop
		# return seek to zero of file
		file_f.seek(0)
		root_dir_sector_address = vol1_info["DA_address"]
		# seek to the root dir sector address of the fat volume
		file_f.seek(root_dir_sector_address * 512)
		# extract the root dir by its indicated size
		s = vol1_info["root_dir_size"]
		# read in the root directory
		vol1_d1 = file_f.read(s)
		# pass for analysis  -- this is for the first entry only
		analayse_dir_entry(vol1_d1)

		# seeks to second entry
		# file_f.seek(0)
		# file_f.seek(((root_dir_sector_address )* 512) + 32)
		# temp = file_f.read(1)
		# print binascii.hexlify(temp)


		# (this just shows information on all enteries)
		# seeks through entrys in 32 Byte Hops
		# checking first bytes for \x00 indicating there is no entry then stopping
		starting_address = (root_dir_sector_address * 512)
		loop = True
		add = 32
		while(loop):
			# reset the seek to start of file
			file_f.seek(0)
			# seek to the new postion in directorry enteries - add 32 bytes each time
			file_f.seek(((root_dir_sector_address )* 512) + add)
			# read in 32 bytes
			temp = file_f.read(32)
			# if the first byte is "\x00" then stop the loop and break early	
			if binascii.hexlify(temp[0]) == "00":
				loop = False
				break
			# analayze the dir entry 
			analayse_dir_entry(temp)
			# add the next 32 bytes for the file seek directory walk
			add = add + 32


		print "\n########################CHECK DELELETED FILES##############################\n"

		# !!!!!!!!!!!same again!!!!!!!!!!!!!!!!! but calling method for deleted files

		# seeks through entrys in 32 Byte Hops
		# checcking first bytes for \x00 indicating there is no entry then stopping
		starting_address = (root_dir_sector_address * 512)
		loop = True
		add = 0
		while(loop):
			file_f.seek(0)
			file_f.seek(((root_dir_sector_address )* 512) + add)
			temp = file_f.read(32)
			if binascii.hexlify(temp[0]) == "00":
				loop = False
				break
			# store deleted file information in status
			status = analayse_dir_entry_for_del_files(temp,vol1_info["cluster2_address"], vol1_info["no_sectors_per_cluster"])
			# if the status has returned a detelted entry then stop
			if not status == None:
				break
			add = add + 32

		# extract the dictionary from the list
		DELETED_ENTRY = status[0]
		# extract the calculted CSA cluster address of the file
		csa = DELETED_ENTRY["CSA"]
		# calculate the bytes
		deleted_entry_address = csa * 512
		# reset the seek postion
		file_f.seek(0)
		# seek to CSA address in bytes
		file_f.seek(deleted_entry_address)
		# read in 16 bytes of content
		deleted_contents = file_f.read(16)

		# first_byte = deleted_contents[0]
		# print binascii.hexlify(first_byte)

		# Print the retrived contents to the terminal
		print "\n\ndeleted first 16 Bytes Content"
		print "----------------------------------"
		# print deleted_contents
		print binascii.hexlify(deleted_contents).decode("hex")
		print "----------------------------------"

		print "\nPROGRAM TERMINATING SUCCESSFULLY"


if __name__ == '__main__':
    main()	



###########-----unfinshed attempt at cluster chaining in FAT---#############

# first_fat_entry = (analysed_parts[0]["start_LBA"] + 2) * 512
# print first_fat_entry
# file_f.seek(0)
# b = []
# start = DELETED_ENTRY["starting_cluster"]
# for i in range(16):
# 	# get to the first entry of the File in the FAT-16 Table (2-byte entrys)
# 	file_f.seek(first_fat_entry + (start *2))
# 	b.append(file_f.read(2))
# 	first_bytes = b[i]
# 	# print int(reverse_bytes(binascii.hexlify(binascii.hexlify(first_byte),16))
# 	start = int(reverse_bytes(binascii.hexlify(first_bytes)),16)

# print b

# coun = 0
# for i in list(b):
# 	print reverse_bytes(binascii.hexlify(b[coun]))
# 	coun = coun + 1