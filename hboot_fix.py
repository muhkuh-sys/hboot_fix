import argparse
import hashlib

tParser = argparse.ArgumentParser(description='View and patch checksums of a HBOOT image.')
tParser.add_argument('-v', '--verbose',
                     dest='fVerbose',
                     required=False,
                     default=False,
                     action='store_const', const=True,
                     help='Be more verbose.')
tParser.add_argument('-f', '--fix-hashes',
                     dest='fFix',
                     required=False,
                     default=False,
                     action='store_const', const=True,
                     help='Fix invalid hashes.')
tParser.add_argument('strInputFile',
                     metavar='FILE',
                     help='Read the HBoot definition from FILE.')
tParser.add_argument('strOutputFile',
                     metavar='FILE',
                     help='Write the HBoot image to FILE.')
tArgs = tParser.parse_args()

tFile = open(tArgs.strInputFile, 'rb')
strData = tFile.read()
tFile.close()

# A HWC starts at offset 64.
ulPosStart = 64
uiHashSize = 4

# Loop over all chunks.
ulPosCnt = ulPosStart
ulPosEnd = len(strData)
while ulPosCnt<ulPosEnd:
    # Get the tag.
    strTagName = strData[ulPosCnt:ulPosCnt+4]
    # Get the size.
    ulChunkSize = ord(strData[ulPosCnt+4]) + 0x0100 * ord(strData[ulPosCnt+5]) + 0x010000 * ord(strData[ulPosCnt+6]) + 0x01000000 * ord(strData[ulPosCnt+7])
    print('Found tag "%s" with 0x%08x.' % (strTagName, ulChunkSize))

    # Get the chunk and the checksum.
    if strTagName=='SKIP':
        strChunk = strData[ulPosCnt:ulPosCnt+8]
        uiHashPosition = ulPosCnt+8
    else:
        strChunk = strData[ulPosCnt:ulPosCnt+4+4*ulChunkSize]
        uiHashPosition = ulPosCnt+4+4*ulChunkSize

    # Get the hash.
    strHash = strData[uiHashPosition:uiHashPosition+uiHashSize]

    # Verify the hash.
    tHash = hashlib.sha384()
    tHash.update(strChunk)
    strMyHash = tHash.digest()
    if strHash==strMyHash[0:uiHashSize]:
        print('  Hash OK')
    else:
        print('  Hash ERROR')
        if tArgs.fFix is True:
            # Update the hash.
            print('Fixing the hash.')
            strData = strData[0:uiHashPosition] + strMyHash[0:uiHashSize] + strData[uiHashPosition+uiHashSize:]

    ulPosCnt += 8 + 4 * ulChunkSize

tFile = open(tArgs.strOutputFile, 'wb')
tFile.write(strData)
tFile.close()
