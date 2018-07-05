Hashing

A hash is made of four byte sections that are Base85 encoded and separated by dashes. These can be between 1 and 20 sections long. The first section is the first 8 bytes of a stream. If the file is smaller then 8 bytes then a single hash is done. The second through the 20th are the data split by one of three four-character strings:
 - 4 nulls
 
 *Future*
 
 - 2 line feeds
 - 2 carridge return line feeds
 - 2 16LE line feeds
 - 2 16BE line feeds
 - 2 16LE carridge return line feeds
 - 2 16BE carridge return line feeds
 
 Each section is a hash of data between the split values. The minimum length of data being hashed is eight bytes. If less then 8 bytes are hashed between the splits the value will be disgarded. The hashing aglorythm does not need to be complex but should generate a generally unique value. Adler32 and Fletcher Checksum are two examples of these. More advanced hashing methods can be used and truncated to four bytes. If hashing is still being done on the stream and 20 hashes already exist each new hash will be inserted at the end of the list and the values starting at indicie 2 and will be XORed with the next neighbor keeping the length of 20. This will continue all the way to 20 XORed with the hash being inserted. The first value will never be XORed.

 Base85 encode string:
 "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:_?+=^!/*&<>()[]{}@%$~"

 hashy.jpg:
 8]8Rw-J$D@v-ipvux-*nQ9l-ZPE:y-t$?Kn-f[z12-7cqQX-hz>.X-G8V@!-jBK5k-*I1@P-/m5vy-f%y)<-0sw/(-8UscY-7/NkH-UoCF~-A^to{-KhFz&

hashy.txt
1$fI}


New thoughts:
Hash and rotating may not be the best method. Other possibilities would be utilizing the size from the Adler32 hash to determine which ones are combined or if it should be thrown away. For example if you have hashes that are in this order and of this size: 15, 8, 16, 179, 81, 123. Then you could combine 15 to 8 or 8 to 16 but you wouldn't want to combine 16 with 179. So a dimension could be size but another dimension could be the number of times it has been combined. As each time it is combined it is not as representative of the data.

This may not be the best for scripts and should probably be kept for binary elements. This also means LF and CR should be taken out of delimiting of important information. Unless we want to try to determine which type of file it is binary/text we would also need to decide on encoding. most scripts are ASCII but UTF16LE and UTF8 is becoming more common although ASCII and UTF8 would have the same delimiters. We could probably safely say that once a null delimiter was seen then text base delimiters should not be checked.
