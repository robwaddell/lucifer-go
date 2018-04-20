package main

import "flag"
import "fmt"
import "io"
import "os"

var S_BOX_ZERO = [16]byte{12, 15, 7, 10, 14, 13, 11, 0, 2, 6, 3, 1, 9, 4, 5, 8}
var S_BOX_ONE = [16]byte{7, 2, 14, 9, 3, 11, 0, 4, 12, 13, 1, 10, 6, 15, 8, 5}

//This lookup table encodes all of the output values for all of the input values of a function that
//permutes a byte.
//Put simply, if the 0th bit of the input is 1, then the 3rd bit (counting from 0) of the output is 1.
//If the 1st bit of the input is 1, then the 5th bit of the output is 1. Here is the full permutation:
//0 -> 3
//1 -> 5
//2 -> 0
//3 -> 4
//4 -> 2
//5 -> 1
//6 -> 7
//7 -> 6
//(above, the 0th bit is the left-most, most-significant bit)
//This could be implemented with bitwise operators, but it is more efficient to use a lookup table.
var BYTE_PERMUTE = [256]byte{
	0, 2, 1, 3, 64, 66, 65, 67,
	32, 34, 33, 35, 96, 98, 97, 99,
	8, 10, 9, 11, 72, 74, 73, 75,
	40, 42, 41, 43, 104, 106, 105, 107,
	128, 130, 129, 131, 192, 194, 193, 195,
	160, 162, 161, 163, 224, 226, 225, 227,
	136, 138, 137, 139, 200, 202, 201, 203,
	168, 170, 169, 171, 232, 234, 233, 235,
	4, 6, 5, 7, 68, 70, 69, 71,
	36, 38, 37, 39, 100, 102, 101, 103,
	12, 14, 13, 15, 76, 78, 77, 79,
	44, 46, 45, 47, 108, 110, 109, 111,
	132, 134, 133, 135, 196, 198, 197, 199,
	164, 166, 165, 167, 228, 230, 229, 231,
	140, 142, 141, 143, 204, 206, 205, 207,
	172, 174, 173, 175, 236, 238, 237, 239,
	16, 18, 17, 19, 80, 82, 81, 83,
	48, 50, 49, 51, 112, 114, 113, 115,
	24, 26, 25, 27, 88, 90, 89, 91,
	56, 58, 57, 59, 120, 122, 121, 123,
	144, 146, 145, 147, 208, 210, 209, 211,
	176, 178, 177, 179, 240, 242, 241, 243,
	152, 154, 153, 155, 216, 218, 217, 219,
	184, 186, 185, 187, 248, 250, 249, 251,
	20, 22, 21, 23, 84, 86, 85, 87,
	52, 54, 53, 55, 116, 118, 117, 119,
	28, 30, 29, 31, 92, 94, 93, 95,
	60, 62, 61, 63, 124, 126, 125, 127,
	148, 150, 149, 151, 212, 214, 213, 215,
	180, 182, 181, 183, 244, 246, 245, 247,
	156, 158, 157, 159, 220, 222, 221, 223,
	188, 190, 189, 191, 252, 254, 253, 255,
}

//this precomputed lookup table provides a convenient and efficient way
//to reverse a byte, eg. "11110101" -> "10101111"
var BYTE_REVERSE = [256]byte{
	0, 128, 64, 192, 32, 160, 96, 224,
	16, 144, 80, 208, 48, 176, 112, 240,
	8, 136, 72, 200, 40, 168, 104, 232,
	24, 152, 88, 216, 56, 184, 120, 248,
	4, 132, 68, 196, 36, 164, 100, 228,
	20, 148, 84, 212, 52, 180, 116, 244,
	12, 140, 76, 204, 44, 172, 108, 236,
	28, 156, 92, 220, 60, 188, 124, 252,
	2, 130, 66, 194, 34, 162, 98, 226,
	18, 146, 82, 210, 50, 178, 114, 242,
	10, 138, 74, 202, 42, 170, 106, 234,
	26, 154, 90, 218, 58, 186, 122, 250,
	6, 134, 70, 198, 38, 166, 102, 230,
	22, 150, 86, 214, 54, 182, 118, 246,
	14, 142, 78, 206, 46, 174, 110, 238,
	30, 158, 94, 222, 62, 190, 126, 254,
	1, 129, 65, 193, 33, 161, 97, 225,
	17, 145, 81, 209, 49, 177, 113, 241,
	9, 137, 73, 201, 41, 169, 105, 233,
	25, 153, 89, 217, 57, 185, 121, 249,
	5, 133, 69, 197, 37, 165, 101, 229,
	21, 149, 85, 213, 53, 181, 117, 245,
	13, 141, 77, 205, 45, 173, 109, 237,
	29, 157, 93, 221, 61, 189, 125, 253,
	3, 131, 67, 195, 35, 163, 99, 227,
	19, 147, 83, 211, 51, 179, 115, 243,
	11, 139, 75, 203, 43, 171, 107, 235,
	27, 155, 91, 219, 59, 187, 123, 251,
	7, 135, 71, 199, 39, 167, 103, 231,
	23, 151, 87, 215, 55, 183, 119, 247,
	15, 143, 79, 207, 47, 175, 111, 239,
	31, 159, 95, 223, 63, 191, 127, 255,
}

func reverseByte(n byte) (reversed byte) {
	return BYTE_REVERSE[n]
}

func applySBoxes(msg byte, icb bool) (confused byte) {
	var leftbits byte = 0
	var rightbits byte = 0

	//read bits out of the left nibble (4 bits) with the rightmost bit being the "most significant"
	for i := uint(4); i <= 7; i++ {
		leftbits = (leftbits * 2) + (msg >> i & 0x01)
	}

	//same, for right nibble
	for i := uint(0); i <= 3; i++ {
		rightbits = (rightbits * 2) + (msg >> i & 0x01)
	}

	if icb {
		return reverseByte((S_BOX_ONE[rightbits] << 4) | S_BOX_ZERO[leftbits])
	} else {
		return reverseByte((S_BOX_ONE[leftbits] << 4) | S_BOX_ZERO[rightbits])
	}
}

func applyPermutation(interrupted byte) (permuted byte) {
	return BYTE_PERMUTE[interrupted]
}

//this implements a diffusion pattern on the msg half that
//is being modified... hard to describe without a diagram,
//maybe I will make some ASCII art later
//the offset is which step # this is, AKA how many rotations have happened
func applyDiffusion(permuted byte, offset uint8, msg_half []byte) {
	//XOR the 0th bit of the permuted byte with the
	//0th bit of the 7th byte (plus offset) of the message
	//(if the permuted bit is 0, no operation needs to
	//take place since XOR with 0 changes nothing)
	if ((permuted >> 7) & 0x01) == 0x01 {
		msg_half[(7+offset)%8] ^= 128
	}
	//1st bit of permuted with 1st bit of 6th byte...
	if ((permuted >> 6) & 0x01) == 0x01 {
		msg_half[(6+offset)%8] ^= 64
	}
	//2nd bit of permuted with 2nd bit of 2nd byte...
	if ((permuted >> 5) & 0x01) == 0x01 {
		msg_half[(2+offset)%8] ^= 32
	}
	//3rd bit of permuted with 3rd bit of 1st byte...
	if ((permuted >> 4) & 0x01) == 0x01 {
		msg_half[(1+offset)%8] ^= 16
	}
	//4th bit of permuted with 4th bit of 5th byte...
	if ((permuted >> 3) & 0x01) == 0x01 {
		msg_half[(5+offset)%8] ^= 8
	}
	//5th bit of permuted with 5th bit of 0th byte...
	if ((permuted >> 2) & 0x01) == 0x01 {
		msg_half[(0+offset)%8] ^= 4
	}
	//6th bit of permuted with 6th bit of 3rd byte...
	if ((permuted >> 1) & 0x01) == 0x01 {
		msg_half[(3+offset)%8] ^= 2
	}
	//7th bit of permuted with 7th bit of 4th byte...
	if ((permuted >> 0) & 0x01) == 0x01 {
		msg_half[(4+offset)%8] ^= 1
	}
}

func stepfn(key_byte byte, upper_msg_byte byte, icb bool, step_num uint8, lower_msg_half []byte) {
	var confused_byte byte = applySBoxes(upper_msg_byte, icb)
	var interrupted_byte byte = confused_byte ^ key_byte
	var permuted_byte byte = applyPermutation(interrupted_byte)
	applyDiffusion(permuted_byte, step_num, lower_msg_half)
}

func encryptBlock(key []byte, msg []byte) {
	var msg_lower_half []byte = msg[0:8]
	var msg_upper_half []byte = msg[8:16]

	for round := uint8(0); round < 16; round++ {
		var transform_control_byte byte = key[(round*7)%16]

		for step := uint8(0); step < 8; step++ {
			//round 0 = bytes 0-7, round 1 = bytes 7-14...
			var key_byte byte = key[((round*7)+step)%16]
			var upper_msg_byte byte = msg_upper_half[step]
			var icb bool = ((transform_control_byte >> (7 - step)) & 0x01) == 0x01
			stepfn(key_byte, upper_msg_byte, icb, step, msg_lower_half)
		}

		msg_lower_half, msg_upper_half = msg_upper_half, msg_lower_half
	}

	//swap contents of the lower half and upper half of the message
	for i := 0; i < 8; i++ {
		msg_lower_half[i], msg_upper_half[i] = msg_upper_half[i], msg_lower_half[i]
	}
}

//decryption is the same as encryption, but with key bytes accessed in a
//different order
func decryptBlock(key []byte, msg []byte) {
	var msg_lower_half []byte = msg[0:8]
	var msg_upper_half []byte = msg[8:16]

	for round := uint8(0); round < 16; round++ {
		var transform_control_byte byte = key[((round+1)*9)%16]

		for step := uint8(0); step < 8; step++ {
			//round 0 = bytes 9-0, round 1 = bytes 2-9, round 2 = bytes 11-2...
			var key_byte byte = key[(((round+1)*9)+step)%16]
			var upper_msg_byte byte = msg_upper_half[step]
			var icb bool = ((transform_control_byte >> (7 - step)) & 0x01) == 0x01
			stepfn(key_byte, upper_msg_byte, icb, step, msg_lower_half)
		}

		msg_lower_half, msg_upper_half = msg_upper_half, msg_lower_half
	}

	//swap contents of the lower half and upper half of the message
	for i := 0; i < 8; i++ {
		msg_lower_half[i], msg_upper_half[i] = msg_upper_half[i], msg_lower_half[i]
	}
}

func processFile(key_file, input_file, output_file string, encrypt bool) {
	//read key_file into key
	key := make([]byte, 16)
	f_key, err := os.Open(key_file)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f_key.Close()
	n_bytes_key, err := f_key.Read(key)
	if err != nil {
		fmt.Println(err)
		return
	}
	if n_bytes_key != 16 {
		fmt.Println("key_file less than 16 bytes long")
		return
	}

	//set up input and output file handles
	f_input, err := os.Open(input_file)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f_input.Close()
	f_output, err := os.Create(output_file)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f_output.Close()

	input_block := make([]byte, 16)
	//for encryption, we always want SOME padding- in the case of
	//an input file that is divisible by 16 bytes, we will add
	//a whole block of padding, so that no real data is mistaken for padding
	var padding_added bool = false
	for {
		n_bytes_input, err := f_input.Read(input_block)
		if err != nil {
			if err == io.EOF {
				if padding_added == false && encrypt == true {
					var pad_block = []byte{
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
					}
					encryptBlock(key, pad_block)
					f_output.Write(pad_block)
				}
				if encrypt == false {
					file_info, err := f_output.Stat()
					if err != nil {
						fmt.Println("couldn't get output file stat")
						return
					}
					file_length := file_info.Size()

					//read the last byte from the file to get padding length
					pad_len_arr := make([]byte, 1)
					f_output.ReadAt(pad_len_arr, file_length-1)
					padding_length := pad_len_arr[0]

					f_output.Truncate(file_length - int64(padding_length))
				}
				return
			}

			fmt.Println(err)
			return
		}
		//if there are less than 16 bytes left, then we need to pad
		if n_bytes_input < 16 {
			if encrypt == true {
				for i := n_bytes_input; i < 15; i++ {
					input_block[i] = 0x00
				}
				//last byte = number of padding bytes
				input_block[15] = byte(16 - n_bytes_input)
				padding_added = true
			} else {
				fmt.Println("Number of bytes in file to decrypt not divisible by 16")
				return
			}
		}

		if encrypt == true {
			encryptBlock(key, input_block)
		} else {
			decryptBlock(key, input_block)
		}

		f_output.Write(input_block)
	}
}

func printUsage() {
	fmt.Println("Usage: lucifer-go (--encrypt | --decrypt) <keyfile> <inputfile> <outputfile>")
}

func main() {
	encrypt := flag.Bool("encrypt", false, "encrypt a file")
	decrypt := flag.Bool("decrypt", false, "decrypt a file")
	flag.Parse()
	if len(flag.Args()) != 3 {
		fmt.Println("Unrecognized number of arguments")
		printUsage()
		return
	}
	if *encrypt && *decrypt {
		fmt.Println("You can either encrypt or decrypt, not both")
		printUsage()
		return
	}
	if !*encrypt && !*decrypt {
		fmt.Println("Please provide an --encrypt or a --decrypt option")
		printUsage()
		return
	}

	keyfile := flag.Args()[0]
	inputfile := flag.Args()[1]
	outputfile := flag.Args()[2]

	//if decrypt is true, then encrypt will be false, thus passing the right value in
	processFile(keyfile, inputfile, outputfile, *encrypt)
}
