package main

import "fmt"

var S_BOX_ZERO = [16]byte{12, 15, 7, 10, 14, 13, 11, 0, 2, 6, 3, 1, 9, 4, 5, 8}
var S_BOX_ONE = [16]byte{7, 2, 14, 9, 3, 11, 0, 4, 12, 13, 1, 10, 6, 15, 8, 5}

func applySBoxes(msg byte, icb bool) (confused byte) {
	var leftbits byte = msg >> 4
	var rightbits byte = msg & 0x0F // 00001111

	if icb {
		return (S_BOX_ZERO[rightbits] << 4) | S_BOX_ONE[leftbits]
	} else {
		return (S_BOX_ZERO[leftbits] << 4) | S_BOX_ONE[rightbits]
	}
}

//this could be replaced by a 256-to-256 encoder,
//similar to how the s-boxes work, just 16x the size
func applyPermutation(interrupted byte) (permuted byte) {
	permuted = 0x00
	if ((interrupted >> 7) & 0x01) == 0x01 { //0th bit (left to right)
		permuted |= 16 //flips 3rd bit
	}
	if ((interrupted >> 6) & 0x01) == 0x01 { //1st bit
		permuted |= 4 //flips 5th bit
	}
	if ((interrupted >> 5) & 0x01) == 0x01 { //2nd bit
		permuted |= 128 //flips 0th bit
	}
	if ((interrupted >> 4) & 0x01) == 0x01 { //3rd bit
		permuted |= 8 //flips 4th bit
	}
	if ((interrupted >> 3) & 0x01) == 0x01 { //4th bit
		permuted |= 32 //flips 2nd bit
	}
	if ((interrupted >> 2) & 0x01) == 0x01 { //5th bit
		permuted |= 64 //flips 1st bit
	}
	if ((interrupted >> 1) & 0x01) == 0x01 { //6th bit
		permuted |= 1 //flips 7th bit
	}
	if ((interrupted >> 0) & 0x01) == 0x01 { //7th bit
		permuted |= 2 //flips 6th bit
	}
	return permuted
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

func encryptBlock(key [16]byte, msg []byte) {
	// I think I need to reverse each of these...
	//OR, access them in reverse
	var msg_lower_half []byte = msg[0:8]
	var msg_upper_half []byte = msg[8:16]

	for round := uint8(0); round < 16; round++ {
		var transform_control_byte byte = key[(round*7)%16]

		for step := uint8(0); step < 8; step++ {
			//round 0 = bytes 0-7, round 1 = bytes 7-14...
			var key_byte byte = key[((round*7)+step)%16]
			var upper_msg_byte byte = msg_upper_half[step] //or if I'm reversing, 7-step?
			var icb bool = ((transform_control_byte >> (7 - step)) & 0x01) == 0x01
			stepfn(key_byte, upper_msg_byte, icb, step, msg_lower_half)
		}

		msg_lower_half, msg_upper_half = msg_upper_half, msg_lower_half
	}
}

func main() {
	var key [16]byte = [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}
	var msg []byte = []byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB}
	fmt.Printf("%08b\n", msg[0])
	fmt.Printf("%08b\n", msg[1])
	fmt.Printf("%08b\n", msg[2])
	fmt.Printf("%08b\n", msg[3])
	fmt.Printf("%08b\n", msg[4])
	fmt.Printf("%08b\n", msg[5])
	fmt.Printf("%08b\n", msg[6])
	fmt.Printf("%08b\n", msg[7])
	fmt.Printf("%08b\n", msg[8])
	fmt.Printf("%08b\n", msg[9])
	fmt.Printf("%08b\n", msg[10])
	fmt.Printf("%08b\n", msg[11])
	fmt.Printf("%08b\n", msg[12])
	fmt.Printf("%08b\n", msg[13])
	fmt.Printf("%08b\n", msg[14])
	fmt.Printf("%08b\n", msg[15])
	fmt.Println(msg)

	fmt.Printf("\n")
	encryptBlock(key, msg)
	fmt.Printf("\n")

	fmt.Printf("%08b\n", msg[0])
	fmt.Printf("%08b\n", msg[1])
	fmt.Printf("%08b\n", msg[2])
	fmt.Printf("%08b\n", msg[3])
	fmt.Printf("%08b\n", msg[4])
	fmt.Printf("%08b\n", msg[5])
	fmt.Printf("%08b\n", msg[6])
	fmt.Printf("%08b\n", msg[7])
	fmt.Printf("%08b\n", msg[8])
	fmt.Printf("%08b\n", msg[9])
	fmt.Printf("%08b\n", msg[10])
	fmt.Printf("%08b\n", msg[11])
	fmt.Printf("%08b\n", msg[12])
	fmt.Printf("%08b\n", msg[13])
	fmt.Printf("%08b\n", msg[14])
	fmt.Printf("%08b\n", msg[15])
	fmt.Println(msg)
}
