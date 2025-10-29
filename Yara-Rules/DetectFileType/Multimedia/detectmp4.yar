rule mp4{
	meta:
		description = "detects mp4"
		author = "benjamin coombe"
		date = "10/10/2025"
	strings:
		$mp1 = {00 00 00 14 66 74 79 70 69 73 6F 6D}
		$mp2 = {00 00 00 18 66 74 79 70}
		$mp3 = {00 00 00 1C 66 74 79 70}
		$mp4 = {66 74 79 70 33 67 70 35}
		$mp5 = {66 74 79 70 4D 53 4E 56}
		$mp6 = {66 74 79 70 69 73 6F 6D} 
	
	condition:
	any of (mp*)
}