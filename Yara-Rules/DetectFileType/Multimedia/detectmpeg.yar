rule mpeg{
	meta:
		description = "detects mp4"
		author = "benjamin coombe"
		date = "10/10/2025"
	strings:
		$mpeg = { 00 00 01 B3}
	Condition:
		$mpeg
}