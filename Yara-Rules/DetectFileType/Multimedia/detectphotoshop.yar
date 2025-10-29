rule photoshop{
	meta:
		description = "detects photoshop images"
		author = "benjamin coombe"
		date = "10/10/2025"
	strings:
		$photoshop = {38 42 50 53}
	
	condition:
	$photoshop
}