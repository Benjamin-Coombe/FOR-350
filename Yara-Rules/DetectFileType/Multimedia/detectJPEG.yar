rule Detect_jpeg{
	meta:
		description = "detects jpegs"
		author = "benjamin coombe"
		date = "10/6/2025"
	strings:
		$jpeg = {FF D8}
	
	condition:
	$jpeg at 0
}