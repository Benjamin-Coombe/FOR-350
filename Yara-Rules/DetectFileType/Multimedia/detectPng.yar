rule png{
	meta:
		description = "detects png"
		author = "benjamin coombe"
		date = "10/10/2025"
	strings:
		$png = {89 50 4E 47 0D 0A 1A 0A}
	
	condition:
	$png
}