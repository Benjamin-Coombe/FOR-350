rule gif{
	meta:
		description = "detects gifs"
		author = "benjamin coombe"
		date = "10/10/2025"
	strings:
		$gif = {47 49 46 38}
	
	condition:
	$gif
}