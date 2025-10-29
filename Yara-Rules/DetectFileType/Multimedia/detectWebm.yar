rule webM{
	meta:
		description = "detects webM"
		author = "benjamin coombe"
		date = "10/10/2025"
	strings:
		$WebM = {1A 45 DF A3}
	
	condition:
	$WebM
}