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