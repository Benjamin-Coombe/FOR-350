import "pe"

rule upx_packed {
	meta:
		description = "finds files packed with UPX"
		author = "Benjamin Coombe"
		date = "10/2/2025"
	strings:
	 $upx1 = "UPX0"
	 $upx2 = "UPX1"
	condition:
		any of ($upx*)
}