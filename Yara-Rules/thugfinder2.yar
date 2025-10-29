rule frontpage{
	meta:
		description = "finds frontpage.jpg"
		author = "benjamin coombe"
		date = "10/13/2025"
	
	strings:
	$exif = "Y21kIC9jI"
	
	condition:
	$exif
}

rule Imagedownloader{
	meta:
		description = "finds imagedownloader.exe"
		author = "benjamin coombe"
		date = "10/13/2025"
	
	strings:
	$ipaddress = "165.73.244.11"
	
	condition:
	$ipaddress
}

rule SecurityAdvisory{
	meta:
		description = "finds securityAdvisory.docm"
		author = "benjamin coombe"
		date = "10/13/2025"
	
	strings:
	$macro = "vbaData.xml" nocase
	
	condition:
	$macro
}