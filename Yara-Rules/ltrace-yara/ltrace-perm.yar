rule permission{
	meta:
		description = "detect permission based ltrace data"
		author = "benjamin coombe"
		date = "11/8/2025"
	
	strings:
		$permission = "chmod(file,0755"
condition:
		any of ($*)
}