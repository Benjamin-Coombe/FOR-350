rule passwd{
	meta:
		description = "detects password based ltrace data"
		author = "benjamin coombe"
		date = "11/8/2025"
	
	strings:
		$passwd = "passwd"
		$shadow = "shadow"
		$tmp = "tmp"
condition:
		any of ($*)
}