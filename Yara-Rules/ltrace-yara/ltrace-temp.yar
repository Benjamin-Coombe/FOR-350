rule temp{
	meta:
		description = "detect temp directory based ltrace data"
		author = "benjamin coombe"
		date = "11/8/2025"
	
	strings:
		$temp = "fopen(/tmp/()"
		$write = ""w""		
condition:
		any of ($*)
}