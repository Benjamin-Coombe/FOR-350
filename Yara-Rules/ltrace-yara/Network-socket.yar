rule socket{
	meta:
		description = "detect network based ltrace data"
		author = "benjamin coombe"
		date = "11/8/2025"
	
	strings:
		$socket = "socket()"
		$bind = "bind()"
		$connect = "connect()"		
condition:
		any of ($*)
}