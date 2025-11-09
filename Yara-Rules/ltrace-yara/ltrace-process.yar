rule fork{
	meta:
		description = "detect new process based ltrace data"
		author = "benjamin coombe"
		date = "11/8/2025"
	
	strings:
		$fork = "fork()"
		$execve = "execve()"
				
condition:
		any of ($*)
}