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