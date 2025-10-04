rule Dos_twice{
	meta:
		description = "Detects multiple instances of This program cannot be run in DOS mode"
		author = "Benjamin Coombe"
		date = "10/3/2025"
	strings:
		$line = /This program cannot be run in DOS mode/
	condition:
		#line >= 2

}