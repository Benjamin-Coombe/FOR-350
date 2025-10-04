rule Command_strings{
	meta:
		description = "detects executable command strings"
		author = "benjamin coombe"
		date = "10/2/2025"
	strings:
		$cmd1 = "powershell.exe" ascii wide nocase
		$cmd2 = "cmd.exe" ascii wide nocase
		$cmd3 = "system(" ascii
		$cmd4 = "WinExec" ascii
		$cmd5 = "CreateProcess" ascii
		$cmd6 = "c/" ascii
		$cmd7 = "-exec" ascii wide
	condition:
		2 of them
}