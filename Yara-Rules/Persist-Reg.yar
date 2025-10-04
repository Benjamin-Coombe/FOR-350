import "pe"

rule Registry_Persistence_Advanced {
    meta:
        description = "Finds registry persistance"
        author = "Benjamin Coombe"
        date = "10/3/2025"
    strings:
        $reg1 = "RegCreateKeyExA" ascii
        $reg2 = "RegCreateKeyExW" ascii
        $reg3 = "RegSetValueExA" ascii
        $reg4 = "RegSetValueExW" ascii
        $run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $winlogon = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
        $services = "System\\CurrentControlSet\\Services" ascii wide nocase
        $ifeo = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" ascii wide nocase
        $appinit = "AppInit_DLLs" ascii wide
        $silent = "SilentProcessExit" ascii wide
    condition:
        pe.is_pe and
        2 of ($reg*) and
        (2 of ($run_key, $runonce, $winlogon, $services) or
         1 of ($ifeo, $appinit, $silent))
}