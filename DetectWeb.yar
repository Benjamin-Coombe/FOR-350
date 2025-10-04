rule Detect_Web{
	meta:
		description = "detects web based actions"
		author = "benjamin coombe"
		date = "10/2/2025"
	
	strings:
		$http = "http://"
		$https = "https://"
		$com = ".com"
		$net = ".net"
		$org = ".org"
		$ipv4 = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
		$installer = "installer"
		$http2 = "http"
		
	condition:
		any of ($*)
}