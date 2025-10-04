import "pe"

rule no_imports{
	meta:
		description = "finds pe files with no imports"
		author = "Benjamin Coombe"
		date = "10/2/2025"
	condition:
		pe.is_pe and
		pe.number_of_imports == 0
}