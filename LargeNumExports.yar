import "pe"

rule LargeNumberOfExports {
	meta:
		description = "fidns files that have many exports"
		author = "benjamin coombe"
		date = "10/2/2025"
	condition:
		pe.number_of_exports < 5 or pe.number_of_exports > 10
}