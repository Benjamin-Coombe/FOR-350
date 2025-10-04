import "pe"
import "math"

rule HighEntropy {
    meta:
        description = "Finds files with high entropy"
        author = "Benjamin Coombe + threathunter"
        date = "10/3/2025"
    
        strings:
		$packer1 = "UPX0" nocase
		$packer2 = "UPX1" nocase
		
	condition:
	(
	for any i in (0..pe.number_of_sections-1) : (
                math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.0 and
                not pe.sections[i].name contains ".rsrc" and
                not pe.sections[i].name contains ".reloc"
			)
	) or
	any of ($packer*)
}