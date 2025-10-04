import "pe"

rule SuspiciousSectionCount {
    meta:
        description = "Finds files with abnormal section numbers"
        author = "Benjamin Coombe + threathunter"
        date = "10/3/2025"
    
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        (
            pe.number_of_sections < 3 or 
            pe.number_of_sections > 10
        )
}