rule LockBit5_Ransomware {
    meta:
        description = "LockBit 5.0 detection based on last IOCs (not previous generation Lockbit)"
        author = "ArmorIntel"
        date = "2025-11-02"
        references = "https://www.trendmicro.com/en_gb/research/25/i/lockbit-5-targets-windows-linux-esxi.html"
        /*
                    "https://www.cyfirma.com/news/weekly-intelligence-report-3-october-2025/,
                    "https://www.aha.org/system/files/media/file/2025/10/h-isac-tlp-white-threat-bulletin-new-lockbit-ransomware-emerges-as-most-dangerous-yet-10-1-2025.pdf",
                    "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/lockbit-50",
                    "https://blog.polyswarm.io/lockbit-5.0"
        */
    strings:
        $note_name = "ReadMeForDecrypt.txt" ascii wide    // Ransom note filename
        $defrag    = "defrag.exe" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}