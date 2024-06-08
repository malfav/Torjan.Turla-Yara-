import "pe"
import "console"
import "hash"
import "math"

 rule Turla_Malware{

	meta:
		Author = "Diyar Saadi"
	condition:
		pe.export_timestamp == 1359984004 and
		pe.number_of_exports > 30 and
		pe.dll_name icontains "inj_snake_Win32.dll" and
		console.log("Main DLL Name : ", pe.dll_name) and
		console.log("Entry Point : ", pe.entry_point) and
		console.log("Entropy : ", math.entropy(0, filesize))	
		}

rule Turla_Export_Low{
	meta:
	Hash = "d597e4a61d94180044dfb616701e5e539f27eeecfae827fb024c114e30c54914"
	Mal_Name = "Trula Trojan"
	condition:
		console.log("SHA-256 => ", hash.sha256(0,filesize)) and
		pe.number_of_exports != 0 
		and 
		for 4 export_names in pe.export_details: 
		(
			export_names.name == "snake_"
		)
		and
		for 50 unknown_exportt in pe.export_details :
		(
			unknown_exportt.name matches /^[a-z]{2}_/
		)
} 
rule is_turla_family{
	condition:
		not Turla_Malware
}

rule TTP_Export_Unsigend_timestamp_export_timestap {
	condition:
		pe.number_of_exports > 60 
		and
		pe.number_of_signatures == 0  and
		pe.timestamp != pe.export_timestamp 
		and
		filesize < 1MB
}


