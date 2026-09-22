| Scan     | Paquet envoyé   | Réponse typique           | Interprétation principale |
| -------- | --------------- | ------------------------- | ------------------------- |
| **SYN**  | TCP SYN         | **SYN+ACK**               | `OPEN`                    |
|          |                 | **RST+ACK / RST**         | `CLOSED`                  |
|          |                 | timeout                   | généralement `FILTERED`   |
| **NULL** | TCP sans flags  | **RST**                   | `CLOSED`                  |
|          |                 | aucune réponse            | `OPEN\|FILTERED`          |
| **FIN**  | TCP FIN         | **RST**                   | `CLOSED`                  |
|          |                 | aucune réponse            | `OPEN\|FILTERED`          |
| **XMAS** | FIN + PSH + URG | **RST**                   | `CLOSED`                  |
|          |                 | aucune réponse            | `OPEN\|FILTERED`          |
| **ACK**  | TCP ACK         | **RST**                   | `UNFILTERED`              |
|          |                 | aucune réponse            | `FILTERED`                |
| **UDP**  | UDP             | **ICMP Port Unreachable** | `CLOSED`                  |
|          |                 | réponse UDP               | `OPEN`                    |
|          |                 | aucune réponse            | `OPEN\|FILTERED`          |
list des fonctions 
jfarchic 
result_to_string()

reconstruct_tcp()

reconstruct_udp()

reconstruct_port()

print_port_result()

display_config()

display_results()

get_port_conclusion()

is_port_open()

ksongbe
get_service_name()

checksum()

find_ip()

find_hostname()

find_dns()

getInterfaceReseau()

scanudp()

scantcp()

workers()

scanManager()

print_help()

ip_in_file()

main()