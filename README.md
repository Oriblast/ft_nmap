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
