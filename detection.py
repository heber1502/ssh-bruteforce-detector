from collections import Counter


def leer_registro(ruta):
    """Lee un auth.log y devuelve los fallos por IP y la lista de accesos correctos."""
    fallos = Counter()
    accesos = []
    with open(ruta, encoding="utf-8") as archivo:
        for linea in archivo:
            palabras = linea.split()
            if "Failed password" in linea:
                ip = palabras[palabras.index("from") + 1]
                fallos[ip] += 1
            elif "Accepted password" in linea:
                ip = palabras[palabras.index("from") + 1]
                usuario = palabras[palabras.index("for") + 1]
                hora = " ".join(palabras[0:3])
                accesos.append((hora, ip, usuario))
    return fallos, accesos


def detectar(fallos, accesos, umbral):
    """Devuelve los accesos correctos desde IP con al menos 'umbral' fallos previos."""
    alertas = []
    for hora, ip, usuario in accesos:
        if fallos[ip] >= umbral:
            alertas.append((hora, ip, usuario, fallos[ip]))
    return alertas


def actividad(ruta, usuario):
    """Devuelve todas las líneas del registro que mencionan a un usuario."""
    lineas = []
    with open(ruta, encoding="utf-8") as archivo:
        for linea in archivo:
            if usuario in linea:
                lineas.append(linea.strip())
    return lineas


# Programa principal
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Detecta accesos SSH correctos tras ataques de fuerza bruta en un auth.log."
    )
    parser.add_argument("archivo", help="ruta del auth.log a analizar")
    parser.add_argument("--umbral", type=int, default=10,
                        help="fallos mínimos previos para generar una alerta (por defecto: 10)")
    args = parser.parse_args()

    fallos, accesos = leer_registro(args.archivo)
    alertas = detectar(fallos, accesos, args.umbral)

    if not alertas:
        print("Sin alertas.")
    for hora, ip, usuario, n in alertas:
        print(f"[ALERTA] {hora}  {usuario} entró desde {ip} tras {n} fallos")
        for linea in actividad(args.archivo, usuario):
            print("    ", linea)