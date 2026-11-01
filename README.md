# Detector de fuerza bruta SSH

Herramienta en Python que analiza un `auth.log` de Linux y detecta accesos
SSH correctos desde direcciones IP que antes acumularon intentos fallidos:
el patrón típico de un ataque de fuerza bruta que tuvo éxito.

## Uso

```
python detection.py auth_practica.log
python detection.py auth_practica.log --umbral 5
```

`--umbral` fija cuántos fallos previos hacen falta para generar una alerta
(por defecto, 10). Un umbral bajo produce más falsos positivos; uno alto,
más falsos negativos.

## Ejemplo

Con el registro de práctica incluido, la herramienta detecta que la cuenta
`backup` accedió desde 203.0.113.45 tras un ataque de fuerza bruta y muestra
su actividad posterior, incluido un `sudo cat /etc/shadow`.

## Datos

`auth_practica.log` es un registro ficticio creado para practicar. Las
direcciones IP pertenecen a rangos reservados para documentación (RFC 5737).

## Limitaciones y mejoras pendientes

- Los fallos se cuentan por IP, no por cuenta atacada.
- No se tiene en cuenta el orden temporal entre fallos y acceso.
- Solo reconoce el formato de `auth.log` de Ubuntu/Debian.