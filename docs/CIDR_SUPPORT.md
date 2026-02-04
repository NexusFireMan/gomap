# Soporte para Escaneo CIDR

## Característica Nueva

Ahora **gomap** soporta escaneo de rangos CIDR, múltiples IPs y redes completas, además de IPs individuales.

## Uso

### Escaneo de IP Individual
```bash
# IP única
./gomap -s 192.168.1.1

# Con resolución de DNS
./gomap -s example.com

# Con puertos específicos
./gomap -s -p 22,80,443 192.168.1.100
```

### Escaneo CIDR (Rango de IPs)
```bash
# Red /24 (256 direcciones, 254 hosts)
./gomap -s -p 22,80,443 192.168.1.0/24

# Red /25 (128 direcciones, 126 hosts)
./gomap -s -p 22 10.0.0.0/25

# Red /30 (4 direcciones, 2 hosts)
./gomap -p 445 10.0.11.6/30

# Red /31 (2 direcciones, 2 hosts) 
./gomap -s -p 22 127.0.0.1/31
```

### Múltiples IPs Específicas
```bash
# Separadas por coma
./gomap -s -p 22,80,445 192.168.1.1,192.168.1.5,192.168.1.10

# Combinación de IPs y CIDR
./gomap -s 192.168.1.1,192.168.1.0/25,10.0.0.1
```

## Limitaciones por Seguridad

- **Máximo 65,536 hosts** (2^16) por rango CIDR
- Esto permite hasta /16 pero previene expansiones de redes muy grandes
- Ejemplo: /16 = 65,536 hosts ✅
- Ejemplo: /15 = 131,072 hosts ❌ (rechazado)

### Mensajes de Error

```bash
# Demasiado grande
./gomap -p 22 192.0.0.0/8
# Error: CIDR range too large (16777216 hosts). Maximum: 65536 hosts

# CIDR inválido
./gomap -p 22 192.168.1.0/33
# Error: invalid CIDR notation
```

## Formato de Salida

### Escaneo Único
```
Scanning 192.168.1.100 (22 ports)

PORT    STATE  SERVICE    VERSION
 22     open   ssh        SSH-2.0 - OpenSSH 7.4
 80     open   http       Apache 2.4.6
443     open   https      
```

### Escaneo CIDR/Múltiple
```
Scanning 192.168.1.1-192.168.1.3 (3 hosts, 22 ports)

=== 192.168.1.1 ===
PORT    STATE  SERVICE    VERSION
 22     open   ssh        SSH-2.0
 80     open   http       Apache

=== 192.168.1.2 ===
(sin puertos abiertos)

=== 192.168.1.3 ===
PORT    STATE  SERVICE    VERSION
443     open   https      Nginx
```

## Implementación Técnica

### Nuevo Archivo: `cidr.go`

**Funciones principales:**

1. **ExpandCIDR(cidr string) []string**
   - Expande notación CIDR a lista de IPs
   - Soporta IPs individuales con DNS resolution
   - Valida límites de tamaño de red

2. **ParseTargets(target string) []string**
   - Parsea entrada (IP, CIDR, o múltiples IPs)
   - Maneja formato separado por comas
   - Retorna lista de todas las IPs a escanear

3. **FormatCIDRInfo(target string) (string, int, error)**
   - Genera descripción legible del rango
   - Retorna "IP1-IP2" para CIDR
   - Retorna IP única para escaneo individual

### Modificaciones a `main.go`

- Uso de `ParseTargets()` en lugar de validación simple de IP
- Loop sobre múltiples targets
- Agrupación de resultados por IP
- Mensajes informativos mejorados para rangos

## Comportamiento por Rango

### /32 (1 host)
```bash
./gomap -s 192.168.1.1
# Sola IP, comportamiento normal
```

### /31 (2 hosts)
```bash
./gomap -s -p 22 192.168.1.0/31
# Expande a: [192.168.1.0, 192.168.1.1]
# Ambas direcciones incluidas (no hay network/broadcast en /31)
```

### /30 (4 direcciones)
```bash
./gomap -s -p 22 192.168.1.0/30
# Expande a: [192.168.1.1, 192.168.1.2]
# Network (x.x.x.0) y broadcast (x.x.x.3) excluidas
```

### /24 y mayores
```bash
./gomap -s -p 22 192.168.1.0/24
# Expande a: [192.168.1.1, ..., 192.168.1.254]
# Red (x.x.x.0) y broadcast (x.x.x.255) excluidas
```

## Rendimiento Esperado

### Escaneo /24 (254 hosts, 22 puertos)
- Modo normal: ~2 minutos (200 workers, 500ms timeout)
- Modo ghost: ~12 minutos (10 workers, 2s timeout)

### Escaneo /25 (126 hosts, 22 puertos)
- Modo normal: ~1 minuto
- Modo ghost: ~6 minutos

### Escaneo Múltiple (3 IPs, 22 puertos)
- Modo normal: ~30 segundos
- Modo ghost: ~3 minutos

## Ejemplos Prácticos

### Auditoría de subred local
```bash
./gomap -s -p 22,80,443,445 192.168.1.0/24
# Escanea 254 hosts en búsqueda de puertos comunes
# Detecta servicios en cada uno
```

### Búsqueda rápida de servidores web
```bash
./gomap -p 80,443 10.0.0.0/16
# Busca puertos HTTP/HTTPS en red /16
# Máximo 65k hosts permitido
```

### Escaneo selectivo
```bash
./gomap -s -p 445 192.168.1.1,192.168.1.5,192.168.1.100
# Solo escanea 3 hosts específicos
# Útil para objetivos conocidos
```

### Modo sigiloso en CIDR
```bash
./gomap -g -s -p 1-1024 192.168.1.0/25
# Ghost mode en red /25
# Más lento pero menos detectable por IDS
```

## Notas de Seguridad

- **No requiere root** para escaneo TCP
- **Respeta límites de red** (no escanea fuera de rango CIDR especificado)
- **Compatible con IDS** (menos ruido en modo normal, muy sigiloso en ghost)
- **Sin ICMP/Ping** por defecto

## Características Futuras Posibles

- [ ] Lectura de targets desde archivo
- [ ] Salida en formato CSV/JSON para reportes
- [ ] Paralelización de escaneos CIDR múltiples
- [ ] Caché de resultados
- [ ] Exportación a herramientas de análisis
