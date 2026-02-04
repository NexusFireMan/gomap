# Implementación de Soporte CIDR

## Resumen de Cambios

Se ha agregado soporte completo para escaneo de rangos CIDR, múltiples IPs y redes, manteniendo la compatibilidad con escaneos de IP única.

## Archivos Modificados

### 1. **cidr.go** (NUEVO - 110 líneas)
Archivo nuevo que maneja toda la lógica de CIDR:

- `ExpandCIDR(cidr string) ([]string, error)`
  - Expande notación CIDR a lista de IPs
  - Soporta IPs individuales con DNS resolution
  - Valida límites de seguridad (máx 65,536 hosts)
  - Excluye direcciones de red y broadcast automáticamente

- `incrementIP(ip net.IP)`
  - Incrementa una dirección IP en 1 (helper)

- `ParseTargets(target string) ([]string, error)`
  - Parsea entrada con múltiples formatos:
    * IP única: `192.168.1.1`
    * CIDR: `192.168.1.0/24`
    * Múltiples (coma-separadas): `192.168.1.1,192.168.1.5`
    * Combinados: `192.168.1.1,192.168.1.0/25,10.0.0.1`

- `FormatCIDRInfo(target string) (string, int, error)`
  - Genera descripción legible de rango
  - Retorna formato "IP1-IP2" para CIDR
  - Retorna conteo de hosts

### 2. **main.go** (MODIFICADO)

**Cambios en usage message:**
```go
// Antes: "Usage: gomap <host> [options]"
// Después: "Usage: gomap <host|CIDR> [options]"

// Nuevos ejemplos:
// - gomap -p 1-1024 -s 192.168.1.0/24
// - gomap -s 192.168.1.1,192.168.1.5,192.168.1.10
```

**Cambios en lógica principal:**
- Usa `ParseTargets()` para expandir entrada
- Valida rango CIDR antes de escanear
- Itera sobre lista de targets
- Agrupa resultados por IP
- Muestra información del rango escaneado
- Soporta múltiples IPs con output separado por "=== IP ==="

**Ejemplo de output para CIDR:**
```
Scanning 192.168.1.1-192.168.1.5 (5 hosts, 22 ports)

=== 192.168.1.1 ===
PORT    STATE  SERVICE
 22     open   ssh

=== 192.168.1.2 ===
(sin puertos abiertos)
```

## Funcionalidades Nuevas

### 1. Escaneo CIDR Directo
```bash
./gomap -s -p 22,80,443 192.168.1.0/24
```

### 2. Múltiples IPs
```bash
./gomap -s -p 445 10.0.11.6,10.0.11.9
```

### 3. Combinación CIDR + IPs
```bash
./gomap -s 192.168.1.1,192.168.1.0/25,10.0.0.0/30
```

### 4. Resolución DNS
```bash
./gomap -s localhost
./gomap -s example.com
```

## Validaciones y Límites

### Validación CIDR
- ✅ Notación CIDR válida (ej: 192.168.1.0/24)
- ✅ Máximo 65,536 hosts por rango (límite de seguridad)
- ❌ Rechaza redes > /16 para evitar expansiones masivas

### Exclusiones Automáticas
- Network address (x.x.x.0) excluida para /30+
- Broadcast address (x.x.x.255) excluida para /30+
- /31 y /32 incluyen todas las direcciones (RFC 3021)

### Errores Útiles
```bash
"CIDR range too large (16777216 hosts). Maximum: 65536 hosts"
"invalid CIDR notation: 192.168.1.0/33"
"invalid IP address or hostname: invalid-host.com"
```

## Estadísticas de Código

```
Antes: 1683 líneas (9 archivos)
Después: 1830 líneas (10 archivos)
Nuevo: 110 líneas (cidr.go)
Modificado: ~40 líneas (main.go)
```

## Comportamiento de Escaneo

### Escaneo Simple (1 IP)
- Comportamiento idéntico a antes
- Output sin encabezado "=== IP ==="
- Velocidad igual: ~5s para 997 puertos

### Escaneo CIDR (N IPs)
- Itera secuencialmente sobre IPs
- Cada IP tiene su propia sección de output
- Velocidad lineal: ~5s * N para 997 puertos cada una
- Ejemplo: /24 = ~30 minutos para 254 hosts

### Escaneo Múltiple (N IPs específicas)
- Mismo comportamiento que CIDR
- Útil para objetivos selectivos
- Ejemplo: 3 IPs = ~15 segundos

## Compatibilidad

- ✅ Backward compatible (IPs individuales funcionan igual)
- ✅ Ghost mode funciona con CIDR (-g flag)
- ✅ Detección de servicios completa (-s flag)
- ✅ Puertos específicos soportados (-p flag)
- ✅ DNS resolution integrada

## Casos de Uso

1. **Auditoría de Subred**
   ```bash
   ./gomap -s -p 22,80,443,445 192.168.1.0/24
   ```

2. **Búsqueda de Puertos Específicos**
   ```bash
   ./gomap -p 445 10.0.0.0/16
   ```

3. **Investigación Selectiva**
   ```bash
   ./gomap -s 192.168.1.1,192.168.1.50,192.168.1.100
   ```

4. **Escaneo Sigiloso de Red**
   ```bash
   ./gomap -g -s -p 1-1024 192.168.1.0/25
   ```

## Testing Validado

✅ IP única: `./gomap -s localhost`
✅ CIDR /31: `./gomap -p 445 10.0.11.6/31`
✅ CIDR /30: `./gomap -s -p 22,80 10.0.11.6/30`
✅ Múltiple IPs: `./gomap -s 10.0.11.6,10.0.11.9`
✅ Compilación limpia: 1830 líneas, sin errores
✅ Help actualizado: nuevos ejemplos visibles

## Documentación

- [CIDR_SUPPORT.md](CIDR_SUPPORT.md) - Guía completa de uso
- [main.go](main.go) - Ejemplos en help message
- [cidr.go](cidr.go) - Implementación técnica

## Conclusión

Se ha implementado soporte completo para:
- ✅ Escaneo de IPs individuales (original)
- ✅ Escaneo de rangos CIDR (nuevo)
- ✅ Escaneo de múltiples IPs específicas (nuevo)
- ✅ Combinaciones de todos los anteriores (nuevo)
- ✅ Resolución DNS para hostnames (nuevo)

Todo manteniendo:
- ✅ Velocidad original (~5s por IP)
- ✅ Detección de servicios precisa
- ✅ Modo ghost stealthy
- ✅ Compatibilidad total hacia atrás
- ✅ Código limpio y sin dependencias externas
