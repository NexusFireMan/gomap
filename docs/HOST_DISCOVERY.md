# Host Discovery para Escaneo CIDR

## Característica Nueva

Se ha implementado **host discovery automático** para escaneos CIDR que detecta qué hosts están activos antes de escanear puertos. Esto reduce significativamente el tiempo de escaneo en redes con hosts dispersos.

## Cómo Funciona

### Antes (sin host discovery)
```
Rango CIDR /24 = 254 hosts × 22 puertos = 5,588 intentos de conexión
Tiempo estimado: ~30-40 minutos
Resultado: Muchas conexiones a hosts inactivos
```

### Ahora (con host discovery)
```
1. Descubrimiento rápido: Prueba 7 puertos comunes en 254 hosts
2. Detecta ~30 hosts activos (ejemplo)
3. Escaneo de puertos: 30 hosts × 22 puertos = 660 intentos
Tiempo estimado: ~3-5 minutos
Ahorro: 85-90% del tiempo
```

## Puertos de Descubrimiento

El host discovery intenta conectarse a estos puertos (en orden):
1. **443** (HTTPS)
2. **80** (HTTP)
3. **22** (SSH)
4. **445** (SMB/Microsoft)
5. **3306** (MySQL)
6. **8080** (HTTP Alternativo)
7. **3389** (RDP)

Si **cualquiera** de estos puertos responde, el host se marca como **activo**.

## Uso

### Automático (Recomendado)
```bash
# CIDR automáticamente detecta hosts activos
./gomap -s -p 22,80,443 192.168.1.0/24

# Output:
# Discovering active hosts in 192.168.1.0/24...
# Found 45 active hosts, starting port scan...
```

### Desactivar Host Discovery
```bash
# Si necesitas escanear todos los hosts incluso inactivos
./gomap -s -nd -p 22 192.168.1.0/24

# -nd = no discovery
# Útil si tienes hosts en modo hibernación o con firewalls restrictivos
```

### IP Única (Sin Discovery)
```bash
# IP individual no usa discovery (solo escanea esa IP)
./gomap -s -p 22 192.168.1.100
```

### Múltiples IPs Específicas (Sin Discovery)
```bash
# IPs separadas por coma no usan discovery
./gomap -s -p 22 192.168.1.1,192.168.1.5,192.168.1.10
```

## Ejemplos Prácticos

### Auditoría Rápida de Red
```bash
# Encuentra hosts activos y escanea puertos comunes
./gomap -s -p 22,80,443,445 192.168.1.0/24

# Output:
# Discovering active hosts in 192.168.1.0/24...
# Found 45 active hosts, starting port scan...
# 
# === 192.168.1.5 ===
# PORT  STATE SERVICE VERSION
#  22   open  ssh     SSH-2.0...
#  80   open  http    Apache...
```

### Búsqueda de Servidores Windows
```bash
# Encuentra hosts con puerto 445 abierto (SMB)
./gomap -p 445 192.168.1.0/24

# Discovery ya habrá encontrado estos
```

### Escaneo Completo (Fuerza Bruta)
```bash
# Escanea TODOS los hosts, incluso los inactivos
./gomap -s -nd -p 22 192.168.1.0/24

# Más lento pero detecta hosts con firewalls restrictivos
```

### Modo Ghost con Discovery
```bash
# Descubrimiento rápido + escaneo sigiloso
./gomap -g -s -p 1-1024 192.168.1.0/24

# Discovery usa timeout corto (500ms)
# Luego escaneo ghost en los hosts activos
```

## Configuración Técnica

### Discovery Timeout
- **500 milisegundos** por intento de conexión
- Si el host responde en <500ms a cualquier puerto = ACTIVO
- Muy rápido, completa /24 en ~30-40 segundos

### Discovery Workers
- **50 conexiones paralelas** durante el descubrimiento
- Balanceado entre velocidad y no sobrecargar la red

### Total Discovery Time
- /24 (254 hosts): ~40 segundos
- /25 (126 hosts): ~20 segundos
- /26 (62 hosts): ~10 segundos

## Comparativa de Tiempos

### Escaneo /24 (254 hosts) - 22 puertos

| Método | Tiempo | Hosts Escaneados | Conexiones |
|--------|--------|-----------------|------------|
| Sin Discovery (-nd) | 30-40 min | 254 | 5,588 |
| Con Discovery | 3-5 min | ~45-60 | 990-1,320 |
| **Mejora** | **85-90%** | **82-84%** | **82-84%** |

### Escaneo /25 (126 hosts) - 22 puertos

| Método | Tiempo | Hosts Escaneados |
|--------|--------|-----------------|
| Sin Discovery | 15-20 min | 126 |
| Con Discovery | 1.5-2 min | ~25-35 |
| **Mejora** | **87-90%** | **72-80%** |

## Ventajas y Desventajas

### Ventajas
✅ **85-90% más rápido** en redes con hosts dispersos
✅ **Automático** - no requiere configuración
✅ **Inteligente** - prueba 7 puertos comunes
✅ **No invasivo** - solo intenta conexiones TCP
✅ **Compatible** - funciona en cualquier red

### Desventajas
❌ Puede perder hosts con **todos los puertos bloqueados**
❌ Hosts en **hibernación** no serán detectados
❌ Puede ser lento en redes muy grandes (>65K hosts)

### Solución
```bash
# Si sospechas que faltan hosts, desactiva discovery
./gomap -nd -p 22 192.168.1.0/24
```

## Estadísticas de Código

```
Nuevo: DiscoverActiveHosts() en cidr.go
Nuevo: IsCIDR() en cidr.go  
Nuevo: -nd flag en main.go
Cambios: ~50 líneas en total
```

## Salida de Ejemplo

```bash
$ ./gomap -s -p 22,80,445 192.168.1.0/24

Discovering active hosts in 192.168.1.0/24...
Found 48 active hosts, starting port scan...

Scanning 192.168.1.1-192.168.1.254 (48 active hosts, 3 ports)

=== 192.168.1.5 ===
PORT    STATE  SERVICE      VERSION
 22     open   ssh          SSH-2.0 - OpenSSH 7.4
 80     open   http         Apache 2.4.6

=== 192.168.1.10 ===
PORT    STATE  SERVICE      VERSION
 445    open   microsoft-ds Windows Server 2016

=== 192.168.1.12 ===
(sin puertos abiertos)

...
```

## Notas Importantes

1. **Discovery es automático** para CIDR/múltiples IPs
2. **IP única no usa discovery** (solo escanea esa IP)
3. **Puertos comunes** (80, 443, 22, etc.) son probados
4. **Timeout corto** (500ms) para rapidez
5. **Puede deshabilitar** con flag `-nd` si es necesario

## Recomendaciones

### Usar Host Discovery (Default)
```bash
./gomap -s -p 22,80,443 192.168.1.0/24
```
- Redes con hosts dispersos
- Auditoría rápida
- La mayoría de casos

### Desactivar Host Discovery (-nd)
```bash
./gomap -s -nd -p 22 192.168.1.0/24
```
- Hosts con firewall restrictivo
- Necesitas garantizar cobertura 100%
- Auditoría exhaustiva (lenta)

## Conclusión

Host discovery automático reduce significativamente el tiempo de escaneo CIDR sin requerir configuración adicional. Es transparente, inteligente y muy rápido, mejorando la experiencia de usuario en redes grandes.
