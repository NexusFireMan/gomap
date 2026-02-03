# 🎨 Colorized Output Examples

## Discovery Phase Output

### Example 1: CIDR Range Scan with Host Discovery

**Terminal Output (with colors):**
```
🔍 Discovering active hosts in 192.168.1.0/24...
✓ Found 12 active hosts, starting port scan...
```

**Color Breakdown:**
- 🔍 Emoji: Discovery indicator
- "Discovering active hosts in" - Blue text (Info color)
- "192.168.1.0/24" - Bright cyan (Highlight color)
- ✓ Emoji: Success indicator
- "Found" - Green (Success color)
- "12" - Bright white (Count color)
- "active hosts, starting port scan..." - Green (Success color)

---

## Scan Results Output

### Example 2: Single Host Results Table

**Terminal Output (with colors):**
```
PORT    STATE SERVICE         VERSION
445     open  microsoft-ds    Windows Server 2008 R2
80      open  http            Apache/2.4.41
22      open  ssh             SSH-2.0-OpenSSH_7.4
3306    open  mysql           MySQL 5.7.14-11-log
```

**Color Breakdown:**
- **Headers** - Bold white
- **Port numbers** (445, 80, 22, 3306) - Bright magenta
- **"open"** state - Green
- **Service names** - Green
- **Versions** - Bright yellow

---

### Example 3: Multi-Host CIDR Results

**Terminal Output (with colors):**
```
═══ 192.168.1.10 ═══
PORT    STATE SERVICE         VERSION
445     open  microsoft-ds    Windows Server 2008 R2
80      open  http            IIS 7.5

═══ 192.168.1.20 ═══
PORT    STATE SERVICE         VERSION
22      open  ssh             SSH-2.0-OpenSSH_7.4
80      open  http            Apache/2.4.41
3306    open  mysql           MySQL 5.7.14-11-log
```

**Color Breakdown:**
- Section separators (═══ ... ═══) - Bright cyan
- IP addresses (192.168.1.10, 192.168.1.20) - Bright blue
- Rest follows standard table coloring

---

## Error and Status Messages

### Error Message Example

**Terminal Output (with colors):**
```
✗ Invalid target specification: 999.999.999.999
```

**Color Breakdown:**
- ✗ Emoji - Red
- "Invalid target specification:" - Red text
- Error details - Red text

---

### Warning Message Example

**Terminal Output (with colors):**
```
⚠ Scanning 192.168.1.0/24 (25 active hosts, 1000 ports) - ⚠ Ghost mode (stealthy)
```

**Color Breakdown:**
- ⚠ Emoji - Yellow
- "Scanning" - Blue (Info)
- "192.168.1.0/24" - Bright cyan (Highlight)
- "25" - Bright white (Count)
- "1000" - Bright white (Count)
- "Ghost mode (stealthy)" - Yellow (Warning)

---

### Success Message Example

**Terminal Output (with colors):**
```
✓ Repository updated
✓ Build successful
✓ gomap has been updated to the latest version
```

**Color Breakdown:**
- ✓ Emoji - Green
- All text - Green (Success)

---

## Update Operation Output

**Terminal Output (with colors):**
```
🔄 Checking for updates...
✓ Detected git repository. Updating via git...
✓ Repository updated
🔨 Rebuilding gomap...
✓ Build successful
✓ gomap has been updated to the latest version
```

**Color Breakdown:**
- 🔄 emoji - Blue info message
- ✓ indicators - Green success
- 🔨 emoji - Blue info message
- "gomap" - Bright white
- Paths/commands - Cyan highlight

---

## Version Information Output

**Terminal Output (with colors):**
```
gomap version 1.0.0
Repository: https://github.com/NexusFireMan/gomap

Update methods:
1. Using git (if cloned from repository):
   gomap -up

2. Using go install (from anywhere):
   go install github.com/NexusFireMan/gomap@latest

3. Manual update:
   git pull origin main && go build
```

**Color Breakdown:**
- "gomap version 1.0.0" - Bright cyan
- Version number - Bright cyan
- "Repository:" - Blue (Info)
- URL - Blue (Info)
- Commands - Bright cyan (Highlight)

---

## Color Palette Reference

### Standard Terminal Colors Used

| Element | Color | ANSI Code | Hex Equivalent |
|---------|-------|-----------|---|
| Ports | Bright Magenta | \033[95m | #FF00FF |
| Services | Green | \033[32m | #00AA00 |
| Versions | Bright Yellow | \033[93m | #FFFF00 |
| State (open) | Green | \033[32m | #00AA00 |
| Hosts | Bright Blue | \033[94m | #0000FF |
| Counts | Bright White | \033[97m | #FFFFFF |
| Info Messages | Blue | \033[34m | #0000AA |
| Success Messages | Green | \033[32m | #00AA00 |
| Error Messages | Red | \033[31m | #AA0000 |
| Warnings | Yellow | \033[33m | #AAAA00 |
| Highlights | Bright Cyan | \033[96m | #00FFFF |
| Headers | Bold White | \033[1m | #FFFFFF |

---

## Emoji Indicators

| Emoji | Meaning | Color | Usage |
|-------|---------|-------|-------|
| 🔍 | Discovering/Searching | Blue | Host discovery messages |
| ✓ | Success | Green | Completed operations |
| ✗ | Error/Failure | Red | Failed operations |
| ⚠ | Warning | Yellow | Ghost mode, cautions |
| 🔄 | Update/Refresh | Blue | Update checking |
| 🔨 | Building/Rebuilding | Blue | Build operations |
| 📦 | Package | Blue | Installation messages |

---

## Terminal Compatibility

### Supported Terminals

```
Linux:
  ✅ xterm
  ✅ GNOME Terminal
  ✅ Konsole (KDE)
  ✅ Terminator
  ✅ Tilix

macOS:
  ✅ Terminal.app
  ✅ iTerm2
  ✅ Hyper

Windows:
  ✅ Windows Terminal
  ✅ Windows 10+ Console
  ✅ Git Bash
  ✅ WSL (Windows Subsystem for Linux)
  ✅ Cygwin

Cross-platform:
  ✅ VS Code Terminal
  ✅ Sublime Terminal
  ✅ JetBrains IDE Terminals
```

---

## Tips for Best Color Experience

1. **Terminal Theme**: Use a terminal theme with good contrast
   - Recommended: Solarized, Nord, Dracula, One Dark Pro

2. **Font**: Use a monospace font for alignment
   - Recommended: Fira Code, JetBrains Mono, Consolas

3. **Terminal Size**: At least 80 columns for optimal table display

4. **Light vs Dark**: Colors work well on both light and dark backgrounds

5. **Font Weight**: Colors appear best with standard (non-bold) font

---

## Color Rendering Test

To verify colors are displaying correctly, look for:

✅ **Port numbers** should stand out in bright magenta
✅ **Service names** should be clearly readable in green
✅ **Versions** should be visible in bright yellow
✅ **Status messages** should use clear color indicators
✅ **Separators** should create visual grouping

If any colors appear incorrect or not visible:
1. Check terminal color scheme settings
2. Try different terminal application
3. Update terminal emulator
4. Verify ANSI color support is enabled

---

## Accessibility Notes

For users with color blindness:
- Color alone is never the only differentiator
- Emoji indicators (✓, ✗, ⚠) provide additional cues
- Text descriptions are always provided
- Separators help organize information visually

**High Contrast:**
- Green on black: Excellent contrast
- Yellow on black: Excellent contrast
- Magenta on black: Good contrast
- Blue on black: Good contrast
- Cyan on black: Excellent contrast

---

## Performance Impact

✅ **Zero Performance Overhead**
- ANSI codes are plain text
- No additional processing required
- No external dependencies
- Colors apply during output only

---

## Examples in Action

### Before Color Enhancement:
```
Scanning 192.168.1.1 (1000 ports)

PORT    STATE SERVICE         VERSION
445     open  microsoft-ds    Microsoft Windows SMB
80      open  http            Apache httpd 2.4.41
22      open  ssh             SSH-2.0-OpenSSH_7.4
3306    open  mysql           MySQL 5.7.14-11-log
```

### After Color Enhancement:
```
🔍 Scanning 192.168.1.1 (1000 ports)

PORT    STATE SERVICE         VERSION
445     open  microsoft-ds    Microsoft Windows SMB
80      open  http            Apache httpd 2.4.41
22      open  ssh             SSH-2.0-OpenSSH_7.4
3306    open  mysql           MySQL 5.7.14-11-log
```

(Note: Colors are applied but not visible in plain text - actual terminal shows full colors)

---

## Summary

🎨 **Gomap now features:**
- ✅ Colorized output for better readability
- ✅ Emoji indicators for quick status recognition
- ✅ Professional terminal styling
- ✅ Full terminal compatibility
- ✅ Zero performance overhead
- ✅ Accessible design
- ✅ High contrast colors
- ✅ Clear visual hierarchy
