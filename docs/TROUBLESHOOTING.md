# Troubleshooting Guide

## Common Issues

### "ghidra-bridge connection refused"

**Cause:** Ghidra is not running or the bridge server is not started.

**Solution:**
1. Start Ghidra: `arael-start-ghidra` or `./scripts/start-ghidra-bridge.sh`
2. Verify the bridge is running on port 4768:
   ```bash
   # Linux/Mac
   lsof -i :4768
   # Windows
   netstat -an | findstr 4768
   ```

If you don't need bridge mode, Arael will automatically fall back to headless mode.

---

### "GHIDRA_PATH not set"

**Cause:** The GHIDRA_PATH environment variable is not configured.

**Solution:**
```bash
# Set temporarily
export GHIDRA_PATH=/path/to/ghidra_11.0_PUBLIC

# Set permanently (add to ~/.bashrc or ~/.zshrc)
echo 'export GHIDRA_PATH=/path/to/ghidra_11.0_PUBLIC' >> ~/.bashrc
source ~/.bashrc
```

**WSL (snap) example:**
```bash
export GHIDRA_PATH=/snap/ghidra/current/ghidra_11.4_PUBLIC
```

---

### "Java not found"

**Cause:** Java is not installed or not in PATH.

**Solution:**
1. Install Java 17+:
   ```bash
   # Ubuntu/Debian
   sudo apt install openjdk-17-jdk

   # macOS with Homebrew
   brew install openjdk@17

   # Windows: Download from https://adoptium.net/
   ```
2. Verify installation:
   ```bash
   java -version
   ```

---

### "analyzeHeadless failed"

**Cause:** Various Ghidra issues.

**Possible solutions:**

1. **Check Ghidra installation:**
   ```bash
   ls $GHIDRA_PATH/support/analyzeHeadless
   ```

   If you pointed `GHIDRA_PATH` at a source tree (e.g. `ghidra-master`), headless will fail.
   Use a built release or the snap path instead.

2. **Increase Java memory:**
   ```bash
   export _JAVA_OPTIONS="-Xmx8g"
   ```

3. **Check Ghidra logs:**
   ```bash
   cat /tmp/arael_projects/*.log
   ```

4. **Try running analyzeHeadless directly:**
   ```bash
   $GHIDRA_PATH/support/analyzeHeadless /tmp test -import /bin/ls
   ```

---

### "Permission denied"

**Cause:** File access issues.

**Solution:**
1. Check file permissions:
   ```bash
   ls -la /path/to/binary
   ```
2. Ensure Arael has access to:
   - Target binary (read)
   - `~/.arael/` directory (read/write)
   - `/tmp/arael_*` (read/write)

---

### "Not an ELF binary"

**Cause:** Arael v1.0 only supports ELF binaries.

**Workaround:**
- For PE (Windows) binaries: Wait for v1.1 or use Ghidra directly
- For Mach-O (macOS) binaries: Wait for v1.1 or use Ghidra directly

---

### "ghidra-bridge not installed"

**Cause:** The Python ghidra-bridge package is not installed.

**Solution:**
```bash
pip install ghidra-bridge
# Or
pip3 install ghidra-bridge
```

If using a virtual environment, ensure it's activated.

---

### Slow Analysis

**Cause:** First-time analysis is slow due to Ghidra's auto-analysis.

**Solutions:**
1. **Use bridge mode** - Start Ghidra with bridge server for ~100ms queries
2. **Caching** - Subsequent queries use cache (instant)
3. **Reduce binary size** - Strip debug symbols if not needed

**Expected times:**
| Binary Size | Bridge Mode | Headless Mode |
|-------------|-------------|---------------|
| <1MB | 5-15s | 15-30s |
| 1-10MB | 15-60s | 30-120s |
| >10MB | 60-180s | 120-300s |

---

### Cache Issues

**Clear the cache:**
```bash
arael cache --clear
```

**View cache stats:**
```bash
arael cache --stats
```

**Cache location:** `~/.arael/cache/analysis.db`

---

## Getting Help

1. Run `arael-check` to diagnose issues
2. Check logs in `/tmp/arael_*`
3. Open an issue on GitHub with:
   - Output of `arael-check`
   - Error message
   - Operating system
   - Ghidra version

## Debug Mode

Enable verbose logging:
```bash
DEBUG=arael:* arael analyze ./binary
```
