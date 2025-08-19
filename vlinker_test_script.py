```python
import obd
import time

# Connect to VLINK MS (auto-detects port/baudrate)
connection = obd.OBD() 

# Test these PIDs (Mode 01 - Standard + Extended + OEM)
TEST_PIDS = {
    # Standard OBD2
    "rpm": "010C",
    "speed": "010D",
    "coolant_temp": "0105",
    "throttle": "0111",
    
    # Extended SAE
    "oil_temp": "015C",
    "fuel_rate": "015E",
    "boost_pressure": "0133", # Some turbo cars
    
    # OEM (GM example)
    "gm_boost_actual": "221100", # Needs CAN header
    "vw_boost_request": "22314C", # VW/Audi
}

def test_pid(pid_name, pid_code):
    try:
        print(f"Testing {pid_name} ({pid_code})...", end=" ", flush=True)
        
        # For OEM PIDs, set CAN header (if needed)
        if pid_code.startswith("22") or pid_code.startswith("23"):
            connection.send(obd.commands["AT_SH_7E0"]) # GM/VW header
            
        cmd = obd.commands[pid_code] if pid_code in obd.commands else None
        if not cmd:
            cmd = obd.commands.OBDCommand(pid_name, pid_name, pid_code, decoder=obd.decoders.noop)
        
        response = connection.query(cmd, force=True)
        
        if response.is_null():
            print("❌ Not supported")
        else:
            print(f"✅ Works! → {response.value} {response.unit}")
            
    except Exception as e:
        print(f"⚠️ Error: {str(e)}")
    time.sleep(0.5) # Avoid flooding the bus

# Run tests
print("\n=== VLINK MS PID Compatibility Test ===")
for name, pid in TEST_PIDS.items():
    test_pid(name, pid)

connection.close()
print("Test complete!")
```

### **How to Use This Script:**
1. **Install requirements**:
   ```bash
   pip install obd
   ```
2. **Plug in your VLINK MS** (ensure drivers are installed).
3. **Run the script** - It will test each PID and show:
   - `✅ Works!` + live data (if supported)
   - `❌ Not supported` (if ECU ignores it)
   - `⚠️ Error` (if communication fails)

### **Expected Output Examples:**
```
=== VLINK MS PID Compatibility Test ===
Testing rpm (010C)... ✅ Works! → 752.5 rpm
Testing speed (010D)... ✅ Works! → 32 km/h
Testing oil_temp (015C)... ❌ Not supported  
Testing gm_boost_actual (221100)... ⚠️ Error: No response (try CAN header)
```

### **What to Do Next?**
- If OEM PIDs fail, try **different CAN headers** (`AT SH 7E0`, `AT SH 7E1`).
- For unsupported PIDs, check your car's **service manual** for the correct codes.
- Want to test **more PIDs**? Just add them to `TEST_PIDS`!

This script is **completely safe**—it only reads data and handles errors gracefully. Let me know if you'd like to expand it! 🛠️
