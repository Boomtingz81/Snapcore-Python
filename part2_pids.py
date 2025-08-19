# ------------------------------------------------------------------

#  part2_pids.py  –  clean PID map (drop-in)

# ------------------------------------------------------------------

from __future__ import annotations

from dataclasses import dataclass, field

from part1_core import PidCategory, VehicleType, ProtocolType

@dataclass(slots=True)

class PidDefinition:

    pid: str

    name: str

    units: str

    category: PidCategory

    decode: str

    min: float | None = None

    max: float | None = None

    manufacturers: set[str] = field(default_factory=set)

    protocols: set[ProtocolType] = field(default_factory=set)

    byte_len: int = 2

    refresh_ms: int = 0  # 0 = best effort

# ------------------------------------------------------------------

#  Core PID map (SAE + Tesla + OEM)

# ------------------------------------------------------------------

FULL_PID_MAP: dict[str, PidDefinition] = {

    # Mode 01 – live data

    "010C": PidDefinition(

        pid="010C", name="Engine RPM", units="rpm",

        category=PidCategory.ENGINE,

        decode="(int(h[:4],16)/4)",

        min=0, max=16383.75

    ),

    "010D": PidDefinition(

        pid="010D", name="Vehicle Speed", units="km/h",

        category=PidCategory.CHASSIS,

        decode="int(h[:2],16)",

        min=0, max=255

    ),

    "019A": PidDefinition(

        pid="019A", name="Battery Voltage", units="V",

        category=PidCategory.HYBRID,

        decode="int(h[:8],16)/1000",

        min=0, max=1000,

        manufacturers={"Tesla", "BMW"}, protocols={ProtocolType.ISO15765_CAN}

    ),

    # OEM examples

    "BMW_F800": PidDefinition(

        pid="BMW_F800", name="Battery SOH", units="%",

        category=PidCategory.HYBRID, decode="int(h[:2],16)/2",

        manufacturers={"BMW"}, protocols={ProtocolType.ISO15765_CAN}

    ),

    # … append more PIDs here

}