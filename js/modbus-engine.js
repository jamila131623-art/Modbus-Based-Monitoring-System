// State Manager
const state = {
  isPolling: false,
  pollingSpeed: 1500, // ms
  nextTransactionId: 100,
  autoAnomaly: false,
  alarmCount: 0,
  activeAttack: null, // Attack waiting to be injected
  selectedPacket: null,
  
  // Node details
  master: {
    x: 80,
    y: 180,
    ip: "10.0.0.10",
    state: "OK",
    pulseTimer: 0
  },
  attacker: {
    x: 80,
    y: 300,
    ip: "192.168.1.99",
    state: "INACTIVE", // INACTIVE, ACTIVE
    pulseTimer: 0,
    visible: false,
    visibilityAlpha: 0.0,
    visibleUntil: 0
  },
  quarantinedNodes: {}, // ip: true
  switchNode: {
    x: 320,
    y: 200,
    activePorts: [false, false, false, false],
    pulseTimer: 0
  },
  slaves: {
    1: {
      id: 1,
      name: "Safety PLC",
      ip: "10.0.0.11",
      x: 580,
      y: 80,
      state: "OK", // OK, BUSY, ALARM
      pulseTimer: 0,
      flashRegisters: {}, // regIndex: 'read'/'write'
      alertMsg: "",
      alertExpiry: 0,
      shakeTimer: 0,
      queueFullIndicator: false,
      registers: {
        40001: { name: "Sys Status", val: 1, baseline: { min: 0, max: 1, label: "0-1" } },
        40002: { name: "Safety Rly", val: 1, baseline: { min: 1, max: 1, label: "1 (OK)" } },
        40003: { name: "E-Stop Loop", val: 1, baseline: { min: 1, max: 1, label: "1 (Armed)" } },
        40004: { name: "Intlk Bypass", val: 1, baseline: { min: 1, max: 1, label: "1 (Safe)" } }, // 0=Bypassed (Out of range!)
        40005: { name: "Flame Sens", val: 0, baseline: { min: 0, max: 0, label: "0 (Norm)" } },
        40006: { name: "Gas Sens", val: 0, baseline: { min: 0, max: 0, label: "0 (Norm)" } },
        40007: { name: "Vent Valve", val: 0, baseline: { min: 0, max: 1, label: "0-1" } },
        40008: { name: "ESD Tripped", val: 0, baseline: { min: 0, max: 0, label: "0 (Safe)" } }
      }
    },
    2: {
      id: 2,
      name: "Motor VFD",
      ip: "10.0.0.12",
      x: 580,
      y: 200,
      state: "OK",
      pulseTimer: 0,
      flashRegisters: {},
      alertMsg: "",
      alertExpiry: 0,
      shakeTimer: 0,
      queueFullIndicator: false,
      registers: {
        40001: { name: "Motor State", val: 1, baseline: { min: 0, max: 1, label: "0-1" } },
        40002: { name: "Motor RPM", val: 1485, baseline: { min: 1400, max: 1600, label: "1400-1600" } }, // Target 1500, >1600 out of range!
        40003: { name: "Current A", val: 145, baseline: { min: 100, max: 180, label: "100-180" } },
        40004: { name: "Torque Nm", val: 218, baseline: { min: 190, max: 245, label: "190-245" } },
        40005: { name: "VFD Temp C", val: 42, baseline: { min: 30, max: 55, label: "30-55°C" } },
        40006: { name: "Brg Temp C", val: 38, baseline: { min: 25, max: 50, label: "25-50°C" } },
        40007: { name: "Vibe mm/s", val: 12, baseline: { min: 5, max: 25, label: "5-25" } },
        40008: { name: "Fan Speed", val: 80, baseline: { min: 50, max: 100, label: "50-100%" } }
      }
    },
    3: {
      id: 3,
      name: "Tank Level",
      ip: "10.0.0.13",
      x: 580,
      y: 320,
      state: "OK",
      pulseTimer: 0,
      flashRegisters: {},
      alertMsg: "",
      alertExpiry: 0,
      shakeTimer: 0,
      queueFullIndicator: false,
      registers: {
        40001: { name: "Lvl Liters", val: 2450, baseline: { min: 1000, max: 4200, label: "1000-4200" } },
        40002: { name: "Inlet Pump", val: 1, baseline: { min: 0, max: 1, label: "0-1" } },
        40003: { name: "Outlet Vlv", val: 0, baseline: { min: 0, max: 1, label: "0-1" } },
        40004: { name: "Water Temp", val: 24, baseline: { min: 15, max: 30, label: "15-30°C" } },
        40005: { name: "HiLvl Alarm", val: 0, baseline: { min: 0, max: 0, label: "0 (OK)" } },
        40006: { name: "LoLvl Alarm", val: 0, baseline: { min: 0, max: 0, label: "0 (OK)" } },
        40007: { name: "FlowIn L/m", val: 120, baseline: { min: 0, max: 150, label: "0-150" } },
        40008: { name: "FlowOut L/m", val: 0, baseline: { min: 0, max: 180, label: "0-180" } }
      }
    }
  },
  packets: [],
  logs: [],
  currentPollTarget: 1
};

// Helper functions for HEX conversion
function toHex8(v) {
  return v.toString(16).toUpperCase().padStart(2, '0');
}

function toHex16(v) {
  const h = v.toString(16).toUpperCase().padStart(4, '0');
  return [h.slice(0, 2), h.slice(2, 4)];
}

function getFcName(fc) {
  if (fc === 3) return "Read Holding Registers";
  if (fc === 6) return "Write Single Register";
  if (fc === 16) return "Write Multiple Registers";
  return "Illegal Function Code";
}

let fsmResetTimer = null;

// Dynamic FSM Strip visual updates with full violation detection support
function updateFsm(step, alertText = "", isViolation = false) {
  const steps = ['idle', 'sent', 'await', 'done'];
  const statusTag = document.getElementById('fsm-status-tag');
  
  if (isViolation) {
    if (fsmResetTimer) clearTimeout(fsmResetTimer);
    
    steps.forEach(s => {
      const el = document.getElementById(`fsm-step-${s}`);
      if (el) {
        if (s === step || (step === 'violation' && (s === 'done' || s === 'sent'))) {
          el.className = "px-2 py-1 rounded border-2 border-rose-500 bg-rose-950 text-rose-300 font-bold animate-pulse shadow-[0_0_12px_rgba(244,63,94,0.6)]";
        } else {
          el.className = "px-2 py-1 rounded border border-slate-800 bg-slate-900/40 text-slate-600";
        }
      }
    });

    if (statusTag) {
      statusTag.className = "text-[9px] font-mono text-rose-400 font-bold animate-pulse";
      statusTag.innerText = "⚠ SEQUENCE VIOLATION";
    }

    const alertEl = document.getElementById('fsm-alert');
    if (alertEl) {
      alertEl.innerHTML = `
        <div class="flex items-center gap-1.5 font-bold text-rose-300">
          <span class="inline-block w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
          <span>⚠ Invalid transition detected:</span>
        </div>
        <div class="text-rose-400 mt-0.5 text-[9px]">${alertText || "Unexpected state transition outside of verified request/response sequence."}</div>
      `;
      alertEl.classList.remove('hidden');
    }

    // Auto reset to normal IDLE state after 4.5 seconds
    fsmResetTimer = setTimeout(() => {
      updateFsm('idle');
    }, 4500);
    return;
  }

  // Normal request/response cycle progression
  steps.forEach(s => {
    const el = document.getElementById(`fsm-step-${s}`);
    if (el) {
      if (s === step) {
        el.className = "px-2 py-1 rounded border border-cyan-400 bg-cyan-950 text-cyan-400 font-bold shadow-[0_0_8px_rgba(6,182,212,0.4)]";
      } else {
        el.className = "px-2 py-1 rounded border border-slate-800 bg-slate-900/60 text-slate-500";
      }
    }
  });

  if (statusTag) {
    statusTag.className = "text-[9px] font-mono text-cyan-500";
    statusTag.innerText = "Live Transaction Audit";
  }

  const alertEl = document.getElementById('fsm-alert');
  if (alertEl) {
    if (alertText) {
      alertEl.innerText = alertText;
      alertEl.classList.remove('hidden');
    } else {
      alertEl.classList.add('hidden');
    }
  }
}

// Frame Generator helper matching Modbus TCP specs
function createModbusFrame(params) {
  const { txId, unitId, fc, addr, val, qty, writeValues, customSrcIp, isAnomaly, anomalyText } = params;
  
  const frame = {
    txId,
    protocolId: 0,
    unitId,
    fc,
    isAnomaly: !!isAnomaly,
    anomalyText: anomalyText || "",
    srcIp: customSrcIp || "10.0.0.10",
    destIp: state.slaves[unitId] ? state.slaves[unitId].ip : `10.0.0.10${unitId}`,
    rawBytes: [],
    bytesDef: [] // Mapping metadata for byte cells
  };

  const txBytes = toHex16(txId);
  const prBytes = [ '00', '00' ];
  
  let pduBytes = [ toHex8(fc) ];
  let pduDefs = [
    { name: "Function Code", desc: `Specifies Modbus operation: 0x${toHex8(fc)}`, val: `FC ${fc}` }
  ];

  // Build PDU based on Function Code
  if (fc === 3) {
    // Read Holding Registers
    const rAddr = addr - 40001;
    const addrBytes = toHex16(rAddr);
    const qtyBytes = toHex16(qty);
    
    pduBytes.push(...addrBytes, ...qtyBytes);
    pduDefs.push(
      { name: "Starting Address (High)", desc: "Starting address offset high byte", val: `0x${addrBytes[0]}` },
      { name: "Starting Address (Low)", desc: `Starting address offset: 0x${addrBytes[0]}${addrBytes[1]} (Reg 4000${rAddr + 1})`, val: `Offset ${rAddr}` },
      { name: "Quantity of Registers (High)", desc: "Number of registers to read high byte", val: `0x${qtyBytes[0]}` },
      { name: "Quantity of Registers (Low)", desc: `Number of registers to read: ${qty}`, val: qty.toString() }
    );
  } else if (fc === 6) {
    // Write Single Register
    const wAddr = addr - 40001;
    const addrBytes = toHex16(wAddr);
    const valBytes = toHex16(val);
    
    pduBytes.push(...addrBytes, ...valBytes);
    pduDefs.push(
      { name: "Register Address (High)", desc: "Target register offset high byte", val: `0x${addrBytes[0]}` },
      { name: "Register Address (Low)", desc: `Target register offset: 0x${addrBytes[0]}${addrBytes[1]} (Reg 4000${wAddr + 1})`, val: `Offset ${wAddr}` },
      { name: "Register Value (High)", desc: "Value to write high byte", val: `0x${valBytes[0]}` },
      { name: "Register Value (Low)", desc: `Value to write: ${val}`, val: val.toString() }
    );
  } else if (fc === 16) {
    // Write Multiple Registers (FC 0x10)
    const wAddr = addr - 40001;
    const addrBytes = toHex16(wAddr);
    const qtyVal = writeValues.length;
    const qtyBytes = toHex16(qtyVal);
    const byteCount = qtyVal * 2;
    
    pduBytes.push(...addrBytes, ...qtyBytes, toHex8(byteCount));
    pduDefs.push(
      { name: "Starting Address (High)", desc: "Starting address high byte", val: `0x${addrBytes[0]}` },
      { name: "Starting Address (Low)", desc: `Starting address: 0x${addrBytes[0]}${addrBytes[1]} (Reg 4000${wAddr + 1})`, val: `Offset ${wAddr}` },
      { name: "Quantity of Registers (High)", desc: "Quantity to write high byte", val: `0x${qtyBytes[0]}` },
      { name: "Quantity of Registers (Low)", desc: `Quantity to write: ${qtyVal}`, val: qtyVal.toString() },
      { name: "Byte Count", desc: `PDU data byte count: ${byteCount} bytes`, val: `${byteCount} Bytes` }
    );
    
    writeValues.forEach((v, idx) => {
      const vBytes = toHex16(v);
      pduBytes.push(...vBytes);
      pduDefs.push(
        { name: `Reg ${addr + idx} Val (High)`, desc: `High byte of write value to Reg ${addr + idx}`, val: `0x${vBytes[0]}` },
        { name: `Reg ${addr + idx} Val (Low)`, desc: `Write value to Reg ${addr + idx}: ${v}`, val: v.toString() }
      );
    });
  } else {
    // Unknown/Unsupported FC (For anomalies)
    pduBytes.push('00', '00', '00', '00');
    pduDefs.push(
      { name: "Payload (Raw)", desc: "Unsupported or non-baseline command field", val: "0x00" },
      { name: "Payload (Raw)", desc: "Unsupported or non-baseline command field", val: "0x00" },
      { name: "Payload (Raw)", desc: "Unsupported or non-baseline command field", val: "0x00" },
      { name: "Payload (Raw)", desc: "Unsupported or non-baseline command field", val: "0x00" }
    );
  }

  // MBAP Header construction
  const mbapLength = pduBytes.length + 1; // unitId (1B) + PDU
  const lenBytes = toHex16(mbapLength);
  const unitBytes = toHex8(unitId);

  frame.rawBytes = [
    ...txBytes, 
    ...prBytes, 
    ...lenBytes, 
    unitBytes, 
    ...pduBytes
  ];

  frame.bytesDef = [
    { name: "Transaction Identifier (High)", desc: "Transaction ID high byte", val: `0x${txBytes[0]}`, colorClass: "bg-violet-500/80 hover:bg-violet-400" },
    { name: "Transaction Identifier (Low)", desc: `Unique identifier: ${txId}`, val: txId.toString(), colorClass: "bg-violet-500/80 hover:bg-violet-400" },
    { name: "Protocol Identifier (High)", desc: "Protocol ID high byte (Always 0)", val: `0x00`, colorClass: "bg-slate-500/80 hover:bg-slate-400" },
    { name: "Protocol Identifier (Low)", desc: "Protocol ID (0 = Modbus TCP)", val: `0x00`, colorClass: "bg-slate-500/80 hover:bg-slate-400" },
    { name: "Length Field (High)", desc: "Length field high byte", val: `0x${lenBytes[0]}`, colorClass: "bg-blue-500/80 hover:bg-blue-400" },
    { name: "Length Field (Low)", desc: `Total bytes following: ${mbapLength}`, val: mbapLength.toString(), colorClass: "bg-blue-500/80 hover:bg-blue-400" },
    { name: "Unit Identifier", desc: `Target device Modbus slave address: ID ${unitId}`, val: `Slave ID ${unitId}`, colorClass: "bg-teal-500/80 hover:bg-teal-400" }
  ];

  // Add PDU mappings to frame description
  const dataColor = isAnomaly ? "bg-red-500/80 hover:bg-red-400" : "bg-emerald-500/80 hover:bg-emerald-400";
  pduDefs.forEach((def, index) => {
    frame.bytesDef.push({
      name: def.name,
      desc: def.desc,
      val: def.val,
      colorClass: index === 0 ? "bg-amber-500/80 hover:bg-amber-400" : dataColor
    });
  });

  return frame;
}

function createResponseFrame(request, isException, exceptionCode) {
  const slave = state.slaves[request.unitId];
  const frame = {
    txId: request.txId,
    protocolId: 0,
    unitId: request.unitId,
    fc: request.fc,
    isAnomaly: request.isAnomaly,
    srcIp: slave.ip,
    destIp: request.srcIp,
    rawBytes: [],
    bytesDef: []
  };

  const txBytes = toHex16(request.txId);
  const prBytes = [ '00', '00' ];
  
  let pduBytes = [];
  let pduDefs = [];

  if (isException) {
    // Modbus Exception Frame
    const exceptionFc = request.fc | 0x80;
    pduBytes.push(toHex8(exceptionFc), toHex8(exceptionCode));
    
    let excName = "Unknown Error";
    if (exceptionCode === 1) excName = "Illegal Function Code";
    if (exceptionCode === 2) excName = "Illegal Data Address";
    if (exceptionCode === 3) excName = "Illegal Data Value";

    pduDefs.push(
      { name: "Exception Function Code", desc: `Error bit set. Original FC + 0x80: 0x${toHex8(exceptionFc)}`, val: `FC ${request.fc} Error` },
      { name: "Exception Exception Code", desc: `Modbus exception code: 0x${toHex8(exceptionCode)} (${excName})`, val: excName }
    );
  } else {
    // Normal Response
    if (request.fc === 3) {
      // Read registers response
      const count = request.rawBytes[request.rawBytes.length - 1]; // Parse qty from request
      const byteCount = parseInt(count, 16) * 2;
      pduBytes.push(toHex8(3), toHex8(byteCount));
      
      pduDefs.push(
        { name: "Function Code", desc: "Read Holding Registers (0x03) response", val: "FC 03" },
        { name: "Byte Count", desc: `Register data block size: ${byteCount} bytes`, val: `${byteCount} Bytes` }
      );

      // Get values from slave registers starting at address
      const startOffset = parseInt(request.rawBytes[8] + request.rawBytes[9], 16);
      const startReg = 40001 + startOffset;
      
      for (let i = 0; i < parseInt(count, 16); i++) {
        const curReg = startReg + i;
        const regVal = slave.registers[curReg] ? slave.registers[curReg].val : 0;
        const valBytes = toHex16(regVal);
        
        pduBytes.push(...valBytes);
        pduDefs.push(
          { name: `Reg ${curReg} Val (High)`, desc: `High byte of Reg ${curReg} value`, val: `0x${valBytes[0]}` },
          { name: `Reg ${curReg} Val (Low)`, desc: `Register ${curReg} value: ${regVal}`, val: regVal.toString() }
        );
      }
    } else if (request.fc === 6 || request.fc === 16) {
      // Write Single/Multiple echoes back portion of request
      const fcByte = toHex8(request.fc);
      const addrBytes = [ request.rawBytes[8], request.rawBytes[9] ];
      const valOrQtyBytes = [ request.rawBytes[10], request.rawBytes[11] ];
      
      pduBytes.push(fcByte, ...addrBytes, ...valOrQtyBytes);
      pduDefs.push(
        { name: "Function Code", desc: `Write operation (0x${fcByte}) confirmation`, val: `FC ${request.fc}` },
        { name: "Address (High)", desc: "Register offset high byte", val: `0x${addrBytes[0]}` },
        { name: "Address (Low)", desc: `Offset: 0x${addrBytes[0]}${addrBytes[1]}`, val: `Offset ${parseInt(addrBytes[0]+addrBytes[1], 16)}` },
        { name: "Data (High)", desc: "Value/Quantity high byte", val: `0x${valOrQtyBytes[0]}` },
        { name: "Data (Low)", desc: "Value/Quantity written", val: `${parseInt(valOrQtyBytes[0]+valOrQtyBytes[1], 16)}` }
      );
    } else {
      // Generic Echo for anomaly custom types
      pduBytes.push(toHex8(request.fc), '00', '00');
      pduDefs.push(
        { name: "Function Code", desc: "Non-standard custom function echo", val: `FC ${request.fc}` },
        { name: "Data", desc: "Empty payload response", val: "0" },
        { name: "Data", desc: "Empty payload response", val: "0" }
      );
    }
  }

  const mbapLength = pduBytes.length + 1; // unitId (1B) + PDU
  const lenBytes = toHex16(mbapLength);
  const unitBytes = toHex8(request.unitId);

  frame.rawBytes = [
    ...txBytes, 
    ...prBytes, 
    ...lenBytes, 
    unitBytes, 
    ...pduBytes
  ];

  frame.bytesDef = [
    { name: "Transaction Identifier (High)", desc: "Transaction ID high byte", val: `0x${txBytes[0]}`, colorClass: "bg-violet-500/80 hover:bg-violet-400" },
    { name: "Transaction Identifier (Low)", desc: `Matches request ID: ${request.txId}`, val: request.txId.toString(), colorClass: "bg-violet-500/80 hover:bg-violet-400" },
    { name: "Protocol Identifier (High)", desc: "Protocol ID high byte", val: `0x00`, colorClass: "bg-slate-500/80 hover:bg-slate-400" },
    { name: "Protocol Identifier (Low)", desc: "Protocol ID (0 = Modbus TCP)", val: `0x00`, colorClass: "bg-slate-500/80 hover:bg-slate-400" },
    { name: "Length Field (High)", desc: "Length field high byte", val: `0x${lenBytes[0]}`, colorClass: "bg-blue-500/80 hover:bg-blue-400" },
    { name: "Length Field (Low)", desc: `Total bytes following: ${mbapLength}`, val: mbapLength.toString(), colorClass: "bg-blue-500/80 hover:bg-blue-400" },
    { name: "Unit Identifier", desc: `Modbus slave address: ID ${request.unitId}`, val: `Slave ID ${request.unitId}`, colorClass: "bg-teal-500/80 hover:bg-teal-400" }
  ];

  const dataColor = isException ? "bg-rose-500/80 hover:bg-rose-400" : "bg-emerald-500/80 hover:bg-emerald-400";
  pduDefs.forEach((def, index) => {
    frame.bytesDef.push({
      name: def.name,
      desc: def.desc,
      val: def.val,
      colorClass: index === 0 ? "bg-amber-500/80 hover:bg-amber-400" : dataColor
    });
  });

  return frame;
}

// Simulated Physical Field Fluctuations
function runPhysicsSimulation() {
  // Slave 2 VFD Control logic
  const s2 = state.slaves[2];
  if (s2.registers[40001].val === 1) { // Motor Running
    const targetRpm = s2.registers[40002].val;
    s2.registers[40002].val = Math.max(0, Math.min(65535, targetRpm + Math.floor(Math.random() * 11) - 5));
    
    const computedCurrent = Math.floor(s2.registers[40002].val * 0.09 + (Math.random() * 4));
    s2.registers[40003].val = computedCurrent;
    s2.registers[40004].val = Math.floor(215 + (Math.random() * 8) - 4);
    if (s2.registers[40006].val < 48) s2.registers[40006].val += 1;
    s2.registers[40007].val = Math.floor(10 + (Math.random() * 6));
  } else { // Stopped or Fault
    s2.registers[40002].val = 0;
    s2.registers[40003].val = 0;
    s2.registers[40004].val = 0;
    if (s2.registers[40006].val > 28) s2.registers[40006].val -= 1;
    s2.registers[40007].val = 0;
  }

  // Slave 3 Tank Level PLC Control logic
  const s3 = state.slaves[3];
  const pumpOn = s3.registers[40002].val;
  const valveOpen = s3.registers[40003].val;
  let level = s3.registers[40001].val;

  if (pumpOn === 1) {
    level += 15 + Math.floor(Math.random() * 6);
    s3.registers[40007].val = 120 + Math.floor(Math.random() * 10);
  } else {
    s3.registers[40007].val = 0;
  }

  if (valveOpen === 1) {
    level -= 20 + Math.floor(Math.random() * 4);
    s3.registers[40008].val = 150 + Math.floor(Math.random() * 12);
  } else {
    s3.registers[40008].val = 0;
  }

  level = Math.max(0, Math.min(5000, level));
  s3.registers[40001].val = level;
  s3.registers[40005].val = level > 4500 ? 1 : 0;
  s3.registers[40006].val = level < 400 ? 1 : 0;

  // Coupled PLC Logic: ESD Trip if motor speed spins out of safety threshold
  const s1 = state.slaves[1];
  if (s2.registers[40002].val > 3000) {
    if (s1.registers[40004].val === 1) {
      s1.registers[40003].val = 0; // Trip E-Stop Loop
      s1.registers[40008].val = 1; // Set ESD Active
      s2.registers[40001].val = 2; // Trip Motor Controller into Fault State
      
      if (typeof logEvent === 'function') {
        logEvent('exception', "SAFETY ESD SYSTEM ACTIVATED: Motor RPM exceeded safe limits (3000 RPM). Automatic system shutdown initiated by Safety PLC.");
      }
    } else {
      if (typeof logEvent === 'function') {
        logEvent('anomaly', "CRITICAL SAFETY EXPLOIT: Motor RPM exceeds 3000 RPM but ESD System is BYPASSED (Safety Interlock = 0). Physical machinery damage risk!");
      }
    }
  }

  if (typeof renderRegisters === 'function') {
    renderRegisters();
  }
}
