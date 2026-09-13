// Attack Scenario Descriptions
const attackLibrary = {
  safety: {
    name: "Unauthorized Write",
    layer: "Rule-based",
    desc: "Attacker issues a Write command (FC 06) targeting register 40004 (Safety Interlock Bypass) on Slave 1 to override physical safety systems.",
    flag: "⚠ Unauthorized write — register outside baseline range."
  },
  func: {
    name: "Illegal Function Code",
    layer: "Rule-based",
    desc: "Attacker sends a query with unsupported function code 0x99, attempting scanner mapping. PLC returns Modbus Exception code 01.",
    flag: "⚠ Illegal function code — not in expected command set."
  },
  replay: {
    name: "Replay Attack",
    layer: "Protocol-state (FSM)",
    desc: "Attacker sniffs a valid write command (e.g. RPM write, TxID 200) and re-injects it later. FSM detects duplicate Transaction ID out of sequence.",
    flag: "⚠ Replayed transaction — duplicate/stale Transaction ID or out-of-sequence write."
  },
  dos: {
    name: "DoS / Flooding",
    layer: "ML-based",
    desc: "Attacker floods Slave 2 with 18 packets in 2 seconds. Baseline frequency metrics trigger ML anomaly on request rate overload.",
    flag: "⚠ Abnormal request rate — exceeds baseline polling frequency."
  },
  recon: {
    name: "Reconnaissance / Scanning",
    layer: "ML-based",
    desc: "Attacker sweeps fast consecutive read commands across multiple register banks and unit IDs to discover device network registers.",
    flag: "⚠ Address/Unit ID sweep detected — consistent with reconnaissance."
  },
  mitm: {
    name: "MITM / Spoofed Source",
    layer: "Protocol-state (FSM)",
    desc: "Attacker injects a command directly at the switch, spoofing Master IP 10.0.0.10. FSM catches it since it has no matching Master request state.",
    flag: "⚠ Possible spoofed source — conflicting transaction context."
  }
};

// Populate attack descriptions dynamically in UI select panel
function showAttackDetails(id) {
  const details = attackLibrary[id];
  const container = document.getElementById('attack-details');
  if (!details || !container) return;
  
  let badgeColor = "";
  if (details.layer === 'Rule-based') {
    badgeColor = "bg-violet-950/60 text-violet-400 border border-violet-800/50";
  } else if (details.layer === 'ML-based') {
    badgeColor = "bg-emerald-950/60 text-emerald-400 border border-emerald-800/50";
  } else if (details.layer === 'Protocol-state (FSM)') {
    badgeColor = "bg-blue-950/60 text-blue-400 border border-blue-800/50";
  }
  
  container.innerHTML = `
    <div class="flex items-center justify-between border-b border-slate-900 pb-1.5">
      <span class="font-bold text-rose-400">${details.name}</span>
      <span class="px-1.5 py-0.5 rounded text-[8px] font-bold uppercase ${badgeColor} border">${details.layer}</span>
    </div>
    <p class="text-slate-400 text-[10px]">${details.desc}</p>
    <div class="text-[9px] text-rose-500 font-bold bg-rose-950/10 p-1 border border-rose-900/30 rounded mt-0.5">
      Expected Trigger: ${details.flag}
    </div>
  `;
}

// Trigger on-demand anomaly templates
function triggerAttackPayload(type, baseConfig) {
  let config = { ...baseConfig, isAnomaly: true };
  
  if (type === 'safety') {
    config.unitId = 1;
    config.fc = 6;
    config.addr = 40004;
    config.val = 0;
    config.anomalyText = "⚠ Unauthorized write — register outside baseline range.";
    config.detectionLayer = "Rule-based";
  } 
  else if (type === 'range') {
    config.unitId = 2;
    config.fc = 6;
    config.addr = 40002;
    config.val = 9999;
    config.anomalyText = "⚠ Unauthorized write — register outside baseline range.";
    config.detectionLayer = "Rule-based";
  } 
  else if (type === 'func') {
    config.unitId = 3;
    config.fc = 0x99;
    config.anomalyText = "⚠ Illegal function code — not in expected command set.";
    config.detectionLayer = "Rule-based";
  } 
  else if (type === 'ip') {
    config.unitId = 1;
    config.fc = 3;
    config.addr = 40001;
    config.qty = 8;
    config.customSrcIp = "192.168.1.99";
    config.anomalyText = "⚠ Firewall Breach: Unauthorized IP source querying registers.";
    config.detectionLayer = "Rule-based";
  }

  dispatchRequest(config);
}

// ----------------------------------------------------
// ADVANCED ATTACK SCENARIO LIBRARY HANDLERS
// ----------------------------------------------------

// Scenario 1: Unauthorized Write / FC Misuse
function launchAttackScenario1() {
  state.attacker.state = "ACTIVE";
  const wasPolling = state.isPolling;
  if (wasPolling) togglePolling();

  const config = {
    txId: state.nextTransactionId++,
    unitId: 1, // Safety PLC
    fc: 6,
    addr: 40004, // Interlock Bypass
    val: 0, // Bypass Safety
    isAnomaly: true,
    anomalyText: "⚠ Unauthorized write — register outside baseline range.",
    customSrcIp: state.attacker.ip,
    detectionLayer: "Rule-based"
  };

  dispatchRequest(config);

  setTimeout(() => {
    state.attacker.state = "INACTIVE";
    if (wasPolling) togglePolling();
  }, 4000);
}

// Scenario 2: Illegal / Reserved Function Code
function launchAttackScenario2() {
  state.attacker.state = "ACTIVE";
  const wasPolling = state.isPolling;
  if (wasPolling) togglePolling();

  const config = {
    txId: state.nextTransactionId++,
    unitId: 3, // Tank Level
    fc: 0x99, // Reserved / Unknown
    isAnomaly: true,
    anomalyText: "⚠ Illegal function code — not in expected command set.",
    customSrcIp: state.attacker.ip,
    detectionLayer: "Rule-based"
  };

  dispatchRequest(config);

  setTimeout(() => {
    state.attacker.state = "INACTIVE";
    if (wasPolling) togglePolling();
  }, 4000);
}

// Scenario 3: Replay Attack
function launchAttackScenario3() {
  const wasPolling = state.isPolling;
  if (wasPolling) togglePolling();

  // Step 1: Normal transaction
  const normalConfig = {
    txId: 200,
    unitId: 2,
    fc: 6,
    addr: 40002,
    val: 1485,
    isAnomaly: false
  };

  logEvent('info', "Attacker Sniffing Network: Capture valid Master RPM write packet...");
  dispatchRequest(normalConfig);

  // Step 2: Replay same transaction out of order from Attacker Node
  setTimeout(() => {
    state.attacker.state = "ACTIVE";
    
    // Trigger FSM violation visual strip alert immediately on packet release
    updateFsm('sent', "FSM ALERT: Replayed Transaction! Duplicate TxID 200 in Completed State.");

    const replayConfig = {
      txId: 200, // Replayed TxID!
      unitId: 2,
      fc: 6,
      addr: 40002,
      val: 1485,
      isAnomaly: true,
      anomalyText: "⚠ Replayed transaction — duplicate/stale Transaction ID or out-of-sequence write.",
      customSrcIp: state.attacker.ip,
      detectionLayer: "Protocol-state (FSM)"
    };

    dispatchRequest(replayConfig);
  }, 2600);

  // Clean up sequence FSM state
  setTimeout(() => {
    state.attacker.state = "INACTIVE";
    updateFsm('idle');
    if (wasPolling) togglePolling();
  }, 6600);
}

// Scenario 4: Denial-of-Service (DoS) / Flooding
function launchAttackScenario4() {
  state.attacker.state = "ACTIVE";
  const wasPolling = state.isPolling;
  if (wasPolling) togglePolling();

  const target = state.slaves[2]; // Target Motor PLC
  logEvent('anomaly', "IDS ALERT: Abnormal request rate threshold breached. Analyzing request frequency...", "", "ML-based");

  let burstCount = 18;
  let sentCount = 0;

  const interval = setInterval(() => {
    if (sentCount >= burstCount) {
      clearInterval(interval);
      return;
    }

    // Trigger shake & overload indicators
    target.shakeTimer = 0.3;
    target.queueFullIndicator = true;

    const config = {
      txId: state.nextTransactionId++,
      unitId: 2,
      fc: 3,
      addr: 40001,
      qty: 4,
      isAnomaly: true,
      anomalyText: "⚠ Abnormal request rate — exceeds baseline polling frequency.",
      customSrcIp: state.attacker.ip,
      detectionLayer: "ML-based"
    };

    const requestFrame = createModbusFrame(config);

    // Send extremely fast packets
    sendPacket({
      type: 'req',
      txId: config.txId,
      unitId: config.unitId,
      isAnomaly: true,
      srcIp: requestFrame.srcIp,
      destIp: requestFrame.destIp,
      rawBytes: requestFrame.rawBytes,
      bytesDef: requestFrame.bytesDef,
      fc: config.fc,
      stepRate: 0.08 // Cascading fast animation speed
    }, () => {
      state.alarmCount++;
      const counterEl = document.getElementById('alarm-counter');
      if (counterEl) counterEl.innerText = state.alarmCount;
      target.state = 'ALARM';
      target.alertMsg = config.anomalyText;
      target.alertExpiry = Date.now() + 1500;

      const responseFrame = createResponseFrame(requestFrame, false, 0);
      sendPacket({
        type: 'res',
        txId: config.txId,
        unitId: config.unitId,
        isAnomaly: true,
        srcIp: responseFrame.srcIp,
        destIp: responseFrame.destIp,
        rawBytes: responseFrame.rawBytes,
        bytesDef: responseFrame.bytesDef,
        fc: config.fc,
        stepRate: 0.08
      }, () => {
        if (target.state !== 'ALARM') target.state = 'OK';
      });
    });

    sentCount++;
  }, 100); // 100ms packet interval

  setTimeout(() => {
    state.attacker.state = "INACTIVE";
    target.queueFullIndicator = false;
    target.state = 'OK';
    if (wasPolling) togglePolling();
  }, 4500);
}

// Scenario 5: Reconnaissance / Scanning (Sweep)
function launchAttackScenario5() {
  state.attacker.state = "ACTIVE";
  const wasPolling = state.isPolling;
  if (wasPolling) togglePolling();

  const sweepSteps = [
    { unitId: 1, addr: 40001 },
    { unitId: 2, addr: 40001 },
    { unitId: 3, addr: 40001 },
    { unitId: 1, addr: 40005 },
    { unitId: 2, addr: 40005 },
    { unitId: 3, addr: 40005 }
  ];

  let stepIdx = 0;
  const interval = setInterval(() => {
    if (stepIdx >= sweepSteps.length) {
      clearInterval(interval);
      return;
    }

    const step = sweepSteps[stepIdx];
    const config = {
      txId: state.nextTransactionId++,
      unitId: step.unitId,
      fc: 3,
      addr: step.addr,
      qty: 2,
      isAnomaly: true,
      anomalyText: "⚠ Address/Unit ID sweep detected — consistent with reconnaissance.",
      customSrcIp: state.attacker.ip,
      detectionLayer: "ML-based"
    };

    const requestFrame = createModbusFrame(config);
    sendPacket({
      type: 'req',
      txId: config.txId,
      unitId: config.unitId,
      isAnomaly: true,
      srcIp: requestFrame.srcIp,
      destIp: requestFrame.destIp,
      rawBytes: requestFrame.rawBytes,
      bytesDef: requestFrame.bytesDef,
      fc: config.fc,
      stepRate: 0.05
    }, () => {
      state.alarmCount++;
      const counterEl = document.getElementById('alarm-counter');
      if (counterEl) counterEl.innerText = state.alarmCount;
      
      const slave = state.slaves[config.unitId];
      slave.state = 'ALARM';
      slave.alertMsg = config.anomalyText;
      slave.alertExpiry = Date.now() + 1000;

      for (let r = 0; r < 2; r++) {
        slave.flashRegisters[config.addr + r] = 'anomaly';
      }
      renderRegisters();

      const responseFrame = createResponseFrame(requestFrame, false, 0);
      sendPacket({
        type: 'res',
        txId: config.txId,
        unitId: config.unitId,
        isAnomaly: true,
        srcIp: responseFrame.srcIp,
        destIp: responseFrame.destIp,
        rawBytes: responseFrame.rawBytes,
        bytesDef: responseFrame.bytesDef,
        fc: config.fc,
        stepRate: 0.05
      }, () => {
        slave.flashRegisters = {};
        slave.state = 'OK';
        renderRegisters();
      });
    });

    stepIdx++;
  }, 400); // 400ms sweep interval

  setTimeout(() => {
    state.attacker.state = "INACTIVE";
    if (wasPolling) togglePolling();
  }, 4500);
}

// Scenario 6: MITM / Spoofed Source
function launchAttackScenario6() {
  state.attacker.state = "ACTIVE";
  const wasPolling = state.isPolling;
  if (wasPolling) togglePolling();

  // Trigger FSM Spoof alert
  updateFsm('sent', "FSM ALERT: Out-of-Sequence Spoofed Injection detected! Spoofed Source: 10.0.0.10.");

  const config = {
    txId: 99, // Mismatched/OutOfSequence TxID
    unitId: 1, // Safety PLC
    fc: 6,
    addr: 40001,
    val: 1,
    isAnomaly: true,
    anomalyText: "⚠ Possible spoofed source — conflicting transaction context.",
    customSrcIp: "10.0.0.10", // Spoofing Master IP!
    detectionLayer: "Protocol-state (FSM)",
    isMitm: true // Injects directly at switch
  };

  const requestFrame = createModbusFrame(config);
  
  logEvent('anomaly', "IDS ALERT: Spoofed packet injection on HMI interface detected. Source IP mismatch.", 
           `TX:99 | IP:10.0.0.10 (Spoofed) | Payload:${requestFrame.rawBytes.slice(7).join(" ")}`, 
           "Protocol-state (FSM)");

  sendPacket({
    type: 'req',
    txId: config.txId,
    unitId: config.unitId,
    isAnomaly: true,
    srcIp: "10.0.0.10",
    destIp: requestFrame.destIp,
    rawBytes: requestFrame.rawBytes,
    bytesDef: requestFrame.bytesDef,
    fc: config.fc,
    isMitm: true
  }, () => {
    state.alarmCount++;
    const counterEl = document.getElementById('alarm-counter');
    if (counterEl) counterEl.innerText = state.alarmCount;

    const slave = state.slaves[config.unitId];
    slave.state = 'ALARM';
    slave.alertMsg = config.anomalyText;
    slave.alertExpiry = Date.now() + 4500;

    const responseFrame = createResponseFrame(requestFrame, false, 0);
    sendPacket({
      type: 'res',
      txId: config.txId,
      unitId: config.unitId,
      isAnomaly: true,
      srcIp: responseFrame.srcIp,
      destIp: "10.0.0.10",
      rawBytes: responseFrame.rawBytes,
      bytesDef: responseFrame.bytesDef,
      fc: config.fc,
      isMitmResponse: true
    }, () => {
      slave.state = 'OK';
    });
  });

  setTimeout(() => {
    state.attacker.state = "INACTIVE";
    updateFsm('idle');
    if (wasPolling) togglePolling();
  }, 5500);
}

// Trigger selected attack from select dropdown UI
function launchAttackFromLibrary() {
  const select = document.getElementById('attack-select');
  const val = select ? select.value : 'safety';
  
  if (val === 'safety') launchAttackScenario1();
  else if (val === 'func') launchAttackScenario2();
  else if (val === 'replay') launchAttackScenario3();
  else if (val === 'dos') launchAttackScenario4();
  else if (val === 'recon') launchAttackScenario5();
  else if (val === 'mitm') launchAttackScenario6();
}
