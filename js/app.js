// Canvas & Graphics Setup
let canvas, ctx;
let width = 0, height = 0;
let animationFrameId = null;
let hoveredPacket = null;

function initCanvas() {
  canvas = document.getElementById('network-canvas');
  if (!canvas) return;
  ctx = canvas.getContext('2d');
  
  resizeCanvas();
  
  canvas.addEventListener('mousemove', function(e) {
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    
    let found = null;
    for (let p of state.packets) {
      if (p.currentX && p.currentY) {
        const dx = mouseX - p.currentX;
        const dy = mouseY - p.currentY;
        if (Math.abs(dx) < 18 && Math.abs(dy) < 12) {
          found = p;
          break;
        }
      }
    }
    
    if (found) {
      hoveredPacket = found;
      inspectPacket(found);
    } else {
      hoveredPacket = null;
    }
  });
}

function resizeCanvas() {
  if (!canvas) return;
  const rect = canvas.parentElement.getBoundingClientRect();
  width = rect.width;
  height = rect.height;
  
  const dpr = window.devicePixelRatio || 1;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  ctx.scale(dpr, dpr);
  
  // Update coordinates dynamically relative to canvas width/height
  state.master.x = width * 0.12;
  state.master.y = height * 0.35;

  state.attacker.x = width * 0.12;
  state.attacker.y = height * 0.72;
  
  state.switchNode.x = width * 0.45;
  state.switchNode.y = height * 0.5;
  
  state.slaves[1].x = width * 0.82;
  state.slaves[1].y = height * 0.22;
  
  state.slaves[2].x = width * 0.82;
  state.slaves[2].y = height * 0.5;
  
  state.slaves[3].x = width * 0.82;
  state.slaves[3].y = height * 0.78;
}

window.addEventListener('resize', resizeCanvas);

// Interactive Byte Block Inspection UI
function inspectPacket(packet) {
  state.selectedPacket = packet;
  
  const placeholder = document.getElementById('inspector-placeholder');
  const content = document.getElementById('inspector-content');
  if (placeholder) placeholder.classList.add('hidden');
  if (content) content.classList.remove('hidden');

  const label = document.getElementById('inspector-packet-label');
  if (label) {
    label.innerText = `${packet.srcIp} → ${packet.destIp} (${packet.rawBytes.length} Bytes)`;
    if (packet.isAnomaly) {
      label.className = "font-bold text-rose-500 animate-pulse";
      const legend = document.getElementById('data-legend-color');
      if (legend) legend.className = "w-2.5 h-2.5 rounded bg-rose-500/80 inline-block";
    } else {
      label.className = "font-bold text-cyan-400";
      const legend = document.getElementById('data-legend-color');
      if (legend) legend.className = "w-2.5 h-2.5 rounded bg-emerald-500/80 inline-block";
    }
  }

  // Render Hex Grid Blocks
  const container = document.getElementById('byte-blocks-container');
  if (container) {
    container.innerHTML = "";
    packet.rawBytes.forEach((byte, idx) => {
      const def = packet.bytesDef[idx] || { colorClass: "bg-slate-700", name: "Reserved" };
      const block = document.createElement('div');
      block.className = `w-8 h-8 rounded border border-slate-950 flex items-center justify-center font-mono text-xs font-bold ${def.colorClass} cursor-pointer transition select-none shadow-sm`;
      block.innerText = byte;
      block.title = `${def.name}: ${byte}`;
      
      block.onmouseenter = () => highlightInspectorRow(idx, def);
      block.onmouseleave = () => clearInspectorHighlight();
      
      container.appendChild(block);
    });
  }

  // Render Detailed Table Rows
  const tableBody = document.getElementById('inspector-table-body');
  if (tableBody) {
    tableBody.innerHTML = "";
    
    let i = 0;
    while (i < packet.rawBytes.length) {
      const def = packet.bytesDef[i] || { name: "Payload Byte", desc: "Data block parameter byte", val: "0x00", colorClass: "bg-emerald-500/80" };
      
      let rangeLabel = `Byte ${i}`;
      let byteGroup = [packet.rawBytes[i]];
      let nextIndex = i + 1;
      
      if (def.name.includes("Transaction Identifier")) {
        byteGroup.push(packet.rawBytes[i+1]);
        rangeLabel = "Bytes 0-1";
        nextIndex = i + 2;
      } else if (def.name.includes("Protocol Identifier")) {
        byteGroup.push(packet.rawBytes[i+1]);
        rangeLabel = "Bytes 2-3";
        nextIndex = i + 2;
      } else if (def.name.includes("Length Field")) {
        byteGroup.push(packet.rawBytes[i+1]);
        rangeLabel = "Bytes 4-5";
        nextIndex = i + 2;
      } else if (def.name.includes("Starting Address") || def.name.includes("Register Address")) {
        byteGroup.push(packet.rawBytes[i+1]);
        rangeLabel = `Bytes ${i}-${i+1}`;
        nextIndex = i + 2;
      } else if (def.name.includes("Quantity of Registers")) {
        byteGroup.push(packet.rawBytes[i+1]);
        rangeLabel = `Bytes ${i}-${i+1}`;
        nextIndex = i + 2;
      } else if (def.name.includes("Register Value") && !def.name.includes("Multiple")) {
        byteGroup.push(packet.rawBytes[i+1]);
        rangeLabel = `Bytes ${i}-${i+1}`;
        nextIndex = i + 2;
      } else if (def.name.includes("Val (High)")) {
        byteGroup.push(packet.rawBytes[i+1]);
        rangeLabel = `Bytes ${i}-${i+1}`;
        nextIndex = i + 2;
      }

      const hexStr = byteGroup.join(" ");
      const finalVal = packet.bytesDef[nextIndex-1] ? packet.bytesDef[nextIndex-1].val : def.val;
      const rowDesc = packet.bytesDef[nextIndex-1] ? packet.bytesDef[nextIndex-1].desc : def.desc;
      const mainName = def.name.replace(" (High)", "").replace(" (Low)", "");
      
      const row = document.createElement('tr');
      row.id = `inspector-row-${i}`;
      row.className = "hover:bg-slate-900 cursor-help transition border-b border-slate-900/40";
      row.innerHTML = `
        <td class="py-2 text-slate-400">${rangeLabel}</td>
        <td class="py-2 text-slate-300 font-bold">${mainName}</td>
        <td class="py-2 text-center text-cyan-400 font-bold">${hexStr}</td>
        <td class="py-2 text-right text-emerald-400">${finalVal}</td>
      `;
      
      const displayIndex = i;
      row.onmouseenter = () => {
        highlightByteBlocks(displayIndex, nextIndex - displayIndex);
        showExplanationCard(mainName, rowDesc);
      };
      row.onmouseleave = () => {
        clearByteBlocksHighlight();
        hideExplanationCard();
      };

      tableBody.appendChild(row);
      i = nextIndex;
    }
  }
}

function showExplanationCard(title, text) {
  const card = document.getElementById('byte-explanation-card');
  const tEl = document.getElementById('exp-title');
  const txtEl = document.getElementById('exp-text');
  if (tEl) tEl.innerText = title;
  if (txtEl) txtEl.innerText = text;
  if (card) card.classList.remove('hidden');
}

function hideExplanationCard() {
  const card = document.getElementById('byte-explanation-card');
  if (card) card.classList.add('hidden');
}

function highlightInspectorRow(byteIndex, def) {
  let targetIdx = byteIndex;
  if (byteIndex === 1) targetIdx = 0; // Trans ID
  if (byteIndex === 3) targetIdx = 2; // Protocol ID
  if (byteIndex === 5) targetIdx = 4; // Length ID
  if (byteIndex === 9 || byteIndex === 11 || byteIndex === 13) targetIdx = byteIndex - 1; // 16-bit args
  
  const row = document.getElementById(`inspector-row-${targetIdx}`);
  if (row) {
    row.classList.add('bg-slate-800');
    showExplanationCard(def.name, def.desc);
  }
}

function clearInspectorHighlight() {
  hideExplanationCard();
  const rows = document.querySelectorAll('#inspector-table-body tr');
  rows.forEach(r => r.classList.remove('bg-slate-800'));
}

function highlightByteBlocks(startIndex, count) {
  const container = document.getElementById('byte-blocks-container');
  if (!container) return;
  const blocks = container.children;
  for (let i = 0; i < blocks.length; i++) {
    if (i >= startIndex && i < startIndex + count) {
      blocks[i].classList.add('ring-2', 'ring-cyan-400', 'scale-105', 'z-10');
    }
  }
}

function clearByteBlocksHighlight() {
  const container = document.getElementById('byte-blocks-container');
  if (!container) return;
  const blocks = container.children;
  for (let i = 0; i < blocks.length; i++) {
    blocks[i].classList.remove('ring-2', 'ring-cyan-400', 'scale-105', 'z-10');
  }
}

// Logger & Alarm Management (Deduplication + Repeat Counter)
function recordAlarm({ attackName, reason, layer = "Rule-based", severity = "MEDIUM", sourceIp = "192.168.1.99" }) {
  state.alarmCount++;
  const counterEl = document.getElementById('alarm-counter');
  if (counterEl) counterEl.innerText = state.alarmCount;

  const timestamp = new Date().toLocaleTimeString();
  
  // Feature 3: Deduplicate consecutive identical alarms into single row with repeat counter
  const lastLog = state.logs.length > 0 ? state.logs[state.logs.length - 1] : null;
  if (lastLog && lastLog.type === 'anomaly' && (lastLog.attackName === attackName || lastLog.text === reason)) {
    lastLog.repeatCount = (lastLog.repeatCount || 1) + 1;
    lastLog.timestamp = timestamp;
  } else {
    state.logs.push({
      timestamp,
      type: 'anomaly',
      attackName,
      text: reason,
      details: `Source IP: ${sourceIp} | Detection: ${layer} | Severity: ${severity}`,
      detectionLayer: layer,
      severity,
      sourceIp,
      repeatCount: 1
    });
  }

  if (state.logs.length > 100) state.logs.shift();
  renderLogs();
}

function revealRogueNode(durationMs = 14000) {
  state.attacker.visible = true;
  state.attacker.visibleUntil = Date.now() + durationMs;
}

function toggleQuarantine(ip) {
  if (!ip) return;
  if (state.quarantinedNodes[ip]) {
    delete state.quarantinedNodes[ip];
    logEvent('info', `Source ${ip} connection restored to network segment.`);
  } else {
    state.quarantinedNodes[ip] = true;
    if (ip === state.attacker.ip) {
      state.attacker.visible = true;
    }
    logEvent('info', `Source ${ip} isolated from network segment.`);
  }
  updateRestoreAllButton();
  renderLogs();
}

function restoreAllQuarantine() {
  const ips = Object.keys(state.quarantinedNodes);
  state.quarantinedNodes = {};
  ips.forEach(ip => {
    logEvent('info', `Source ${ip} connection restored to network segment.`);
  });
  updateRestoreAllButton();
  renderLogs();
}

function updateRestoreAllButton() {
  const btn = document.getElementById('restore-all-btn');
  if (!btn) return;
  const count = Object.keys(state.quarantinedNodes).length;
  if (count > 0) {
    btn.classList.remove('hidden');
    btn.innerText = `↺ Restore (${count}) Isolated`;
  } else {
    btn.classList.add('hidden');
  }
}

function logEvent(type, text, details = "", detectionLayer = "", severity = "") {
  const timestamp = new Date().toLocaleTimeString();
  state.logs.push({ timestamp, type, text, details, detectionLayer, severity, repeatCount: 1 });
  
  if (state.logs.length > 100) state.logs.shift();
  renderLogs();
}

function clearLogs() {
  state.logs = [];
  renderLogs();
}

function renderLogs() {
  const filterEl = document.getElementById('log-filter');
  const filter = filterEl ? filterEl.value : 'all';
  const container = document.getElementById('console-box');
  if (!container) return;
  
  container.innerHTML = "";
  
  state.logs.forEach(log => {
    if (filter === 'alerts' && log.type !== 'anomaly' && log.type !== 'exception') return;
    if (filter === 'traffic' && log.type !== 'tx' && log.type !== 'rx') return;

    const line = document.createElement('div');
    line.className = "mb-1.5 flex flex-col md:flex-row md:items-start border-l-2 pl-2 border-slate-700 py-0.5";
    
    let colorClass = "text-slate-400";
    let prefix = "[INFO]";
    
    if (log.type === 'tx') {
      colorClass = "text-cyan-400";
      prefix = "⚡ [SEND]";
      line.className = "mb-1.5 flex flex-col md:flex-row md:items-start border-l-2 pl-2 border-cyan-500 py-0.5 bg-cyan-950/10";
    } else if (log.type === 'rx') {
      colorClass = "text-emerald-400";
      prefix = "✔ [RECV]";
      line.className = "mb-1.5 flex flex-col md:flex-row md:items-start border-l-2 pl-2 border-emerald-500 py-0.5 bg-emerald-950/10";
    } else if (log.type === 'anomaly') {
      colorClass = "text-rose-500 font-bold";
      prefix = "🚨 [ALARM]";
      line.className = "mb-1.5 flex flex-col md:flex-row md:items-start border-l-2 pl-2 border-rose-500 py-1 bg-rose-950/25 rounded-r shadow-sm";
    } else if (log.type === 'exception') {
      colorClass = "text-amber-500";
      prefix = "⚠ [FAULT]";
      line.className = "mb-1.5 flex flex-col md:flex-row md:items-start border-l-2 pl-2 border-amber-500 py-0.5 bg-amber-950/10";
    }

    let badgesHtml = "";
    if (log.detectionLayer) {
      let badgeColor = "";
      if (log.detectionLayer === 'Rule-based') {
        badgeColor = "bg-violet-950/60 text-violet-400 border border-violet-800/50";
      } else if (log.detectionLayer === 'ML-based') {
        badgeColor = "bg-emerald-950/60 text-emerald-400 border border-emerald-800/50";
      } else if (log.detectionLayer === 'Protocol-state (FSM)') {
        badgeColor = "bg-blue-950/60 text-blue-400 border border-blue-800/50";
      }
      badgesHtml += `<span class="px-1.5 py-0.5 rounded text-[8px] font-bold uppercase ${badgeColor} border">${log.detectionLayer}</span>`;
    }

    if (log.severity) {
      let sevColor = "";
      if (log.severity === 'CRITICAL') {
        sevColor = "bg-rose-950 text-rose-300 border border-rose-600 font-extrabold";
      } else if (log.severity === 'HIGH') {
        sevColor = "bg-orange-950 text-orange-300 border border-orange-600 font-bold";
      } else if (log.severity === 'MEDIUM') {
        sevColor = "bg-amber-950 text-amber-300 border border-amber-600 font-bold";
      } else {
        sevColor = "bg-yellow-950 text-yellow-300 border border-yellow-600 font-bold";
      }
      badgesHtml += `<span class="px-1.5 py-0.5 rounded text-[8px] uppercase ${sevColor} border">${log.severity}</span>`;
    }

    let actionHtml = "";
    if (log.type === 'anomaly' && log.sourceIp) {
      const isIso = !!state.quarantinedNodes[log.sourceIp];
      if (isIso) {
        actionHtml = `<button onclick="toggleQuarantine('${log.sourceIp}')" class="shrink-0 text-[8px] font-mono px-2 py-0.5 rounded bg-amber-950 hover:bg-amber-900 text-amber-300 border border-amber-600 transition flex items-center gap-1 font-bold shadow-sm">↺ Restore Connection</button>`;
      } else {
        actionHtml = `<button onclick="toggleQuarantine('${log.sourceIp}')" class="shrink-0 text-[8px] font-mono px-2 py-0.5 rounded bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-600 transition flex items-center gap-1 font-bold shadow-sm">🛡 Quarantine Source</button>`;
      }
    }

    const repeatBadge = (log.repeatCount && log.repeatCount > 1) 
      ? `<span class="ml-1.5 px-1.5 py-0.2 rounded text-[9px] font-extrabold bg-rose-600 text-white border border-rose-400 shadow-sm animate-pulse">×${log.repeatCount}</span>` 
      : "";

    line.innerHTML = `
      <span class="text-slate-500 shrink-0 select-none mr-2">${log.timestamp}</span>
      <span class="${colorClass} shrink-0 select-none mr-2">${prefix}</span>
      <div class="flex-1 min-w-0">
        <div class="flex items-center flex-wrap gap-1.5 justify-between">
          <div class="flex items-center flex-wrap gap-1.5">
            ${log.attackName ? `<span class="text-rose-300 font-bold flex items-center">${log.attackName}${repeatBadge}:</span>` : ""}
            <span class="text-slate-300 font-medium">${log.text}</span>
            ${badgesHtml}
          </div>
          ${actionHtml}
        </div>
        ${log.details ? `<span class="block text-[10px] text-slate-500 mt-0.5">${log.details}</span>` : ""}
      </div>
    `;
    container.appendChild(line);
  });
  
  container.scrollTop = container.scrollHeight;
}

// Render Slave registers matching Byte Inspector Table Discipline & Spacing (Feature 1 & 5)
function renderRegisters() {
  for (let sId = 1; sId <= 3; sId++) {
    const container = document.getElementById(`slave-${sId}-regs`);
    if (!container) continue;
    container.innerHTML = "";
    const slave = state.slaves[sId];
    
    // Header Table matching Byte Inspector discipline
    const table = document.createElement('table');
    table.className = "w-full text-[9.5px] font-mono border-collapse";
    
    let rowsHtml = "";
    for (let rAddr = 40001; rAddr <= 40008; rAddr++) {
      const reg = slave.registers[rAddr];
      
      let flashClass = "text-slate-300";
      if (slave.flashRegisters[rAddr] === 'write') {
        flashClass = "bg-emerald-950/70 text-emerald-300 font-bold border-l-2 border-emerald-500";
      } else if (slave.flashRegisters[rAddr] === 'read') {
        flashClass = "bg-cyan-950/70 text-cyan-300 font-bold border-l-2 border-cyan-500";
      } else if (slave.flashRegisters[rAddr] === 'anomaly') {
        flashClass = "bg-rose-950/90 text-rose-300 font-bold border-l-2 border-rose-500 animate-pulse";
      }
      
      const hasBaseline = !!reg.baseline;
      const isOutOfRange = hasBaseline && (reg.val < reg.baseline.min || reg.val > reg.baseline.max);
      
      let valHtml = "";
      let baselineBadgeHtml = "";

      if (isOutOfRange) {
        valHtml = `<span class="font-extrabold text-rose-400">${reg.val}</span>`;
        baselineBadgeHtml = `
          <span class="px-1 py-0.2 rounded text-[7.5px] font-extrabold bg-rose-950 text-rose-300 border border-rose-600 animate-pulse inline-block shadow-[0_0_8px_rgba(244,63,94,0.4)]" title="Operational limit: ${reg.baseline.label}">
            ${reg.val} [OUT OF RANGE]
          </span>
        `;
      } else if (hasBaseline) {
        valHtml = `<span class="font-bold text-slate-200">${reg.val}</span>`;
        baselineBadgeHtml = `
          <span class="px-1 py-0.2 rounded text-[7.5px] bg-slate-900 text-slate-400 border border-slate-800/80 inline-block" title="Expected Baseline: ${reg.baseline.label}">
            ${reg.baseline.label}
          </span>
        `;
      } else {
        valHtml = `<span class="font-bold text-slate-200">${reg.val}</span>`;
        baselineBadgeHtml = `<span class="text-[7.5px] text-slate-600">-</span>`;
      }

      rowsHtml += `
        <tr class="border-b border-slate-900/50 hover:bg-slate-900/40 transition-colors py-0.5 ${flashClass} ${isOutOfRange ? 'bg-rose-950/30' : ''}">
          <td class="py-1 pl-1 text-slate-400 shrink-0 select-none" title="Register Address">${rAddr}</td>
          <td class="py-1 px-1.5 text-slate-300 font-medium truncate max-w-[90px]" title="${reg.name}">${reg.name}</td>
          <td class="py-1 px-1 text-right">${valHtml}</td>
          <td class="py-1 pr-1 text-right shrink-0">${baselineBadgeHtml}</td>
        </tr>
      `;
    }

    table.innerHTML = `
      <thead>
        <tr class="text-[8px] text-slate-500 uppercase border-b border-slate-800/60 font-semibold select-none">
          <th class="text-left py-0.5 pl-1 font-mono">Reg</th>
          <th class="text-left py-0.5 px-1.5 font-mono">Parameter</th>
          <th class="text-right py-0.5 px-1 font-mono">Val</th>
          <th class="text-right py-0.5 pr-1 font-mono">Baseline</th>
        </tr>
      </thead>
      <tbody>
        ${rowsHtml}
      </tbody>
    `;
    
    container.appendChild(table);
  }
}

// Draw Grid & Topology
function drawGrid(w, h) {
  ctx.strokeStyle = "rgba(30, 41, 59, 0.25)";
  ctx.lineWidth = 1;
  const step = 20;
  for (let x = 0; x < w; x += step) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, h);
    ctx.stroke();
  }
  for (let y = 0; y < h; y += step) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }
}

function drawTopology() {
  if (!ctx) return;
  ctx.clearRect(0, 0, width, height);
  drawGrid(width, height);

  const m = state.master;
  const sw = state.switchNode;
  const atk = state.attacker;

  // Draw Main Wires
  ctx.lineWidth = 4;
  ctx.lineCap = "round";
  ctx.s  // Wire: Master to Switch
  ctx.save();
  if (state.quarantinedNodes[m.ip]) {
    ctx.strokeStyle = "rgba(100, 116, 139, 0.6)";
    ctx.lineWidth = 2.5;
    ctx.setLineDash([5, 5]);
  } else {
    ctx.strokeStyle = "rgba(15, 23, 42, 0.8)";
    ctx.lineWidth = 4;
  }
  ctx.beginPath();
  ctx.moveTo(m.x, m.y);
  ctx.lineTo(sw.x, sw.y);
  ctx.stroke();
  if (!state.quarantinedNodes[m.ip]) {
    ctx.strokeStyle = "#1e293b";
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }
  ctx.restore();

  // Wire: Attacker to Switch (Rogue Node) - only visible when revealed or quarantined (Feature 6 & 4)
  if (atk.visibilityAlpha > 0.01) {
    ctx.save();
    ctx.globalAlpha = atk.visibilityAlpha;
    const slideX = (1.0 - atk.visibilityAlpha) * -30;
    const atkWX = atk.x + slideX;
    
    ctx.beginPath();
    ctx.moveTo(atkWX, atk.y);
    ctx.lineTo(sw.x, sw.y);
    
    if (state.quarantinedNodes[atk.ip]) {
      ctx.strokeStyle = "rgba(100, 116, 139, 0.8)";
      ctx.lineWidth = 2.5;
      ctx.setLineDash([5, 5]);
    } else if (atk.state === "ACTIVE") {
      ctx.strokeStyle = "rgba(239, 68, 68, 0.85)";
      ctx.lineWidth = 2.5;
      ctx.setLineDash([4, 4]);
      ctx.lineDashOffset = -Math.floor(Date.now() / 40) % 80;
    } else {
      ctx.strokeStyle = "rgba(100, 116, 139, 0.25)";
      ctx.lineWidth = 1.5;
    }
    ctx.stroke();
    ctx.restore();
  }

  // Wires: Switch to Slaves
  for (let sId = 1; sId <= 3; sId++) {
    const sl = state.slaves[sId];
    ctx.save();
    if (state.quarantinedNodes[sl.ip]) {
      ctx.strokeStyle = "rgba(100, 116, 139, 0.6)";
      ctx.lineWidth = 2.5;
      ctx.setLineDash([5, 5]);
      ctx.beginPath();
      ctx.moveTo(sw.x, sw.y);
      ctx.lineTo(sl.x, sl.y);
      ctx.stroke();
    } else {
      ctx.strokeStyle = "rgba(15, 23, 42, 0.8)";
      ctx.lineWidth = 4;
      ctx.beginPath();
      ctx.moveTo(sw.x, sw.y);
      ctx.lineTo(sl.x, sl.y);
      ctx.stroke();
      
      ctx.strokeStyle = "#1e293b";
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }
    ctx.restore();
  }

  // Draw Switch Node
  ctx.shadowBlur = 0;
  ctx.fillStyle = "#1e293b";
  ctx.strokeStyle = "#334155";
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.rect(sw.x - 18, sw.y - 18, 36, 36);
  ctx.fill();
  ctx.stroke();

  // Network ports on switch
  ctx.fillStyle = "#0f172a";
  ctx.fillRect(sw.x - 12, sw.y - 12, 8, 8);
  ctx.fillRect(sw.x + 4, sw.y - 12, 8, 8);
  ctx.fillRect(sw.x - 12, sw.y + 4, 8, 8);
  ctx.fillRect(sw.x + 4, sw.y + 4, 8, 8);

  // Flashing green port LEDs
  sw.pulseTimer += 0.05;
  ctx.fillStyle = Math.sin(sw.pulseTimer) > 0 ? "#10b981" : "#047857";
  ctx.beginPath();
  ctx.arc(sw.x - 8, sw.y - 8, 2, 0, Math.PI * 2);
  ctx.fill();
  ctx.fillStyle = Math.sin(sw.pulseTimer + 1) > 0 ? "#10b981" : "#047857";
  ctx.beginPath();
  ctx.arc(sw.x + 8, sw.y - 8, 2, 0, Math.PI * 2);
  ctx.fill();
  ctx.fillStyle = Math.sin(sw.pulseTimer + 2) > 0 ? "#10b981" : "#047857";
  ctx.beginPath();
  ctx.arc(sw.x - 8, sw.y + 8, 2, 0, Math.PI * 2);
  ctx.fill();
  ctx.fillStyle = Math.sin(sw.pulseTimer + 3) > 0 ? "#10b981" : "#047857";
  ctx.beginPath();
  ctx.arc(sw.x + 8, sw.y + 8, 2, 0, Math.PI * 2);
  ctx.fill();

  // Label Switch
  ctx.font = "bold 9px 'Fira Code'";
  ctx.fillStyle = "#64748b";
  ctx.textAlign = "center";
  ctx.fillText("ETHERNET SWITCH", sw.x, sw.y - 24);

  // Draw Master Node HMI
  drawDeviceNode(m.x, m.y, "HMI Master", m.ip, m.state, true, 0, false, !!state.quarantinedNodes[m.ip]);

  // Draw Attacker Rogue Node (Feature 6 & 4)
  if (atk.visibilityAlpha > 0.01) {
    ctx.save();
    ctx.globalAlpha = atk.visibilityAlpha;
    const slideX = (1.0 - atk.visibilityAlpha) * -30;
    const isIso = !!state.quarantinedNodes[atk.ip];
    const devState = isIso ? 'ISOLATED' : (atk.state === "ACTIVE" || atk.pulseTimer > 0 ? "ATTACK" : "INACTIVE");
    drawDeviceNode(atk.x + slideX, atk.y, "Rogue Node", atk.ip, devState, false, 0, true, isIso);
    if (atk.pulseTimer > 0) atk.pulseTimer -= 0.016;
    ctx.restore();
  }

  // Draw Slaves
  for (let sId = 1; sId <= 3; sId++) {
    const sl = state.slaves[sId];
    let shakeOffset = { x: 0, y: 0 };
    if (sl.shakeTimer > 0) {
      shakeOffset.x = (Math.random() - 0.5) * 8;
      shakeOffset.y = (Math.random() - 0.5) * 8;
      sl.shakeTimer -= 0.016;
    }
    
    drawDeviceNode(sl.x + shakeOffset.x, sl.y + shakeOffset.y, sl.name, sl.ip, sl.state, false, sl.id, false, !!state.quarantinedNodes[sl.ip]);
    
    if (sl.queueFullIndicator) {
      ctx.font = "bold 8px 'Fira Code'";
      ctx.fillStyle = "#ef4444";
      ctx.textAlign = "center";
      ctx.fillText("QUEUE FULL (100% CPU)", sl.x, sl.y + 38);
    }
  }

  // Draw Packets In Flight
  ctx.shadowBlur = 0;
  state.packets.forEach(p => {
    let currentPos = { x: 0, y: 0 };
    // Helper to clamp progress t along segment to avoid overlapping node boxes (Wireshark / Lucidchart style)
    const clampSeg = (tVal, minT = 0.16, maxT = 0.84) => Math.max(minT, Math.min(maxT, tVal));
    
    if (p.type === 'req') {
      if (p.isMitm) {
        // Spoofed packet injected directly at Switch -> travels to Slave
        const sl = state.slaves[p.unitId];
        const t = clampSeg(p.progress, 0.15, 0.85);
        currentPos.x = sw.x + (sl.x - sw.x) * t;
        currentPos.y = sw.y + (sl.y - sw.y) * t;
      } else {
        // Master or Attacker -> Switch -> Slave
        const startNode = (p.srcIp === atk.ip) ? atk : m;
        if (p.progress <= 0.4) {
          const t = clampSeg(p.progress / 0.4, 0.18, 0.82);
          currentPos.x = startNode.x + (sw.x - startNode.x) * t;
          currentPos.y = startNode.y + (sw.y - startNode.y) * t;
        } else {
          const sl = state.slaves[p.unitId];
          const t = clampSeg((p.progress - 0.4) / 0.6, 0.18, 0.82);
          currentPos.x = sw.x + (sl.x - sw.x) * t;
          currentPos.y = sw.y + (sl.y - sw.y) * t;
        }
      }
    } else {
      if (p.isMitmResponse) {
        // MITM response returns to Switch and dissolves/captures
        const sl = state.slaves[p.unitId];
        const t = clampSeg(p.progress, 0.15, 0.85);
        currentPos.x = sl.x + (sw.x - sl.x) * t;
        currentPos.y = sl.y + (sw.y - sl.y) * t;
      } else {
        // Slave -> Switch -> Master or Attacker
        const sl = state.slaves[p.unitId];
        const destNode = (p.destIp === atk.ip) ? atk : m;
        if (p.progress <= 0.6) {
          const t = clampSeg(p.progress / 0.6, 0.18, 0.82);
          currentPos.x = sl.x + (sw.x - sl.x) * t;
          currentPos.y = sl.y + (sw.y - sl.y) * t;
        } else {
          const t = clampSeg((p.progress - 0.6) / 0.4, 0.18, 0.82);
          currentPos.x = sw.x + (destNode.x - sw.x) * t;
          currentPos.y = sw.y + (destNode.y - sw.y) * t;
        }
      }
    }

    p.currentX = currentPos.x;
    p.currentY = currentPos.y;

    const isHovered = hoveredPacket && hoveredPacket.id === p.id;
    const color = p.isAnomaly ? "#f43f5e" : (p.type === 'req' ? "#06b6d4" : "#10b981");
    
    ctx.save();
    ctx.shadowColor = color;
    ctx.shadowBlur = isHovered ? 15 : 6;
    
    ctx.fillStyle = color;
    ctx.strokeStyle = "#090d16";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(currentPos.x - 14, currentPos.y - 8, 28, 16, 4);
    ctx.fill();
    ctx.stroke();
    
    ctx.shadowBlur = 0;
    ctx.fillStyle = "#090d16";
    ctx.font = "bold 8px 'Fira Code'";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(p.type === 'req' ? "REQ" : "RSP", currentPos.x, currentPos.y + 0.5);
    ctx.restore();

    ctx.font = "7px 'Fira Code'";
    ctx.fillStyle = p.isAnomaly ? "#f43f5e" : "#94a3b8";
    ctx.fillText(`TX:${p.txId}`, currentPos.x, currentPos.y - 12);
  });

  // Draw Tooltips / Alerts over Slave nodes
  for (let sId = 1; sId <= 3; sId++) {
    const sl = state.slaves[sId];
    if (sl.alertMsg && Date.now() < sl.alertExpiry) {
      drawNodeAlert(sl.x, sl.y, sl.alertMsg);
    }
  }
}

function drawDeviceNode(x, y, label, ip, deviceState, isMaster, unitId = 0, isAttacker = false, isQuarantined = false) {
  ctx.fillStyle = "#0f172a";
  
  let strokeColor = "#334155";
  if (isQuarantined) strokeColor = "#ef4444";
  else if (deviceState === 'ALARM' || deviceState === 'ATTACK') strokeColor = "#ef4444";
  else if (deviceState === 'BUSY') strokeColor = "#f59e0b";
  else if (isAttacker) strokeColor = "#dc2626";
  
  ctx.strokeStyle = strokeColor;
  ctx.lineWidth = 2;
  
  ctx.save();
  if (isQuarantined) {
    ctx.setLineDash([4, 4]);
  } else if (isAttacker) {
    ctx.setLineDash([3, 3]);
  }
  if (deviceState === 'ALARM' || deviceState === 'ATTACK') {
    ctx.shadowColor = "#ef4444";
    ctx.shadowBlur = 8;
  }
  ctx.beginPath();
  ctx.roundRect(x - 52, y - 28, 104, 56, 6);
  ctx.fill();
  ctx.stroke();
  ctx.restore();

  // Header label
  ctx.font = "bold 9px 'Outfit'";
  ctx.fillStyle = isAttacker ? "#f87171" : "#f1f5f9";
  ctx.textAlign = "center";
  ctx.fillText(label.toUpperCase(), x, y - 12);

  // Icon Graphic
  ctx.font = "14px 'Outfit'";
  let icon = "💾";
  if (isMaster) icon = "💻";
  if (isAttacker) icon = "⚠️";
  ctx.fillText(icon, x - 32, y + 10);

  // Sub-details (IP)
  ctx.font = "8px 'Fira Code'";
  ctx.fillStyle = isAttacker ? "#f87171" : "#94a3b8";
  ctx.fillText(ip, x + 8, y + 4);

  if (isQuarantined) {
    ctx.save();
    ctx.fillStyle = "#450a0a";
    ctx.strokeStyle = "#ef4444";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(x - 22, y + 8, 56, 13, 3);
    ctx.fill();
    ctx.stroke();
    ctx.font = "bold 7.5px 'Fira Code'";
    ctx.fillStyle = "#fca5a5";
    ctx.textAlign = "center";
    ctx.fillText("ISOLATED", x + 6, y + 17.5);
    ctx.restore();
  } else if (!isMaster && !isAttacker) {
    ctx.font = "bold 8px 'Fira Code'";
    ctx.fillStyle = "#2dd4bf";
    ctx.fillText(`UNIT ID: ${toHex8(unitId)}`, x + 8, y + 14);
  } else if (isAttacker) {
    ctx.font = "bold 8px 'Fira Code'";
    ctx.fillStyle = "#ef4444";
    ctx.fillText("ROGUE INTRUDER", x + 8, y + 14);
  }

  // Status LED circle
  ctx.beginPath();
  ctx.arc(x - 34, y - 15, 3.5, 0, Math.PI * 2);
  if (isQuarantined) {
    ctx.fillStyle = "#64748b"; // grey/red
    ctx.strokeStyle = "#ef4444";
    ctx.lineWidth = 2;
    ctx.stroke();
  } else if (deviceState === 'ALARM' || deviceState === 'ATTACK') {
    ctx.fillStyle = "#ef4444";
    ctx.strokeStyle = "rgba(239, 68, 68, 0.4)";
    ctx.lineWidth = 2;
    ctx.stroke();
  } else if (deviceState === 'BUSY') {
    ctx.fillStyle = "#f59e0b";
  } else {
    ctx.fillStyle = isAttacker ? "#ef4444" : "#10b981";
  }
  ctx.fill();
}

function drawNodeAlert(x, y, msg) {
  ctx.save();
  ctx.font = "bold 8px 'Fira Code'";
  const textWidth = ctx.measureText(msg).width;
  const padX = 8;
  const padY = 5;
  
  const widthBox = textWidth + padX * 2;
  const heightBox = 16 + padY * 2;
  
  const boxX = x - widthBox / 2;
  const boxY = y - 62;

  ctx.fillStyle = "#991b1b";
  ctx.strokeStyle = "#f87171";
  ctx.lineWidth = 1;
  
  ctx.beginPath();
  ctx.roundRect(boxX, boxY, widthBox, heightBox, 4);
  ctx.fill();
  ctx.stroke();

  ctx.beginPath();
  ctx.moveTo(x - 5, boxY + heightBox);
  ctx.lineTo(x, boxY + heightBox + 6);
  ctx.lineTo(x + 5, boxY + heightBox);
  ctx.fill();
  ctx.stroke();

  ctx.fillStyle = "#fecdd3";
  ctx.textAlign = "center";
  ctx.fillText(msg, x, boxY + padY + 8);
  ctx.restore();
}

// Animation Tick Loop
function tick(timestamp) {
  // Smoothly update Rogue Node visibility (Feature 6)
  const atk = state.attacker;
  const isAtkVisible = atk.state === "ACTIVE" || !!state.quarantinedNodes[atk.ip] || (atk.visibleUntil && Date.now() < atk.visibleUntil);
  if (isAtkVisible) {
    atk.visibilityAlpha = Math.min(1.0, (atk.visibilityAlpha || 0) + 0.08);
  } else {
    atk.visibilityAlpha = Math.max(0.0, (atk.visibilityAlpha || 0) - 0.03);
  }

  let finishedPackets = [];
  
  state.packets.forEach((p) => {
    if (hoveredPacket && hoveredPacket.id === p.id) {
      return;
    }

    const baseRate = p.stepRate || 0.015;
    const speedMultiplier = (1500 / state.pollingSpeed);
    p.progress += baseRate * speedMultiplier;
    
    if (p.progress >= 1.0) {
      p.progress = 1.0;
      finishedPackets.push(p);
    }
  });

  finishedPackets.forEach(p => {
    state.packets = state.packets.filter(x => x.id !== p.id);
    if (p.callback) p.callback();
  });

  drawTopology();
  animationFrameId = requestAnimationFrame(tick);
}

// Trigger packet delivery
function sendPacket(packetData, onComplete) {
  const packet = {
    id: Math.random().toString(36).slice(2, 9),
    ...packetData,
    progress: 0,
    currentX: 0,
    currentY: 0,
    callback: onComplete
  };
  
  state.packets.push(packet);
  inspectPacket(packet);
}

// Polling Control Functions
let pollingTimerId = null;

function togglePolling() {
  const btnText = document.getElementById('poll-btn-text');
  const btn = document.getElementById('poll-btn');
  const btnIcon = document.getElementById('poll-btn-icon');

  if (state.isPolling) {
    state.isPolling = false;
    clearTimeout(pollingTimerId);
    if (btnText) btnText.innerText = "Start Polling";
    if (btn) btn.className = "flex-1 bg-cyan-600 hover:bg-cyan-500 text-brand-darkest font-bold py-1.5 px-3 rounded text-xs transition duration-150 flex items-center justify-center gap-1.5";
    if (btnIcon) {
      btnIcon.innerHTML = `
        <path stroke-linecap="round" stroke-linejoin="round" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
        <path stroke-linecap="round" stroke-linejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      `;
    }
    logEvent('info', "SCADA automatic polling suspended.");
  } else {
    state.isPolling = true;
    if (btnText) btnText.innerText = "Pause Polling";
    if (btn) btn.className = "flex-1 bg-amber-600 hover:bg-amber-500 text-brand-darkest font-bold py-1.5 px-3 rounded text-xs transition duration-150 flex items-center justify-center gap-1.5";
    if (btnIcon) {
      btnIcon.innerHTML = `
        <path stroke-linecap="round" stroke-linejoin="round" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" />
      `;
    }
    logEvent('info', "SCADA automatic polling started.");
    scheduleNextPoll();
  }
}

function scheduleNextPoll() {
  if (!state.isPolling) return;
  
  pollingTimerId = setTimeout(() => {
    executePollCycle();
  }, state.pollingSpeed);
}

function changePollingSpeed(val) {
  state.pollingSpeed = parseInt(val);
  const speedEl = document.getElementById('speed-val');
  if (speedEl) speedEl.innerText = (val / 1000).toFixed(1) + 's';
}

function toggleAutoAnomaly(chk) {
  state.autoAnomaly = chk.checked;
  logEvent('info', `Automated random anomaly injection ${state.autoAnomaly ? 'ENABLED' : 'DISABLED'}.`);
}

// Execute standard request/response polling
function executePollCycle() {
  const unitId = state.currentPollTarget;
  const fcSelect = document.getElementById('poll-fc-select');
  const fc = fcSelect ? parseInt(fcSelect.value) : 3;
  
  let reqConfig = {
    txId: state.nextTransactionId++,
    unitId: unitId,
    fc: fc,
    addr: 40001,
    qty: 4,
    val: 0,
    writeValues: [1]
  };

  if (state.autoAnomaly && !state.activeAttack && Math.random() < 0.25) {
    const attacks = ['safety', 'range', 'func', 'ip'];
    state.activeAttack = attacks[Math.floor(Math.random() * attacks.length)];
  }

  if (state.activeAttack) {
    const attack = state.activeAttack;
    state.activeAttack = null;
    triggerAttackPayload(attack, reqConfig);
    return;
  }

  dispatchRequest(reqConfig);
  state.currentPollTarget = (state.currentPollTarget % 3) + 1;
}

// Compile and launch Modbus TCP frame request on the wire
function dispatchRequest(config) {
  const isAnomaly = !!config.isAnomaly;
  const requestFrame = createModbusFrame(config);
  
  if (isAnomaly) {
    logEvent('anomaly', `Attack Transmitted: ${config.anomalyText || 'Anomaly Injection'}`, 
             `TX:${config.txId} | IP:${requestFrame.srcIp} | Length:${requestFrame.rawBytes.length} Bytes | Payload:${requestFrame.rawBytes.slice(7).join(" ")}`,
             config.detectionLayer);
  } else {
    logEvent('tx', `Transmitting Modbus Request: FC 0${config.fc} (${getFcName(config.fc)}) to Slave ID 0${config.unitId}`, 
             `TX:${config.txId} | IP:${requestFrame.srcIp} | Length:${requestFrame.rawBytes.length} Bytes | Payload:${requestFrame.rawBytes.slice(7).join(" ")}`);
  }

  if (config.customSrcIp !== state.attacker.ip) {
    updateFsm('sent');
  }

  const targetSlave = state.slaves[config.unitId];
  if (targetSlave) {
    targetSlave.pulseTimer = 0.5;
    targetSlave.state = isAnomaly ? 'ALARM' : 'BUSY';
    
    const opType = (config.fc === 3) ? 'read' : 'write';
    const startAddr = config.addr;
    const count = (config.fc === 16) ? config.writeValues.length : (config.fc === 6 ? 1 : config.qty);
    
    for (let i = 0; i < count; i++) {
      targetSlave.flashRegisters[startAddr + i] = isAnomaly ? 'anomaly' : opType;
    }
    renderRegisters();
  }

  sendPacket({
    type: 'req',
    txId: config.txId,
    unitId: config.unitId,
    isAnomaly: isAnomaly,
    srcIp: requestFrame.srcIp,
    destIp: requestFrame.destIp,
    rawBytes: requestFrame.rawBytes,
    bytesDef: requestFrame.bytesDef,
    fc: config.fc,
    isMitm: config.isMitm || false
  }, () => {
    handleSlaveRequestArrival(config, requestFrame);
  });
}

// Handler when packet arrives at Slave PLC
function handleSlaveRequestArrival(reqConfig, requestFrame) {
  const slave = state.slaves[reqConfig.unitId];
  let hasException = false;
  let exceptionCode = 0;
  
  if (reqConfig.customSrcIp !== state.attacker.ip && !requestFrame.isMitm) {
    updateFsm('await');
  }

  if (requestFrame.isAnomaly) {
    if (!reqConfig._alarmRecorded) {
      recordAlarm({
        attackName: reqConfig.attackName || "Security Anomaly",
        reason: requestFrame.anomalyText || "Unauthorized Modbus activity detected.",
        layer: reqConfig.detectionLayer || "Rule-based",
        severity: reqConfig.severity || "MEDIUM",
        sourceIp: requestFrame.srcIp
      });
      reqConfig._alarmRecorded = true;
    }
    
    slave.state = 'ALARM';
    slave.alertMsg = requestFrame.anomalyText;
    slave.alertExpiry = Date.now() + 4500;
    
    if (reqConfig.fc === 0x99) {
      hasException = true;
      exceptionCode = 1;
    }
  }

  if (!hasException) {
    if (reqConfig.fc === 6) {
      slave.registers[reqConfig.addr].val = reqConfig.val;
    } else if (reqConfig.fc === 16) {
      reqConfig.writeValues.forEach((v, index) => {
        if (slave.registers[reqConfig.addr + index]) {
          slave.registers[reqConfig.addr + index].val = v;
        }
      });
    }
  }

  renderRegisters();

  const responseFrame = createResponseFrame(requestFrame, hasException, exceptionCode);
  
  setTimeout(() => {
    const logType = hasException ? 'exception' : 'rx';
    const summary = hasException 
      ? `Modbus Exception Response Code 0${exceptionCode} (Error) from Slave ID 0${reqConfig.unitId}`
      : `Receiving Modbus Response: FC 0${reqConfig.fc} from Slave ID 0${reqConfig.unitId}`;
      
    logEvent(logType, summary, 
             `TX:${reqConfig.txId} | IP:${responseFrame.srcIp} | Length:${responseFrame.rawBytes.length} Bytes | Payload:${responseFrame.rawBytes.slice(7).join(" ")}`);

    sendPacket({
      type: 'res',
      txId: reqConfig.txId,
      unitId: reqConfig.unitId,
      isAnomaly: requestFrame.isAnomaly,
      srcIp: responseFrame.srcIp,
      destIp: responseFrame.destIp,
      rawBytes: responseFrame.rawBytes,
      bytesDef: responseFrame.bytesDef,
      fc: reqConfig.fc,
      isMitmResponse: reqConfig.isMitm || false
    }, () => {
      handleResponseArrival(reqConfig.unitId);
    });
  }, 300);
}

function handleResponseArrival(unitId) {
  const slave = state.slaves[unitId];
  if (slave) {
    setTimeout(() => {
      slave.flashRegisters = {};
      if (slave.state === 'BUSY') slave.state = 'OK';
      renderRegisters();
    }, 1200);
  }
  
  updateFsm('done');
  setTimeout(() => {
    const activeReqs = state.packets.filter(p => p.type === 'req');
    if (activeReqs.length === 0) {
      updateFsm('idle');
    }
  }, 1000);
  
  scheduleNextPoll();
}

// Toggle custom input fields in panel based on function code
function toggleCustomDataFields(fc) {
  const dataLabel = document.getElementById('custom-data-label');
  const dataInput = document.getElementById('custom-data');
  if (!dataLabel || !dataInput) return;
  
  if (fc === '03') {
    dataLabel.innerText = "Quantity";
    dataInput.min = 1;
    dataInput.max = 8;
    dataInput.value = 4;
  } else if (fc === '06') {
    dataLabel.innerText = "Value";
    dataInput.min = 0;
    dataInput.max = 65535;
    dataInput.value = 100;
  } else if (fc === '10') {
    dataLabel.innerText = "Values (CSV)";
    dataInput.value = "100, 200, 300";
    dataInput.type = "text";
    return;
  }
  dataInput.type = "number";
}

// Custom packet sender form handler
function sendCustomRequest() {
  const sIdEl = document.getElementById('custom-slave-id');
  const fcEl = document.getElementById('custom-fc');
  const regEl = document.getElementById('custom-reg');
  const dataEl = document.getElementById('custom-data');
  if (!sIdEl || !fcEl || !regEl || !dataEl) return;

  const sId = parseInt(sIdEl.value);
  const fc = parseInt(fcEl.value);
  const reg = parseInt(regEl.value);
  const dataVal = dataEl.value;
  
  let config = {
    txId: state.nextTransactionId++,
    unitId: sId,
    fc: fc,
    addr: reg,
    isAnomaly: false
  };

  if (fc === 3) {
    config.qty = parseInt(dataVal) || 1;
  } else if (fc === 6) {
    config.val = parseInt(dataVal) || 0;
  } else if (fc === 16) {
    config.writeValues = dataVal.split(",").map(v => parseInt(v.trim()) || 0);
  }

  // Security baseline triggers for manual packet sender
  if (sId === 1 && fc === 6 && reg === 40004 && config.val === 0) {
    config.isAnomaly = true;
    config.anomalyText = "⚠ Unauthorized write — register outside baseline range.";
    config.detectionLayer = "Rule-based";
  }
  if (sId === 2 && fc === 6 && reg === 40002 && config.val > 3000) {
    config.isAnomaly = true;
    config.anomalyText = "⚠ Unauthorized write — register outside baseline range.";
    config.detectionLayer = "Rule-based";
  }

  const wasPolling = state.isPolling;
  if (wasPolling) togglePolling();

  dispatchRequest(config);
  
  if (wasPolling) {
    setTimeout(() => {
      togglePolling();
    }, 3000);
  }
}

// Global Initialization
window.onload = () => {
  initCanvas();
  
  // Start physical coupled telemetry loop
  setInterval(runPhysicsSimulation, 1000);
  
  // Initial Event Logs
  logEvent('info', "ICS Security Monitoring Active. Firewall configured.");
  logEvent('info', "Modbus TCP Baseline Profile loaded. Checking network adapters...");
  logEvent('info', "HMI SCADA Master connected at IP 10.0.0.10");
  logEvent('info', "Slave PLCs online: Unit 1 (10.0.0.11), Unit 2 (10.0.0.12), Unit 3 (10.0.0.13)");
  logEvent('info', "IDS FSM Auditor online. Monitoring state transitions...");
  
  // Initial UI Component Renders
  renderRegisters();
  showAttackDetails('safety');
  updateFsm('idle');
  
  // Start Animation Loop
  tick();
  
  // Start Polling Loop
  togglePolling();
};
