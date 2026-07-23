const state = { socket: null, map: null, markers: [], focused: false, currentTab: "operations" };

const threatClass = (level) => ({ CRITICAL: "critical", RED: "red", YELLOW: "amber" })[(level || "GREEN").toUpperCase()] || "green";
const setText = (id, value) => { const node = document.getElementById(id); if (node) node.textContent = value; };
const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);

function activateTab(tab) {
  state.currentTab = tab;
  document.querySelectorAll(".command-tab").forEach((node) => node.classList.toggle("active", node.dataset.tab === tab));
  document.querySelectorAll(".command-view").forEach((node) => node.classList.toggle("active", node.dataset.view === tab));
  if (tab === "map" && state.map) setTimeout(() => state.map.resize(), 40);
}

function buildAlertCard(alert) { return `<article class="stack-item"><span>${escapeHtml(alert.created_at)}</span><strong>${escapeHtml(alert.threat_title)}</strong><p>${escapeHtml(alert.threat_details)}</p><div class="chip ${threatClass(alert.threat_level)}">${escapeHtml(alert.threat_level)}</div></article>`; }
function buildDeviceCard(device) { return `<article class="stack-item"><span>${escapeHtml(device.connection_mode)}</span><strong>${escapeHtml(device.device_name)}</strong><p>${escapeHtml(device.ip_address || "Unknown IP")} · ${escapeHtml(device.status)}<br>last seen ${escapeHtml(device.last_seen_at)}</p></article>`; }
function buildIncidentRow(incident) { return `<article class="incident-row"><div><strong>${escapeHtml(incident.incident_code)}</strong><div class="meta">${escapeHtml(incident.created_at)}</div></div><div><strong>${escapeHtml(incident.threat_title)}</strong><div class="meta">${escapeHtml(incident.threat_details)}</div></div><div>${escapeHtml(incident.object_type).toUpperCase()}</div><div>${escapeHtml(incident.sector)}</div><div><span class="chip ${threatClass(incident.threat_level)}">${escapeHtml(incident.threat_level)}</span></div></article>`; }
function buildEvidenceCard(incident) { const image = incident.screenshot_path ? `<img src="${encodeURI(incident.screenshot_path)}" alt="Evidence for ${escapeHtml(incident.incident_code)}" />` : ""; return `<article class="evidence-card"><span>${escapeHtml(incident.object_type).toUpperCase()} · ${escapeHtml(incident.sector)}</span><strong>${escapeHtml(incident.threat_title)}</strong><p>${escapeHtml(incident.plate_number || incident.person_name || incident.identity_result)}</p>${image}</article>`; }

function initializeMap() {
  const key = window.DRONEGUARD_MAPTILER_KEY;
  const message = document.getElementById("map-message");
  if (!key) { message.textContent = "Map key not configured. Set DRONEGUARD_MAPTILER_KEY before starting the local server."; return; }
  if (!window.maplibregl) { message.textContent = "Map renderer could not be loaded."; return; }
  state.map = new maplibregl.Map({ container: "incident-map", style: `https://api.maptiler.com/maps/toner-v2/style.json?key=${encodeURIComponent(key)}`, center: [44.3661, 33.3152], zoom: 10, attributionControl: true });
  state.map.addControl(new maplibregl.NavigationControl(), "top-right");
  state.map.on("load", () => { setText("map-status", "Toner live"); message.textContent = "High-contrast pins show recorded field-terminal GPS positions."; });
  state.map.on("error", () => { message.textContent = "Map tiles unavailable. Check your MapTiler key and allowed domains."; });
}

function renderIncidentMap(incidents) {
  const located = incidents.filter((item) => Number.isFinite(item.latitude) && Number.isFinite(item.longitude));
  setText("map-dot-count", located.length);
  if (!state.map) return;
  state.markers.forEach((marker) => marker.remove()); state.markers = [];
  const bounds = new maplibregl.LngLatBounds();
  located.forEach((incident) => {
    const pin = document.createElement("button"); pin.className = `map-marker ${threatClass(incident.threat_level)}`; pin.title = incident.threat_title || "Incident";
    const popup = `<strong>${escapeHtml(incident.threat_title)}</strong><br><span>${escapeHtml(incident.object_type).toUpperCase()} · ${escapeHtml(incident.threat_level)}</span><br><span>${escapeHtml(incident.location_summary || "GPS position")}</span><br><span>${escapeHtml(incident.created_at)}</span>`;
    state.markers.push(new maplibregl.Marker({ element: pin }).setLngLat([incident.longitude, incident.latitude]).setPopup(new maplibregl.Popup({ offset: 18 }).setHTML(popup)).addTo(state.map));
    bounds.extend([incident.longitude, incident.latitude]);
  });
  if (located.length && !state.focused) { state.map.fitBounds(bounds, { padding: 90, maxZoom: 15, duration: 700 }); state.focused = true; }
  if (!located.length) setText("map-status", "Awaiting GPS");
}

function renderSnapshot(snapshot) {
  setText("command-status", snapshot.command_center.status); setText("top-threat", snapshot.command_center.top_threat); setText("night-mode", snapshot.command_center.night_mode_enabled ? "ACTIVE" : "STANDBY");
  setText("metric-alerts", snapshot.summary.active_alerts); setText("metric-devices", snapshot.summary.connected_devices); setText("metric-incidents", snapshot.summary.incidents_today); setText("metric-authorized", snapshot.summary.authorized_events);
  document.getElementById("alerts-list").innerHTML = snapshot.active_alerts.length ? snapshot.active_alerts.map(buildAlertCard).join("") : `<article class="stack-item"><strong>No active alerts</strong><p>The perimeter is currently stable.</p></article>`;
  document.getElementById("devices-list").innerHTML = snapshot.devices.length ? snapshot.devices.map(buildDeviceCard).join("") : `<article class="stack-item"><strong>No field terminals</strong><p>Awaiting Android device registration.</p></article>`;
  document.getElementById("incidents-table").innerHTML = snapshot.incidents.length ? snapshot.incidents.map(buildIncidentRow).join("") : `<article class="stack-item"><strong>No incidents recorded</strong><p>The archive is empty.</p></article>`;
  document.getElementById("evidence-viewer").innerHTML = snapshot.incidents.length ? snapshot.incidents.slice(0, 12).map(buildEvidenceCard).join("") : `<article class="evidence-card"><strong>No evidence captured</strong><p>Field screenshots will appear here.</p></article>`;
  renderIncidentMap(snapshot.incidents);
  const latest = snapshot.incidents[0]; const image = document.getElementById("live-feed-image");
  if (latest) { setText("feed-sector", latest.sector); setText("live-feed-title", latest.threat_title); setText("live-feed-threat", latest.threat_level); document.getElementById("live-feed-threat").className = `chip ${threatClass(latest.threat_level)}`; if (latest.screenshot_path) { image.src = latest.screenshot_path; image.style.visibility = "visible"; } else { image.removeAttribute("src"); image.style.visibility = "hidden"; } }
}

async function loadSnapshot() { try { const response = await fetch("/api/dashboard/snapshot"); renderSnapshot(await response.json()); } catch (_) { setText("command-status", "RECONNECTING"); } }
function connectSocket() { const protocol = location.protocol === "https:" ? "wss" : "ws"; state.socket = new WebSocket(`${protocol}://${location.host}/ws/dashboard`); state.socket.onmessage = (event) => renderSnapshot(JSON.parse(event.data)); state.socket.onclose = () => setTimeout(connectSocket, 1500); }
document.querySelectorAll(".command-tab").forEach((button) => button.addEventListener("click", () => activateTab(button.dataset.tab)));
initializeMap(); loadSnapshot(); connectSocket(); setInterval(loadSnapshot, 7000);
