const state = {
  overview: null,
  artifacts: null,
  candidates: null,
  activeSessionId: null,
  refreshing: false,
};

const displayTimeZone = "Etc/GMT-2";
const displayTimeZoneLabel = "UTC+2";

const eventCodes = {
  connection_opened: "CO",
  client_fingerprint: "FP",
  login_attempt: "AU",
  shell_opened: "SH",
  command_input: "CM",
  command_failed: "CF",
  command_output: "OU",
  file_download_requested: "DL",
  artifact_captured: "AR",
  connection_closed: "CL",
};

const fieldLabels = {
  protocol: "Protokół",
  client_version: "Klient",
  hassh: "HASSH",
  hassh_algorithms: "Algorytmy HASSH",
  kex_algorithms: "Wymiana kluczy",
  host_key_algorithms: "Klucz hosta",
  encryption_algorithms: "Szyfrowanie",
  mac_algorithms: "MAC",
  compression_algorithms: "Kompresja",
  username: "Użytkownik",
  auth_method: "Metoda",
  success: "Wynik",
  terminal: "Terminal",
  command: "Komenda",
  stdout: "Standardowe wyjście",
  stderr: "Standardowy błąd",
  exit_code: "Kod zakończenia",
  emulated: "Emulacja",
  url: "Adres URL",
  tool: "Narzędzie",
  outcome: "Rezultat",
  destination_filename: "Plik docelowy",
  phase: "Etap transferu",
  execution_intended: "Zamiar wykonania",
  cleanup_intended: "Zamiar usunięcia śladów",
  sha256: "SHA-256",
  size_bytes: "Rozmiar",
  media_type: "Typ pliku",
  filename: "Nazwa pliku",
  origin: "Pochodzenie",
  role: "Rola",
  capture_status: "Stan przechwycenia",
  reason: "Powód",
  duration_ms: "Czas [ms]",
};

const confidenceLabels = {
  low: "niska",
  medium: "średnia",
  high: "wysoka",
};

const chainStatusLabels = {
  observed: "zaobserwowano",
  attempted: "próba",
  contained: "powstrzymano",
  unknown: "wynik nieznany",
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatDate(value) {
  return new Intl.DateTimeFormat("pl-PL", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: displayTimeZone,
  }).format(new Date(value));
}

function formatTime(value) {
  return new Intl.DateTimeFormat("pl-PL", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: displayTimeZone,
  }).format(new Date(value));
}

function formatDuration(seconds) {
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} min ${seconds % 60} s`;
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return "rozmiar nieznany";
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 ** 2).toFixed(1)} MiB`;
}

function signalCount(value) {
  if (value === 1) return "1 sygnał";
  if (value >= 2 && value <= 4) return `${value} sygnały`;
  return `${value} sygnałów`;
}

function polishCount(value, singular, paucal, plural) {
  if (value === 1) return `${value} ${singular}`;
  const lastTwo = value % 100;
  const last = value % 10;
  if (last >= 2 && last <= 4 && !(lastTwo >= 12 && lastTwo <= 14)) {
    return `${value} ${paucal}`;
  }
  return `${value} ${plural}`;
}

function readableValue(field, value) {
  if (field === "success") return value ? "powodzenie" : "niepowodzenie";
  if (field === "size_bytes") return `${value} B`;
  if (field === "outcome") {
    return {
      succeeded: "pobrano i przechwycono",
      failed: "niepowodzenie",
      emulated: "bezpiecznie zasymulowano — bez pobrania",
      unknown: "wynik nieznany",
    }[value] || String(value);
  }
  if (field === "phase") return value === "fallback" ? "fallback" : "pierwsza próba";
  if (field === "execution_intended" || field === "cleanup_intended") {
    return value ? "tak" : "nie";
  }
  if (field === "capture_status") {
    return {
      complete: "kompletny",
      empty_upload: "pusty upload",
      incomplete_transfer: "niedokończony transfer",
      unknown: "stan nieznany",
    }[value] || String(value);
  }
  return String(value);
}

function geoLocationLabel(geo) {
  if (!geo) return "GeoIP: baza lokalna niepodłączona lub brak dopasowania";
  const country = geo.country_name || (
    geo.country_code
      ? new Intl.DisplayNames(["pl"], { type: "region" }).of(geo.country_code)
      : null
  );
  const location = [geo.city, geo.subdivision, country]
    .filter(Boolean)
    .filter((value, index, values) => values.indexOf(value) === index)
    .join(", ");
  const network = [geo.asn ? `AS${geo.asn}` : null, geo.organization]
    .filter(Boolean)
    .join(" · ");
  return [location || "lokalizacja nieznana", network || null].filter(Boolean).join(" · ");
}

function sessionGeoLabel(geo) {
  if (!geo) return "";
  return [geo.country_code, geo.asn ? `AS${geo.asn}` : null].filter(Boolean).join(" · ");
}

function analyticalReading(session) {
  const types = new Set(session.timeline.map((event) => event.event_type));
  const detectionTypes = new Set(session.detections.map((detection) => detection.category));
  const command = session.timeline.find((event) => event.event_type === "command_input")?.data
    ?.command;
  if (detectionTypes.has("honeypot_probe")) {
    return "Źródło nie ograniczyło się do zwykłego rekonesansu. Sprawdzało ślady emulacji lub konteneryzacji, co może oznaczać próbę rozpoznania honeypota. Detekcja pokazuje wykorzystane polecenia, ale nie przesądza, czy test był skuteczny.";
  }
  const meaningfulArtifact = session.timeline.some(
    (event) => event.event_type === "artifact_captured"
      && !["empty_upload", "incomplete_transfer"].includes(event.data.capture_status),
  );
  if (meaningfulArtifact) {
    return "Po uzyskaniu interakcji źródło pozostawiło artefakt. Sensor zachował jego metadane; plik nie został uruchomiony. To najsilniejszy sygnał w tej sesji.";
  }
  if (types.has("file_download_requested")) {
    const detail = command ? ` Wcześniej obserwowano komendę „${command}”.` : "";
    return `Źródło przeszło od kontaktu z usługą do próby pobrania pliku.${detail} Sam ślad nie przesądza o skutecznym przejęciu ani o pochodzeniu operatora.`;
  }
  if (types.has("command_input")) {
    return "Sesja wykroczyła poza automatyczne logowanie: sensor zarejestrował interaktywne polecenie. Wymaga ono dalszej klasyfikacji zachowania.";
  }
  return "Sesja obejmuje kontakt z usługą i próbę dostępu. Na tym etapie wygląda jak obserwacja lub automatyczne skanowanie, bez śladu wykonania komend.";
}

function renderStats(overview) {
  const formatMetric = (value) => new Intl.NumberFormat("pl-PL").format(value ?? 0);
  document.querySelector("#stat-sessions").textContent = formatMetric(overview.session_count);
  document.querySelector("#stat-events").textContent = formatMetric(overview.event_count);
  document.querySelector("#stat-sensors").textContent = formatMetric(overview.sensor_count);
  document.querySelector("#stat-commands").textContent = formatMetric(overview.command_count);
  document.querySelector("#session-count").textContent = formatMetric(overview.session_count);
  document.querySelector("#stat-events-note").textContent = overview.truncated
    ? `${formatMetric(overview.analyzed_event_count)} ostatnich wpisów w analizie`
    : "zwalidowane wpisy w pełnym oknie";
}

function renderSessions(sessions) {
  const list = document.querySelector("#session-list");
  if (!sessions.length) {
    list.innerHTML = '<p class="session-source">Brak sesji. Zaimportuj fixture lub log Cowrie.</p>';
    return;
  }
  list.innerHTML = sessions
    .map(
      (session) => `
        <button
          class="session-item"
          type="button"
          data-session-id="${escapeHtml(session.session_id)}"
          aria-current="${session.session_id === state.activeSessionId}"
        >
          <span class="session-topline">
            <span class="session-id">${escapeHtml(session.session_id)}</span>
            <span class="risk-chip" data-level="${escapeHtml(session.risk.level)}">
              ${escapeHtml(session.risk.score)}/100
            </span>
          </span>
          <span class="session-source">${escapeHtml(session.source)}</span>
          ${session.geo ? `<span class="session-location">${escapeHtml(sessionGeoLabel(session.geo))}</span>` : ""}
          <span class="session-meta">
            <span>${escapeHtml(formatDate(session.started_at))} ${displayTimeZoneLabel}</span>
            <span>${escapeHtml(session.event_count)} zd.</span>
            <span>${escapeHtml(session.detection_count)} det.</span>
          </span>
        </button>
      `,
    )
    .join("");

  list.querySelectorAll(".session-item").forEach((button) => {
    button.addEventListener("click", () => selectSession(button.dataset.sessionId));
  });
}

function renderArtifacts(queue) {
  const list = document.querySelector("#artifact-list");
  document.querySelector("#artifact-count").textContent = queue.artifact_count;
  if (!queue.artifacts.length) {
    list.innerHTML = `
      <div class="artifact-empty">
        Brak metadanych przechwyconych artefaktów. Kolejka pozostaje gotowa.
      </div>
    `;
    return;
  }
  list.innerHTML = queue.artifacts
    .map((artifact) => {
      const filename = artifact.filenames[0] || "nazwa nieznana";
      const size = artifact.sizes_bytes.length
        ? artifact.sizes_bytes.map(formatBytes).join(" / ")
        : "rozmiar nieznany";
      const context = [...artifact.origins, ...artifact.roles].filter(Boolean).join(" · ");
      const isEmpty = artifact.workflow_state === "empty_upload";
      return `
        <article class="artifact-card">
          <div class="artifact-card-topline">
            <span class="artifact-state">${isEmpty ? "empty upload" : "metadata only"}</span>
            <time datetime="${escapeHtml(artifact.last_seen)}">
              ${escapeHtml(formatDate(artifact.last_seen))} ${displayTimeZoneLabel}
            </time>
          </div>
          <h3>${escapeHtml(isEmpty ? `${filename} — pusty transfer` : filename)}</h3>
          <code class="artifact-hash" title="${escapeHtml(artifact.sha256)}">
            ${escapeHtml(artifact.sha256)}
          </code>
          <div class="artifact-facts">
            <span>${escapeHtml(size)}</span>
            <span>${escapeHtml(polishCount(artifact.observation_count, "obserwacja", "obserwacje", "obserwacji"))}</span>
            <span>${escapeHtml(polishCount(artifact.session_count, "sesja", "sesje", "sesji"))}</span>
            ${context ? `<span>${escapeHtml(context)}</span>` : ""}
          </div>
          <button
            class="manifest-button"
            type="button"
            data-artifact-id="${escapeHtml(artifact.artifact_id)}"
            data-sha256="${escapeHtml(artifact.sha256)}"
          >
            Eksportuj manifest <span aria-hidden="true">↗</span>
          </button>
        </article>
      `;
    })
    .join("");

  list.querySelectorAll(".manifest-button").forEach((button) => {
    button.addEventListener("click", () => downloadArtifactManifest(button));
  });
}

function renderCandidates(queue) {
  const list = document.querySelector("#candidate-list");
  document.querySelector("#candidate-count").textContent = queue.candidate_count;
  if (!queue.candidates.length) {
    list.innerHTML = `
      <div class="artifact-empty">
        Brak zarejestrowanych prób zdalnego pobrania. Intake pozostaje aktywny.
      </div>
    `;
    return;
  }
  list.innerHTML = queue.candidates
    .map((candidate) => {
      const filename = candidate.destination_filenames[0] || "nazwa docelowa nieznana";
      const context = [...candidate.schemes, ...candidate.tools, ...candidate.outcomes]
        .filter(Boolean)
        .join(" · ");
      return `
        <article class="artifact-card candidate-card">
          <div class="artifact-card-topline">
            <span class="artifact-state candidate-state">fetcher disabled</span>
            <time datetime="${escapeHtml(candidate.last_seen)}">
              ${escapeHtml(formatDate(candidate.last_seen))} ${displayTimeZoneLabel}
            </time>
          </div>
          <h3>${escapeHtml(filename)}</h3>
          <code class="artifact-hash" title="${escapeHtml(candidate.candidate_id)}">
            ${escapeHtml(candidate.candidate_id)}
          </code>
          <div class="artifact-facts">
            <span>${escapeHtml(polishCount(candidate.observation_count, "obserwacja", "obserwacje", "obserwacji"))}</span>
            <span>${escapeHtml(polishCount(candidate.session_count, "sesja", "sesje", "sesji"))}</span>
            ${context ? `<span>${escapeHtml(context)}</span>` : ""}
          </div>
          <button
            class="manifest-button candidate-manifest-button"
            type="button"
            data-candidate-id="${escapeHtml(candidate.candidate_id)}"
          >
            Eksportuj kartę decyzji <span aria-hidden="true">↗</span>
          </button>
        </article>
      `;
    })
    .join("");

  list.querySelectorAll(".candidate-manifest-button").forEach((button) => {
    button.addEventListener("click", () => downloadCandidateManifest(button));
  });
}

async function downloadCandidateManifest(button) {
  const original = button.innerHTML;
  button.disabled = true;
  button.textContent = "Tworzenie karty…";
  try {
    const candidateId = button.dataset.candidateId;
    const response = await fetch(
      `/api/dashboard/acquisition-candidates/${encodeURIComponent(candidateId)}/manifest`,
    );
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const manifest = await response.json();
    const blob = new Blob([`${JSON.stringify(manifest, null, 2)}\n`], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `honeynet-candidate-${candidateId.slice(-16)}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    button.textContent = "Karta zapisana";
  } catch (error) {
    console.error(error);
    button.textContent = "Eksport nieudany";
  } finally {
    setTimeout(() => {
      button.disabled = false;
      button.innerHTML = original;
    }, 1800);
  }
}

async function downloadArtifactManifest(button) {
  const original = button.innerHTML;
  button.disabled = true;
  button.textContent = "Tworzenie manifestu…";
  try {
    const artifactId = button.dataset.artifactId;
    const response = await fetch(
      `/api/dashboard/artifacts/${encodeURIComponent(artifactId)}/manifest`,
    );
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const manifest = await response.json();
    const blob = new Blob([`${JSON.stringify(manifest, null, 2)}\n`], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `honeynet-metadata-${button.dataset.sha256.slice(0, 16)}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    button.textContent = "Manifest zapisany";
  } catch (error) {
    console.error(error);
    button.textContent = "Eksport nieudany";
  } finally {
    setTimeout(() => {
      button.disabled = false;
      button.innerHTML = original;
    }, 1800);
  }
}

function renderDetections(detections) {
  const list = document.querySelector("#detection-list");
  document.querySelector("#detection-count").textContent = signalCount(detections.length);
  if (!detections.length) {
    list.innerHTML = `
      <div class="detection-empty">
        Brak dopasowania do obecnego zestawu reguł. Nie oznacza to braku zagrożenia.
      </div>
    `;
    return;
  }
  list.innerHTML = detections
    .map(
      (detection) => `
        <article class="detection-card" data-severity="${escapeHtml(detection.severity)}">
          <div class="detection-topline">
            <span class="detection-category">${escapeHtml(detection.category)}</span>
            <span class="detection-confidence">pewność: ${escapeHtml(confidenceLabels[detection.confidence] || detection.confidence)}</span>
          </div>
          <h4>${escapeHtml(detection.title)}</h4>
          <p>${escapeHtml(detection.summary)}</p>
          <div class="detection-evidence">
            ${detection.evidence
              .map(
                (item) => `
                  <div>
                    <time datetime="${escapeHtml(item.timestamp)}">${escapeHtml(formatTime(item.timestamp))}</time>
                    <code>${escapeHtml(item.value)}</code>
                  </div>
                `,
              )
              .join("")}
          </div>
        </article>
      `,
    )
    .join("");
}

function renderAttackChain(stages) {
  const list = document.querySelector("#attack-chain-list");
  document.querySelector("#attack-chain-count").textContent = `${stages.length} etapów`;
  if (!stages.length) {
    list.innerHTML = `
      <div class="chain-empty">
        Za mało dowodów, aby zrekonstruować kolejne etapy tej sesji.
      </div>
    `;
    return;
  }
  list.innerHTML = stages
    .map(
      (stage, index) => `
        <article class="chain-stage" data-status="${escapeHtml(stage.status)}">
          <div class="chain-index">${String(index + 1).padStart(2, "0")}</div>
          <div class="chain-copy">
            <div class="chain-topline">
              <span>${escapeHtml(stage.category)}</span>
              <strong>${escapeHtml(chainStatusLabels[stage.status] || stage.status)}</strong>
            </div>
            <h4>${escapeHtml(stage.title)}</h4>
            <p>${escapeHtml(stage.summary)}</p>
            <small>pewność: ${escapeHtml(confidenceLabels[stage.confidence] || stage.confidence)}</small>
          </div>
        </article>
      `,
    )
    .join("");
}

function renderTimeline(events) {
  const timeline = document.querySelector("#timeline");
  timeline.innerHTML = events
    .map((event) => {
      const evidence = Object.entries(event.data)
        .map(
          ([field, value]) => `
            <div class="evidence-row">
              <span>${escapeHtml(fieldLabels[field] || field)}</span>
              <code>${escapeHtml(readableValue(field, value))}</code>
            </div>
          `,
        )
        .join("");
      return `
        <li class="timeline-event" data-type="${escapeHtml(event.event_type)}">
          <time class="event-time" datetime="${escapeHtml(event.timestamp)}">
            ${escapeHtml(formatTime(event.timestamp))}
          </time>
          <span class="event-node" aria-hidden="true">
            ${escapeHtml(eventCodes[event.event_type] || "EV")}
          </span>
          <div class="event-body">
            <h4>${escapeHtml(event.title)}</h4>
            <p>${escapeHtml(event.description)}</p>
            ${evidence ? `<div class="evidence-grid">${evidence}</div>` : ""}
          </div>
        </li>
      `;
    })
    .join("");
}

function renderCase(session) {
  document.querySelector("#case-title").textContent = session.session_id;
  document.querySelector("#case-source").textContent = `Źródło: ${session.source}`;
  document.querySelector("#case-geo").textContent = geoLocationLabel(session.geo);
  document.querySelector("#case-sensor").textContent = session.sensor_id;
  document.querySelector("#case-start").textContent = `${formatDate(session.started_at)} ${displayTimeZoneLabel}`;
  document.querySelector("#case-duration").textContent = formatDuration(session.duration_seconds);
  document.querySelector("#case-events").textContent = session.event_count;
  document.querySelector("#risk-score").textContent = session.risk.score;
  document.querySelector("#risk-label").textContent = session.risk.label;
  document.querySelector("#risk-stamp").dataset.level = session.risk.level;
  document.querySelector("#case-reading").textContent = analyticalReading(session);
  renderAttackChain(session.attack_chain || []);
  renderDetections(session.detections);
  renderTimeline(session.timeline);
}

function setCaseState(nextState) {
  document.querySelector("#case-loading").hidden = nextState !== "loading";
  document.querySelector("#case-content").hidden = nextState !== "ready";
  document.querySelector("#case-error").hidden = nextState !== "error";
}

function updateSyncStatus(mode) {
  const element = document.querySelector("#sync-status");
  element.dataset.state = mode;
  if (mode === "loading") {
    element.textContent = "synchronizacja…";
  } else if (mode === "error") {
    element.textContent = "brak synchronizacji";
  } else {
    element.textContent = `na żywo · ${formatTime(new Date().toISOString())}`;
  }
}

async function selectSession(sessionId, options = {}) {
  if (!sessionId) return;
  const { showLoading = true, updateUrl = true } = options;
  state.activeSessionId = sessionId;
  renderSessions(state.overview.sessions);
  if (showLoading) setCaseState("loading");
  try {
    const response = await fetch(`/api/dashboard/sessions/${encodeURIComponent(sessionId)}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const session = await response.json();
    renderCase(session);
    setCaseState("ready");
    if (updateUrl) history.replaceState(null, "", `/#${encodeURIComponent(sessionId)}`);
  } catch (error) {
    console.error(error);
    if (showLoading) setCaseState("error");
  }
}

async function loadDashboard(options = {}) {
  const { silent = false } = options;
  if (state.refreshing) return;
  state.refreshing = true;
  if (!silent) document.querySelector("#refresh-button").disabled = true;
  updateSyncStatus("loading");
  try {
    const [overviewResponse, artifactsResponse, candidatesResponse] = await Promise.all([
      fetch("/api/dashboard/overview"),
      fetch("/api/dashboard/artifacts"),
      fetch("/api/dashboard/acquisition-candidates"),
    ]);
    if (!overviewResponse.ok) throw new Error(`Overview HTTP ${overviewResponse.status}`);
    if (!artifactsResponse.ok) throw new Error(`Artifacts HTTP ${artifactsResponse.status}`);
    if (!candidatesResponse.ok) throw new Error(`Candidates HTTP ${candidatesResponse.status}`);
    state.overview = await overviewResponse.json();
    state.artifacts = await artifactsResponse.json();
    state.candidates = await candidatesResponse.json();
    renderStats(state.overview);
    renderArtifacts(state.artifacts);
    renderCandidates(state.candidates);
    const hashSession = decodeURIComponent(location.hash.slice(1));
    const preferred = state.overview.sessions.find(
      (session) => session.session_id === hashSession,
    );
    const active = state.overview.sessions.find(
      (session) => session.session_id === state.activeSessionId,
    );
    const cowrie = state.overview.sessions.find((session) =>
      session.session_id.includes("cowrie"),
    );
    state.activeSessionId =
      hashSession ||
      preferred?.session_id ||
      active?.session_id ||
      cowrie?.session_id ||
      state.overview.sessions[0]?.session_id;
    renderSessions(state.overview.sessions);
    await selectSession(state.activeSessionId, {
      showLoading: !silent,
      updateUrl: !silent,
    });
    updateSyncStatus("live");
  } catch (error) {
    console.error(error);
    updateSyncStatus("error");
    if (!silent) setCaseState("error");
  } finally {
    state.refreshing = false;
    if (!silent) document.querySelector("#refresh-button").disabled = false;
  }
}

document
  .querySelector("#refresh-button")
  .addEventListener("click", () => loadDashboard({ silent: false }));
loadDashboard();
setInterval(() => {
  if (document.visibilityState === "visible") loadDashboard({ silent: true });
}, 5000);
