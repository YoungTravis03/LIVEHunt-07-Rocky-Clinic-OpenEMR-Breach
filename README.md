# LIVEHunt 07 // Rocky Clinic // OpenEMR Breach

Threat hunt scenario page for the Rocky Clinic OpenEMR breach investigation.

## Investigation Window
4–14 February 2026 UTC | Host: rocky83

## Sections
- Q00 Mission Brief
- Q01 Asset Validation (Container Runtime, OS Distribution)
- Q03 Discovery (Suspicious Session)
- Q04 Privilege Escalation (Anomalous Logons, SHA256)

## Usage
Open `index.html` directly in a browser, or deploy via GitHub Pages.

git init
git add .
git commit -m "feat: Rocky Clinic LIVEHunt 07 scenario page"
git branch -M main
git remote add origin https://github.com/YoungTravis03/rocky-clinic-hunt.git
git push -u origin main

https://YoungTravis03.github.io/rocky-clinic-hunt/




<!-- TOP BAR -->
<div class="topbar">
  <span class="logo">CYBER RANGE</span>
  <span class="sep">//</span>
  <span class="breadcrumb">LIVEHunt 07 // <span>Rocky Clinic // OpenEMR Breach</span></span>
  <div class="status-dot"></div>
</div>

<div class="container">

  <!-- HERO -->
  <div class="hero">
    <div class="phase-tag">Q00 // MISSION BRIEF</div>
    <h1>ROCKY CLINIC<br><span>OPENEMR BREACH</span></h1>
    <div class="subtitle">INVESTIGATION WINDOW: 4–14 FEBRUARY 2026 UTC &nbsp;|&nbsp; HOST: rocky83 &nbsp;|&nbsp; PLATFORM: OpenEMR</div>
  </div>

  <!-- MISSION BRIEF -->
  <div class="brief-box">
    <div class="brief-header">
      <span class="icon">📡</span>
      INCIDENT LEAD TRANSMISSION // ROCKY CLINIC
    </div>
    <div class="brief-body">
      <div class="memo-line">From: <span>Incident Lead // Rocky Clinic</span></div>
      <div class="memo-line">To: <span>Threat Hunt // On-Shift</span></div>
      <div class="memo-line">Re: <span>OpenEMR breach // post-incident reconstruction</span></div>
      <hr class="memo-divider">

      <p><em>"Rocky Clinic ran quiet until it did not. No ransomware, no alerts, no outage, just an operator moving through the estate like they belonged. Read the brief, then acknowledge when you are ready to start."</em></p>

      <p>Rocky Clinic runs OpenEMR, a cloud-hosted electronic health record platform for patient data and clinical workflow. Earlier this month they identified a security incident. The initial access path is unknown.</p>

      <p>This one began quietly. No ransomware, no alerts, no outage. Early activity inside the application looked like ordinary administration, but the pattern was deliberate exploration of identities, data, and workflows, before a pivot to the underlying host.</p>

      <p>Your job is to reconstruct the whole arc. What the attacker learned, how they expanded access, how a low-noise look-around turned into full operational compromise, and how data left the building.</p>

      <p><strong>What we do not yet know:</strong></p>
      <ul class="unknown-list">
        <li>The initial access path (still unattributed)</li>
        <li>What persisted, and whether it survives a reboot</li>
        <li>How control was established and data moved out</li>
        <li>What the operator did to cover the trail</li>
      </ul>

      <p>Evidence sits in the Sentinel workspace for this host. Discover the schema yourself with <code>take 1</code> or <code>getschema</code> — that is part of the work. Some answers are process telemetry, others live in the alert and other tables. Pivot across them.</p>

      <p>Scope tightly. Every query in this hunt runs lighter with explicit time bounds, the window is <strong>4 to 14 February 2026 UTC</strong>. Narrow further per phase as you learn the timeline.</p>

      <p>Section 00 is a gate. The phrase to submit is in this brief:</p>
      <div class="gate-phrase">▶ ready to hunt</div>
    </div>
  </div>

  <div class="scope-banner">
    ⏱ INVESTIGATION WINDOW: datetime(2026-02-04) .. datetime(2026-02-14) &nbsp;|&nbsp; HOST: rocky83 &nbsp;|&nbsp; SENTINEL WORKSPACE
  </div>

  <!-- SECTION: ASSET VALIDATION -->
  <div class="section-header">
    <div class="section-number">Q01 // ASSET VALIDATION</div>
    <div class="section-title">PLATFORM & HOST IDENTIFICATION</div>
  </div>

  <!-- Q1 -->
  <div class="question-card">
    <div class="q-header">
      <div class="q-num">Q01</div>
      <div class="q-title">What container runtime hosts the OpenEMR application on rocky83?</div>
      <div class="q-format">Platform name, single word</div>
    </div>
    <div class="q-body">
      <p>The cloud provider is Azure, but that is the infrastructure layer. We are asking about the layer that actually runs the OpenEMR application code.</p>

      <div class="kql-wrapper">
        <div class="kql-label">KQL // CONTAINER RUNTIME DETECTION</div>
        <div class="kql-block" id="kql1">
          <button class="copy-btn" onclick="copyKql('kql1')">COPY</button>
<span class="cm">// Identify container runtime by process activity on rocky83</span>
<br><span class="tbl">DeviceProcessEvents</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">DeviceName</span> <span class="op">==</span> <span class="str">"rocky83"</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">Timestamp</span> <span class="fn">between</span> (<span class="fn">datetime</span>(<span class="str">2026-02-04</span>) <span class="op">..</span> <span class="fn">datetime</span>(<span class="str">2026-02-14</span>))
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">FileName</span> <span class="fn">in~</span> (<span class="str">"docker"</span>, <span class="str">"podman"</span>, <span class="str">"containerd"</span>, <span class="str">"kubectl"</span>, <span class="str">"lxc"</span>, <span class="str">"crio"</span>)
<br><span class="op">|</span> <span class="kw">summarize</span> <span class="var">count()</span> <span class="kw">by</span> <span class="var">FileName</span>
<br><span class="op">|</span> <span class="kw">order by</span> <span class="var">count_</span> <span class="kw">desc</span>
        </div>
      </div>

      <div class="kql-wrapper" style="margin-top:10px">
        <div class="kql-label">ALTERNATIVE // DEVICE INFO</div>
        <div class="kql-block" id="kql1b">
          <button class="copy-btn" onclick="copyKql('kql1b')">COPY</button>
<span class="tbl">DeviceInfo</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">DeviceName</span> <span class="op">==</span> <span class="str">"rocky83"</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">Timestamp</span> <span class="fn">between</span> (<span class="fn">datetime</span>(<span class="str">2026-02-04</span>) <span class="op">..</span> <span class="fn">datetime</span>(<span class="str">2026-02-14</span>))
<br><span class="op">|</span> <span class="kw">project</span> <span class="var">Timestamp</span>, <span class="var">DeviceName</span>, <span class="var">OSPlatform</span>, <span class="var">OSDistribution</span>, <span class="var">OSVersionInfo</span>
<br><span class="op">|</span> <span class="kw">take</span> <span class="str">1</span>
        </div>
      </div>

      <div class="hint-row">
        <div class="hint-tag" onclick="toggleHint('h1a')">💡 HINT FREE</div>
      </div>
      <div class="hint-content" id="h1a">The runtime process name with the highest event count IS the answer. On Rocky Linux, Podman is the default rootless container runtime — but Docker may be explicitly installed. The FileName column will show which is active.</div>
    </div>
  </div>

  <!-- Q2: OS Distribution -->
  <div class="question-card">
    <div class="q-header">
      <div class="q-num">Q02</div>
      <div class="q-title">What operating system distribution hosts the platform, as recorded by the EDR?</div>
      <div class="q-format">Distribution name as recorded in DeviceInfo</div>
    </div>
    <div class="q-body">
      <div class="kql-wrapper">
        <div class="kql-label">KQL // OS DISTRIBUTION</div>
        <div class="kql-block" id="kql2">
          <button class="copy-btn" onclick="copyKql('kql2')">COPY</button>
<span class="tbl">DeviceInfo</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">DeviceName</span> <span class="op">==</span> <span class="str">"rocky83"</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">Timestamp</span> <span class="fn">between</span> (<span class="fn">datetime</span>(<span class="str">2026-02-04</span>) <span class="op">..</span> <span class="fn">datetime</span>(<span class="str">2026-02-14</span>))
<br><span class="op">|</span> <span class="kw">summarize</span> <span class="fn">arg_max</span>(<span class="var">Timestamp</span>, <span class="op">*</span>) <span class="kw">by</span> <span class="var">DeviceName</span>
<br><span class="op">|</span> <span class="kw">project</span> <span class="var">DeviceName</span>, <span class="var">OSDistribution</span>, <span class="var">OSPlatform</span>, <span class="var">OSVersionInfo</span>
        </div>
      </div>
    </div>
  </div>

  <!-- SECTION: DISCOVERY -->
  <div class="section-header">
    <div class="section-number">Q03 // DISCOVERY</div>
    <div class="section-title">SUSPICIOUS SESSION ANALYSIS</div>
  </div>

  <!-- Q3: First command -->
  <div class="question-card">
    <div class="q-header">
      <div class="q-num">Q03</div>
      <div class="q-title">Suspicious remote logon onto rocky83 — first command to check who else is logged in</div>
      <div class="q-format">ProcessId of the event</div>
    </div>
    <div class="q-body">
      <p>A suspicious remote logon onto rocky83 starts a new operator session in the investigation window. Within that session, identify the first command the operator runs to check who else is currently logged in.</p>

      <div class="scope-block">
        <div class="scope-label">SCOPE</div>
        host: rocky83 &nbsp;|&nbsp; account: it.admin<br>
        session: SUSPICIOUS (anchored by external RemoteIP — not routine internal admin)<br>
        window: 4 to 14 February 2026 UTC
      </div>

      <div class="kql-wrapper">
        <div class="kql-label">STEP 1 // FIND SUSPICIOUS LOGON</div>
        <div class="kql-block" id="kql3a">
          <button class="copy-btn" onclick="copyKql('kql3a')">COPY</button>
<span class="cm">// Identify external (non-RFC1918) remote logon for it.admin</span>
<br><span class="tbl">DeviceLogonEvents</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">DeviceName</span> <span class="op">==</span> <span class="str">"rocky83"</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">AccountName</span> <span class="fn">has</span> <span class="str">"it.admin"</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">Timestamp</span> <span class="fn">between</span> (<span class="fn">datetime</span>(<span class="str">2026-02-04</span>) <span class="op">..</span> <span class="fn">datetime</span>(<span class="str">2026-02-14</span>))
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">LogonType</span> <span class="fn">in</span> (<span class="str">"RemoteInteractive"</span>, <span class="str">"Network"</span>)
<br><span class="op">|</span> <span class="kw">where</span> <span class="fn">not</span>(<span class="var">RemoteIP</span> <span class="fn">startswith</span> <span class="str">"10."</span>)
<br><span class="op">|</span> <span class="kw">where</span> <span class="fn">not</span>(<span class="var">RemoteIP</span> <span class="fn">startswith</span> <span class="str">"192.168."</span>)
<br><span class="op">|</span> <span class="kw">where</span> <span class="fn">not</span>(<span class="var">RemoteIP</span> <span class="fn">startswith</span> <span class="str">"172."</span>)
<br><span class="op">|</span> <span class="kw">project</span> <span class="var">Timestamp</span>, <span class="var">AccountName</span>, <span class="var">RemoteIP</span>, <span class="var">LogonType</span>, <span class="var">SessionId</span>
<br><span class="op">|</span> <span class="kw">order by</span> <span class="var">Timestamp</span> <span class="kw">asc</span>
        </div>
      </div>

      <div class="kql-wrapper" style="margin-top:10px">
        <div class="kql-label">STEP 2 // FIRST WHO-IS-LOGGED-IN COMMAND IN SESSION</div>
        <div class="kql-block" id="kql3b">
          <button class="copy-btn" onclick="copyKql('kql3b')">COPY</button>
<span class="cm">// Find first enumeration-of-users command after suspicious logon</span>
<br><span class="tbl">DeviceProcessEvents</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">DeviceName</span> <span class="op">==</span> <span class="str">"rocky83"</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">AccountName</span> <span class="fn">has</span> <span class="str">"it.admin"</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">Timestamp</span> <span class="fn">between</span> (<span class="fn">datetime</span>(<span class="str">2026-02-04</span>) <span class="op">..</span> <span class="fn">datetime</span>(<span class="str">2026-02-14</span>))
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">ProcessCommandLine</span> <span class="fn">has_any</span> (<span class="str">"who"</span>, <span class="str">" w "</span>, <span class="str">"last "</span>, <span class="str">"users"</span>, <span class="str">"finger"</span>, <span class="str">"loginctl"</span>)
<br><span class="op">|</span>    <span class="kw">or</span> <span class="var">FileName</span> <span class="fn">in~</span> (<span class="str">"who"</span>, <span class="str">"w"</span>, <span class="str">"last"</span>, <span class="str">"users"</span>)
<br><span class="op">|</span> <span class="kw">project</span> <span class="var">Timestamp</span>, <span class="var">DeviceName</span>, <span class="var">AccountName</span>,
<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="var">ProcessId</span>, <span class="var">FileName</span>, <span class="var">ProcessCommandLine</span>
<br><span class="op">|</span> <span class="kw">order by</span> <span class="var">Timestamp</span> <span class="kw">asc</span>
        </div>
      </div>

      <div class="hint-row">
        <div class="hint-tag" onclick="toggleHint('h3a')">💡 HINT FREE</div>
      </div>
      <div class="hint-content" id="h3a">The suspicious session is anchored by a non-RFC1918 RemoteIP. Filter logons first, note the Timestamp, then query DeviceProcessEvents for commands like `who`, `w`, or `last` immediately after that timestamp. The ProcessId column in the first matching row is the answer.</div>
    </div>
  </div>

  <!-- SECTION: PRIVILEGE ESCALATION -->
  <div class="section-header">
    <div class="section-number">Q04 // PRIVILEGE ESCALATION</div>
    <div class="section-title">SHELL ESCAPE & SESSION FORENSICS</div>
  </div>

  <!-- Q4: Suspicious account -->
  <div class="question-card">
    <div class="q-header">
      <div class="q-num">Q04</div>
      <div class="q-title">Anomalous remote logons appear in the window. Identify the account behind the suspicious remote sessions.</div>
      <div class="q-format">Username</div>
    </div>
    <div class="q-body">
      <div class="kql-wrapper">
        <div class="kql-label">KQL // ANOMALOUS REMOTE LOGONS</div>
        <div class="kql-block" id="kql4">
          <button class="copy-btn" onclick="copyKql('kql4')">COPY</button>
<span class="tbl">DeviceLogonEvents</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">DeviceName</span> <span class="op">==</span> <span class="str">"rocky83"</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">Timestamp</span> <span class="fn">between</span> (<span class="fn">datetime</span>(<span class="str">2026-02-04</span>) <span class="op">..</span> <span class="fn">datetime</span>(<span class="str">2026-02-14</span>))
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">LogonType</span> <span class="fn">in</span> (<span class="str">"RemoteInteractive"</span>, <span class="str">"Network"</span>, <span class="str">"Ssh"</span>)
<br><span class="op">|</span> <span class="kw">where</span> <span class="fn">not</span>(<span class="var">RemoteIP</span> <span class="fn">startswith</span> <span class="str">"10."</span>)
<br><span class="op">|</span> <span class="kw">where</span> <span class="fn">not</span>(<span class="var">RemoteIP</span> <span class="fn">startswith</span> <span class="str">"192.168."</span>)
<br><span class="op">|</span> <span class="kw">where</span> <span class="fn">not</span>(<span class="var">RemoteIP</span> <span class="fn">startswith</span> <span class="str">"172."</span>)
<br><span class="op">|</span> <span class="kw">summarize</span> <span class="fn">count()</span>, <span class="fn">make_set</span>(<span class="var">RemoteIP</span>) <span class="kw">by</span> <span class="var">AccountName</span>, <span class="var">LogonType</span>
<br><span class="op">|</span> <span class="kw">order by</span> <span class="var">count_</span> <span class="kw">desc</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Q5: SHA256 of last command -->
  <div class="question-card">
    <div class="q-header">
      <div class="q-num">Q05</div>
      <div class="q-title">SHA256 of the binary behind the last interactive operator command before session cleanup</div>
      <div class="q-format">SHA256 hash</div>
    </div>
    <div class="q-body">
      <p>Before disconnecting, an operator often runs one last interactive check that confirms state. In the same suspicious session as Q03, what is the SHA256 of the binary behind the last interactive operator command before session cleanup?</p>

      <div class="scope-block">
        <div class="scope-label">SCOPE</div>
        host: rocky83 &nbsp;|&nbsp; same operator session as Q03 (anchored by external RemoteIP)<br>
        window: 4 to 14 February 2026 UTC
      </div>

      <div class="kql-wrapper">
        <div class="kql-label">KQL // LAST INTERACTIVE COMMAND + SHA256</div>
        <div class="kql-block" id="kql5">
          <button class="copy-btn" onclick="copyKql('kql5')">COPY</button>
<span class="cm">// Get all commands in suspicious session, ordered desc — first result is last command</span>
<br><span class="tbl">DeviceProcessEvents</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">DeviceName</span> <span class="op">==</span> <span class="str">"rocky83"</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">AccountName</span> <span class="fn">has</span> <span class="str">"it.admin"</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">Timestamp</span> <span class="fn">between</span> (<span class="fn">datetime</span>(<span class="str">2026-02-04</span>) <span class="op">..</span> <span class="fn">datetime</span>(<span class="str">2026-02-14</span>))
<br><span class="cm">// Exclude noise — system daemons, kernel threads</span>
<br><span class="op">|</span> <span class="kw">where</span> <span class="var">InitiatingProcessFileName</span> <span class="fn">in~</span> (<span class="str">"bash"</span>, <span class="str">"sh"</span>, <span class="str">"zsh"</span>, <span class="str">"ssh"</span>)
<br><span class="op">|</span> <span class="kw">project</span> <span class="var">Timestamp</span>, <span class="var">AccountName</span>,
<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="var">ProcessId</span>, <span class="var">FileName</span>,
<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="var">ProcessCommandLine</span>,
<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="var">SHA256</span>
<br><span class="op">|</span> <span class="kw">order by</span> <span class="var">Timestamp</span> <span class="kw">desc</span>
<br><span class="op">|</span> <span class="kw">take</span> <span class="str">10</span>
        </div>
      </div>

      <div class="hint-row">
        <div class="hint-tag" onclick="toggleHint('h5a')">💡 HINT FREE</div>
      </div>
      <div class="hint-content" id="h5a">Anchor the session start time from Q03, then look for the last process event before a logoff event or a long gap in activity. The SHA256 column in DeviceProcessEvents holds the binary hash directly — no join needed.</div>
    </div>
  </div>

</div><!-- /container -->

<!-- FOOTER -->
<div class="container">
  <div class="footer">
    <span class="logo-sm">CYBER RANGE // 0x48554E54</span>
    <span>LIVEHunt 07 // Rocky Clinic // OpenEMR Breach // 4–14 FEB 2026 UTC</span>
  </div>
</div>

<script>
function toggleHint(id) {
  const el = document.getElementById(id);
  el.classList.toggle('visible');
}

function copyKql(id) {
  const el = document.getElementById(id);
  // Get text content, strip HTML tags
  const text = el.innerText.replace(/^COPY\n/, '').trim();
  navigator.clipboard.writeText(text).then(() => {
    const btn = el.querySelector('.copy-btn');
    const orig = btn.textContent;
    btn.textContent = 'COPIED';
    btn.style.color = 'var(--green)';
    setTimeout(() => {
      btn.textContent = orig;
      btn.style.color = '';
    }, 1500);
  });
}
</script>
</body>
</html>
