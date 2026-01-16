// Landing page for Claude Defense Kit

// Report shell page - loads cached scan data from sessionStorage
export function generateReportShell(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Claude Defense Kit | Loading Report...</title>
  <style>
    body {
      background: linear-gradient(135deg, #0F2727 0%, #0A1414 50%, #203A3A 100%);
      color: white;
      font-family: system-ui, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
    }
    .loading {
      text-align: center;
    }
    .spinner {
      width: 40px;
      height: 40px;
      border: 3px solid rgba(167, 225, 224, 0.2);
      border-top-color: #a7e1e0;
      border-radius: 50%;
      animation: spin 1s linear infinite;
      margin: 0 auto 16px;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
  </style>
</head>
<body>
  <div class="loading">
    <div class="spinner"></div>
    <p>Loading report...</p>
  </div>
  <script>
    // Check for cached scan results
    const cachedResults = sessionStorage.getItem('cdk-scan-results');
    const cachedTimestamp = sessionStorage.getItem('cdk-scan-timestamp');
    
    if (cachedResults && cachedTimestamp) {
      // Check if cache is fresh (less than 60 seconds old)
      const age = Date.now() - parseInt(cachedTimestamp);
      if (age < 60000) {
        // Send cached data to server to render the report
        fetch('/api/render-report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: cachedResults
        })
        .then(res => res.text())
        .then(html => {
          // Replace the entire page with the rendered report
          document.open();
          document.write(html);
          document.close();
          // Clear the cache
          sessionStorage.removeItem('cdk-scan-results');
          sessionStorage.removeItem('cdk-scan-timestamp');
        })
        .catch(err => {
          console.error('Failed to render cached report:', err);
          // Fall back to fresh scan
          window.location.href = '/report';
        });
      } else {
        // Cache is stale, do fresh scan
        window.location.href = '/report';
      }
    } else {
      // No cache, do fresh scan
      window.location.href = '/report';
    }
  </script>
</body>
</html>`;
}

// Scanning interstitial page - shows while scan runs
export function generateScanningPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Claude Defense Kit | Scanning...</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --primary: #a7e1e0;
      --primary-dark: #5fa8a7;
      --bg-primary: #0F2727;
    }
    body {
      background: linear-gradient(135deg, #0F2727 0%, #0A1414 50%, #203A3A 100%);
    }
    .spinner {
      width: 40px;
      height: 40px;
      border: 3px solid rgba(167, 225, 224, 0.2);
      border-top-color: var(--primary);
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .progress-step {
      opacity: 0.4;
      transition: opacity 0.3s ease;
    }
    .progress-step.active {
      opacity: 1;
    }
    .progress-step.complete {
      opacity: 0.7;
    }
    .progress-step.complete .step-icon {
      color: #10b981;
    }
    .fade-in {
      animation: fadeIn 0.5s ease forwards;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .glass-card {
      background: rgba(255, 255, 255, 0.06);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .btn-disabled {
      background: rgba(255, 255, 255, 0.1);
      color: rgba(255, 255, 255, 0.4);
      cursor: not-allowed;
    }
    .btn-enabled {
      background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
      color: #0a2020;
      box-shadow: 0 4px 20px rgba(167, 225, 224, 0.4);
      cursor: pointer;
    }
  </style>
</head>
<body class="text-white min-h-screen font-sans">
  <div class="min-h-screen flex flex-col">
    <!-- Main Content -->
    <div class="flex-1 flex items-center justify-center px-6 py-8">
      <div class="max-w-lg w-full text-center">
        <!-- Logo -->
        <div class="mb-6">
          <svg width="180" height="22" viewBox="0 0 399 49" fill="none" xmlns="http://www.w3.org/2000/svg" class="mx-auto mb-3">
        <path d="M27.324 17.6425V28.6352C27.324 29.2483 27.0276 29.8231 26.5288 30.1791L0.576411 48.6781C0.334743 48.8504 0 48.6781 0 48.3809V37.3883C0 36.7751 0.29637 36.2003 0.795218 35.8444L26.7476 17.3453C26.9893 17.1731 27.324 17.3453 27.324 17.6425Z" fill="white"/>
        <path d="M27.324 0.36571V11.3543C27.324 11.9674 27.0276 12.5422 26.5288 12.8982L12.8076 22.6775C10.9943 23.9692 8.56207 23.9692 6.74874 22.6775L0.795218 18.4345C0.29637 18.0785 0 17.5037 0 16.8906V5.90285C0 5.60648 0.334743 5.43339 0.576411 5.60566L8.17507 11.022C9.1344 11.7078 10.4219 11.7078 11.3813 11.022L26.7476 0.0685238C26.9893 -0.103746 27.324 0.0685238 27.324 0.36571Z" fill="white"/>
        <path d="M49.1282 37.4536V3.79782H63.5247C69.7206 3.79782 73.8865 7.24672 73.8865 12.3822C73.8865 15.6543 72.1242 18.0984 69.16 19.1487C73.5785 20.0425 76.2295 23.0672 76.2295 27.42C76.2295 33.3331 71.3718 37.4586 64.4134 37.4586H49.1282V37.4536ZM63.5701 32.1363C67.6401 32.1363 69.8872 30.4094 69.8872 27.2786C69.8872 24.1478 67.6452 22.4158 63.5701 22.4158H55.2887V32.1414H63.5701V32.1363ZM62.5854 17.1945C65.7667 17.1945 67.5896 15.7149 67.5896 13.1295C67.5896 10.5441 65.7667 9.11003 62.5854 9.11003H55.2887V17.1945H62.5854Z" fill="white"/>
        <path d="M91.3983 38.2007C83.425 38.2007 78.2693 32.6814 78.2693 24.1375C78.2693 15.5935 83.526 10.0742 91.3478 10.0742C99.1697 10.0742 104.103 15.134 104.103 22.9659V26.1169H84.551C84.9348 30.4192 87.6061 33.1712 91.4438 33.1712C94.4331 33.1712 96.7509 31.6008 97.6397 28.9649L97.7406 28.672H103.931L103.815 29.1972C102.614 34.6659 97.7407 38.2057 91.4034 38.2057L91.3983 38.2007ZM98.0285 21.3147C97.8568 17.472 95.3825 15.1037 91.4892 15.1037C87.5959 15.1037 85.263 17.3609 84.6318 21.3147H98.0335H98.0285Z" fill="white"/>
        <path d="M108.839 46.8255L113.303 35.7567L103.946 10.8267H110.354L119.146 34.2721C119.615 35.5294 119.6 36.908 119.1 38.1502L115.606 46.8255H108.839Z" fill="white"/>
        <path d="M118.853 28.8231L125.201 11.9624C125.458 11.2807 126.12 10.8212 126.847 10.8212H132.093L125.256 27.697C124.983 28.3787 124.327 28.8231 123.59 28.8231H118.858H118.853Z" fill="white"/>
        <path d="M384.958 28.8232L391.306 11.9625C391.563 11.2808 392.225 10.8213 392.952 10.8213H398.199L391.361 27.6971C391.089 28.3788 390.432 28.8232 389.695 28.8232H384.964H384.958Z" fill="white"/>
        <path d="M144.995 38.2007C137.007 38.2007 131.634 32.5501 131.634 24.1375C131.634 15.7248 137.002 10.0742 144.995 10.0742C152.989 10.0742 158.362 15.7248 158.362 24.1375C158.362 32.5501 152.989 38.2007 144.995 38.2007ZM144.995 15.1037C140.582 15.1037 137.84 18.5627 137.84 24.1375C137.84 29.7122 140.582 33.1712 144.995 33.1712C149.409 33.1712 152.156 29.7122 152.156 24.1375C152.156 18.5627 149.414 15.1037 144.995 15.1037Z" fill="white"/>
        <path d="M178.919 37.4533V21.744C178.919 17.4013 177.267 15.1996 174.01 15.1996C172.571 15.1996 167.885 15.7399 167.885 22.6832V37.4533H161.962V10.8216H167.794V14.1998C169.582 11.5235 172.344 10.0692 175.697 10.0692C181.423 10.0692 184.842 14.2402 184.842 21.2289V37.4533H178.919Z" fill="white"/>
        <path d="M200.627 38.2007C194.754 38.2007 188.437 33.7974 188.437 24.1375C188.437 14.4775 194.754 10.0743 200.627 10.0743C204.318 10.0743 207.464 11.7305 209.338 14.5785C209.333 14.2402 209.333 13.9069 209.333 13.5484V0.000244141H215.256V37.4533H209.383V34.8174C209.383 34.4034 209.383 34.0145 209.383 33.6257C207.52 36.5192 204.349 38.2007 200.627 38.2007ZM202.036 15.1037C197.547 15.1037 194.643 18.6485 194.643 24.1375C194.643 29.6264 197.547 33.1713 202.036 33.1713C206.525 33.1713 209.383 29.5406 209.383 24.1375C209.383 18.7344 206.429 15.1037 202.036 15.1037Z" fill="white"/>
        <path d="M249.316 38.2007C243.443 38.2007 237.126 33.7974 237.126 24.1375C237.126 14.4775 243.443 10.0743 249.316 10.0743C253.007 10.0743 256.153 11.7305 258.026 14.5785C258.021 14.2402 258.021 13.9069 258.021 13.5484V0.000244141H263.944V37.4533H258.067V34.8174C258.067 34.4034 258.067 34.0145 258.067 33.6257C256.203 36.5192 253.032 38.2007 249.31 38.2007H249.316ZM250.724 15.1037C246.235 15.1037 243.332 18.6485 243.332 24.1375C243.332 29.6264 246.235 33.1713 250.724 33.1713C255.214 33.1713 258.067 29.6264 258.067 24.1375C258.067 18.6485 255.183 15.1037 250.724 15.1037Z" fill="white"/>
        <path d="M280.668 38.2007C272.695 38.2007 267.539 32.6814 267.539 24.1375C267.539 15.5935 272.796 10.0742 280.623 10.0742C288.45 10.0742 293.373 15.134 293.373 22.9659V26.1169H273.821C274.205 30.4192 276.876 33.1712 280.714 33.1712C283.703 33.1712 286.021 31.6008 286.91 28.9649L287.011 28.672H293.202L293.085 29.1972C291.884 34.6659 287.011 38.2057 280.668 38.2057V38.2007ZM287.304 21.3147C287.132 17.472 284.658 15.1037 280.764 15.1037C276.871 15.1037 274.538 17.3609 273.907 21.3147H287.304Z" fill="white"/>
        <path d="M313.839 37.4533V21.7439C313.839 17.4013 312.188 15.1996 308.926 15.1996C307.487 15.1996 302.801 15.7399 302.801 22.6832V37.4533H296.877V10.8216H302.705V14.2099C304.492 11.5285 307.254 10.0742 310.612 10.0742C316.339 10.0742 319.757 14.2452 319.757 21.2339V37.4584H313.834L313.839 37.4533Z" fill="white"/>
        <path d="M333.957 37.4536C329.14 37.4536 326.589 34.9237 326.589 30.1316V15.9472H321.53V10.8219H326.589V3.79782H332.513V10.8269H340.521V15.9523H332.513V29.7176C332.513 31.5506 333.305 32.3282 335.174 32.3282H340.713V37.4586H333.957V37.4536Z" fill="white"/>
        <path d="M349.662 1.35873H343.643V7.23145H349.662V1.35873Z" fill="white"/>
        <path d="M349.611 10.8213H343.688V37.453H349.611V10.8213Z" fill="white"/>
        <path d="M233.758 3.79797H227.744V14.5991H227.79V37.4537H233.713V14.5991H233.758V3.79797Z" fill="white"/>
        <path d="M385.251 34.2723L376.46 10.8269H363.538V3.79782H357.615V10.8219H352.555V15.9422H357.615V30.1316C357.615 34.9187 360.16 37.4536 364.977 37.4536H371.733V32.3282H366.194C364.331 32.3282 363.533 31.5455 363.533 29.7125V15.9472H371.966L379.404 35.7569L374.935 46.8257H381.484H381.706L385.201 38.1504C385.701 36.9032 385.721 35.5297 385.246 34.2723H385.251Z" fill="white"/>
      </svg>
      <h1 class="text-2xl font-bold text-white mb-3">Claude Defense Kit</h1>
          <p class="text-sm text-white/60 max-w-sm mx-auto">
            Scan your Claude Code installation for security risks, identify exposed credentials and MCP servers, and fix issues with one click.
          </p>
        </div>
    
        <!-- Spinner -->
    <div class="spinner mx-auto mb-8"></div>
    
    <!-- Status Message -->
    <h2 id="status-message" class="text-xl font-semibold text-[var(--primary)] mb-6">Scanning Environment...</h2>
    
    <!-- Progress Steps -->
    <div class="space-y-3 text-left max-w-xs mx-auto mb-8">
      <div id="step-1" class="progress-step active flex items-center gap-3">
        <span class="step-icon text-[var(--primary)]">●</span>
        <span class="text-sm text-white/80">Detecting Claude Code installation</span>
      </div>
      <div id="step-2" class="progress-step flex items-center gap-3">
        <span class="step-icon text-white/40">○</span>
        <span class="text-sm text-white/60">Scanning MCP servers & tools</span>
      </div>
      <div id="step-3" class="progress-step flex items-center gap-3">
        <span class="step-icon text-white/40">○</span>
        <span class="text-sm text-white/60">Analyzing configuration files</span>
      </div>
      <div id="step-4" class="progress-step flex items-center gap-3">
        <span class="step-icon text-white/40">○</span>
        <span class="text-sm text-white/60">Computing effective permissions</span>
      </div>
      <div id="step-5" class="progress-step flex items-center gap-3">
        <span class="step-icon text-white/40">○</span>
        <span class="text-sm text-white/60">Generating security report</span>
      </div>
    </div>
    
      </div>
    </div>
    
    <!-- Fixed Bottom Button -->
    <div class="px-6 py-6 border-t border-white/10">
      <div class="max-w-lg mx-auto">
        <a id="view-report-btn" href="/report?cached=true" 
           class="block w-full text-center px-8 py-4 rounded-xl font-semibold text-lg transition-all duration-300 btn-disabled pointer-events-none"
           onclick="return scanReady;">
          <span id="btn-text">Scanning...</span>
        </a>
      </div>
    </div>
  </div>
  
  <script>
    const steps = [
      { id: 'step-1', message: 'Detecting Claude Code installation...' },
      { id: 'step-2', message: 'Scanning MCP servers & tools...' },
      { id: 'step-3', message: 'Analyzing configuration files...' },
      { id: 'step-4', message: 'Computing effective permissions...' },
      { id: 'step-5', message: 'Generating security report...' },
    ];
    
    let currentStep = 0;
    let scanComplete = false;
    
    function advanceStep() {
      if (currentStep > 0) {
        const prevStep = document.getElementById(steps[currentStep - 1].id);
        prevStep.classList.remove('active');
        prevStep.classList.add('complete');
        prevStep.querySelector('.step-icon').textContent = '✓';
      }
      
      if (currentStep < steps.length) {
        const step = document.getElementById(steps[currentStep].id);
        step.classList.add('active');
        step.querySelector('.step-icon').textContent = '●';
        document.getElementById('status-message').textContent = steps[currentStep].message;
        currentStep++;
      }
    }
    
    let scanData = null;
    let animationComplete = false;
    
    function checkReadyToShow() {
      if (scanData && animationComplete) {
        showCompleteState();
      }
    }
    
    let scanReady = false;
    
    function showCompleteState() {
      // Mark all steps complete
      steps.forEach(s => {
        const step = document.getElementById(s.id);
        step.classList.remove('active');
        step.classList.add('complete');
        step.querySelector('.step-icon').textContent = '✓';
      });
      
      // Update status message
      document.getElementById('status-message').textContent = 'Scan Complete!';
      document.getElementById('status-message').style.color = '#10b981';
      
      // Hide spinner
      document.querySelector('.spinner').style.display = 'none';
      
      // Enable the button
      scanReady = true;
      const btn = document.getElementById('view-report-btn');
      btn.classList.remove('btn-disabled', 'pointer-events-none');
      btn.classList.add('btn-enabled');
      document.getElementById('btn-text').textContent = 'View Security Report →';
    }
    
    // Start the actual scan in the background immediately
    fetch('/api/scan')
      .then(res => res.json())
      .then(data => {
        scanData = data;
        // Store in sessionStorage for the report page to use
        sessionStorage.setItem('cdk-scan-results', JSON.stringify(data));
        sessionStorage.setItem('cdk-scan-timestamp', Date.now().toString());
        checkReadyToShow();
      })
      .catch(err => {
        console.error('Scan failed:', err);
        // Still show button, report page will re-scan
        scanData = { error: true };
        checkReadyToShow();
      });
    
    // Run progress animation
    const progressInterval = setInterval(() => {
      if (currentStep < steps.length) {
        advanceStep();
      } else if (!animationComplete) {
        clearInterval(progressInterval);
        animationComplete = true;
        checkReadyToShow();
      }
    }, 600);
  </script>
</body>
</html>`;
}

export function generateLandingPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Claude Defense Kit | Secure Your Claude Code Installation</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .gradient-text {
      background: linear-gradient(135deg, #58a6ff 0%, #f0883e 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .code-block {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
    }
    .feature-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      transition: border-color 0.2s ease;
    }
    .feature-card:hover {
      border-color: #58a6ff;
    }
  </style>
</head>
<body class="bg-[#0d1117] text-[#c9d1d9] min-h-screen font-sans">

  <!-- Hero Section -->
  <header class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16 text-center">
      <h1 class="text-4xl md:text-5xl font-bold mb-6">
        <span class="gradient-text">Claude Defense Kit</span>
      </h1>
      <p class="text-xl text-[#8b949e] mb-10 max-w-2xl mx-auto">
        Secure your Claude Code installation against prompt injection attacks.
        See what's at risk and lock it down with one click.
      </p>

      <!-- CTA Section -->
      <div class="code-block p-6 md:p-8 max-w-2xl mx-auto text-left">
        <div class="text-lg font-semibold mb-6 text-center">Get Started</div>

        <!-- Step 1 -->
        <div class="mb-6">
          <div class="flex items-center gap-3 mb-2">
            <span class="w-6 h-6 rounded-full bg-[#58a6ff] text-white text-sm flex items-center justify-center font-bold">1</span>
            <span class="font-semibold">Run the scanner</span>
          </div>
          <div class="ml-9">
            <div class="bg-[#0d1117] border border-[#30363d] rounded px-4 py-2 font-mono text-sm flex items-center justify-between">
              <span><span class="text-[#8b949e]">$</span> npx claude-defense-kit</span>
              <button onclick="navigator.clipboard.writeText('npx claude-defense-kit')"
                class="text-[#8b949e] hover:text-[#58a6ff] transition text-xs">Copy</button>
            </div>
          </div>
        </div>

        <!-- Step 2 -->
        <div class="mb-6">
          <div class="flex items-center gap-3 mb-2">
            <span class="w-6 h-6 rounded-full bg-[#58a6ff] text-white text-sm flex items-center justify-center font-bold">2</span>
            <span class="font-semibold">Opens an interactive report in your browser</span>
          </div>
          <div class="ml-9 text-sm text-[#8b949e]">
            <div class="flex items-start gap-2 mb-1">
              <span class="text-[#3fb950]">&#8226;</span>
              <span>See what MCP servers, tools, and files are exposed</span>
            </div>
            <div class="flex items-start gap-2">
              <span class="text-[#3fb950]">&#8226;</span>
              <span>View attack scenarios specific to your config</span>
            </div>
          </div>
        </div>

        <!-- Step 3 -->
        <div class="mb-6">
          <div class="flex items-center gap-3 mb-2">
            <span class="w-6 h-6 rounded-full bg-[#58a6ff] text-white text-sm flex items-center justify-center font-bold">3</span>
            <span class="font-semibold">Fix issues with one click</span>
          </div>
          <div class="ml-9 text-sm text-[#8b949e]">
            <div class="flex items-start gap-2 mb-1">
              <span class="text-[#3fb950]">&#8226;</span>
              <span>Disable risky MCP servers</span>
            </div>
            <div class="flex items-start gap-2 mb-1">
              <span class="text-[#3fb950]">&#8226;</span>
              <span>Block sensitive file paths</span>
            </div>
            <div class="flex items-start gap-2">
              <span class="text-[#3fb950]">&#8226;</span>
              <span>Restrict dangerous bash commands</span>
            </div>
          </div>
        </div>

        <!-- Privacy note -->
        <div class="text-center text-sm text-[#8b949e] border-t border-[#30363d] pt-5">
          All analysis runs locally. No data leaves your machine.
        </div>

        <!-- Badges -->
        <div class="flex flex-wrap justify-center gap-4 mt-4 text-xs">
          <span class="px-3 py-1 bg-[#21262d] rounded-full text-[#8b949e]">Runs in 10 seconds</span>
          <span class="px-3 py-1 bg-[#21262d] rounded-full text-[#8b949e]">No installation required</span>
          <span class="px-3 py-1 bg-[#21262d] rounded-full text-[#8b949e]">One-click fixes</span>
        </div>

        <!-- Buttons -->
        <div class="flex flex-col sm:flex-row gap-3 justify-center mt-6">
          <a href="https://github.com/gobeyondidentity/claude-defense-kit" target="_blank"
            class="px-5 py-2.5 bg-[#21262d] text-[#c9d1d9] border border-[#30363d] rounded-lg font-semibold hover:bg-[#30363d] transition text-center text-sm">
            View on GitHub
          </a>
        </div>
      </div>
    </div>
  </header>

  <!-- The Problem Section -->
  <section class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-2">We've Seen This Before</h2>
      <p class="text-[#8b949e] mb-8">
        The agent architecture is structurally identical to command-and-control
        malware. The difference is intent, not design.
      </p>

      <div class="grid md:grid-cols-2 gap-8 mb-8">
        <!-- C2 Architecture -->
        <div class="code-block p-4">
          <div class="text-xs font-semibold text-[#f85149] uppercase mb-3">Traditional Botnet</div>
          <pre class="text-sm text-[#8b949e] whitespace-pre-wrap">Command source: C2 server
Executor:       Bot/malware
Instructions:   Encoded commands
System access:  Shell, APIs, files
Exfiltration:   Back to C2
Persistence:    Registry, cron</pre>
        </div>

        <!-- Agent Architecture -->
        <div class="code-block p-4">
          <div class="text-xs font-semibold text-[#58a6ff] uppercase mb-3">Claude Code</div>
          <pre class="text-sm text-[#8b949e] whitespace-pre-wrap">Command source: LLM (via context)
Executor:       Agent program
Instructions:   Natural language
System access:  Tools (bash, HTTP)
Exfiltration:   Tool results, context
Persistence:    MCP server, plugin</pre>
        </div>
      </div>

      <p class="text-sm text-[#8b949e]">
        Same pattern. Different runtime.
      </p>
    </div>
  </section>

  <!-- Classic Vulnerabilities Reborn -->
  <section class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-6">Classic Vulnerabilities, Reborn</h2>

      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-[#30363d]">
              <th class="text-left py-3 px-4 text-[#8b949e] font-semibold">Classic</th>
              <th class="text-left py-3 px-4 text-[#8b949e] font-semibold">Agentic</th>
            </tr>
          </thead>
          <tbody>
            <tr class="border-b border-[#21262d]">
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">SQL Injection</span>
                <div class="text-xs text-[#8b949e] mt-1">Untrusted input in SQL query</div>
              </td>
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">Prompt Injection</span>
                <div class="text-xs text-[#8b949e] mt-1">Untrusted data in LLM context</div>
              </td>
            </tr>
            <tr class="border-b border-[#21262d]">
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">Confused Deputy</span>
                <div class="text-xs text-[#8b949e] mt-1">Service tricked into misusing permissions</div>
              </td>
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">Agent as Deputy</span>
                <div class="text-xs text-[#8b949e] mt-1">Claude Code uses your creds for attacker's requests</div>
              </td>
            </tr>
            <tr class="border-b border-[#21262d]">
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">Supply Chain</span>
                <div class="text-xs text-[#8b949e] mt-1">Malicious npm package</div>
              </td>
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">MCP Supply Chain</span>
                <div class="text-xs text-[#8b949e] mt-1">Malicious MCP server or plugin</div>
              </td>
            </tr>
            <tr>
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">Data Exfiltration</span>
                <div class="text-xs text-[#8b949e] mt-1">SQL dump, XSS cookie theft</div>
              </td>
              <td class="py-3 px-4">
                <span class="text-[#f0883e]">Context Leakage</span>
                <div class="text-xs text-[#8b949e] mt-1">Tool call sends data to external endpoint</div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- What We Scan -->
  <section class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-6">What We Scan</h2>

      <div class="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <div class="feature-card p-4">
          <div class="text-[#58a6ff] font-semibold mb-2">MCP Servers</div>
          <p class="text-sm text-[#8b949e]">Tool inventory, exposed environment variables, command access</p>
        </div>
        <div class="feature-card p-4">
          <div class="text-[#58a6ff] font-semibold mb-2">Filesystem Access</div>
          <p class="text-sm text-[#8b949e]">Read/write paths, sensitive files in accessible directories</p>
        </div>
        <div class="feature-card p-4">
          <div class="text-[#58a6ff] font-semibold mb-2">Credentials</div>
          <p class="text-sm text-[#8b949e]">API keys, tokens, SSH keys that Claude Code can read</p>
        </div>
        <div class="feature-card p-4">
          <div class="text-[#58a6ff] font-semibold mb-2">Bash Access</div>
          <p class="text-sm text-[#8b949e]">Shell command capabilities, dangerous command patterns</p>
        </div>
        <div class="feature-card p-4">
          <div class="text-[#58a6ff] font-semibold mb-2">Network</div>
          <p class="text-sm text-[#8b949e]">HTTP/curl/fetch tools that enable data exfiltration</p>
        </div>
        <div class="feature-card p-4">
          <div class="text-[#58a6ff] font-semibold mb-2">Integrity</div>
          <p class="text-sm text-[#8b949e]">Hash tracking for MCP scripts and Claude installation</p>
        </div>
      </div>
    </div>
  </section>

  <!-- Attack Scenarios -->
  <section class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-6">Attack Scenarios</h2>

      <div class="space-y-6">
        <div class="code-block p-5">
          <div class="flex items-center gap-2 mb-3">
            <span class="text-[#f85149] text-lg">1</span>
            <span class="font-semibold">Credential Theft</span>
          </div>
          <p class="text-sm text-[#8b949e]">
            A malicious MCP server or prompt injection reads API keys from accessible
            config files (~/.aws/credentials, .env files) and exfiltrates them via
            an HTTP tool call.
          </p>
        </div>

        <div class="code-block p-5">
          <div class="flex items-center gap-2 mb-3">
            <span class="text-[#f85149] text-lg">2</span>
            <span class="font-semibold">Data Exfiltration</span>
          </div>
          <p class="text-sm text-[#8b949e]">
            Claude Code with file read + network access can read sensitive documents,
            source code, or database exports and send them anywhere. The agent
            faithfully executes what the LLM requests.
          </p>
        </div>

        <div class="code-block p-5">
          <div class="flex items-center gap-2 mb-3">
            <span class="text-[#f85149] text-lg">3</span>
            <span class="font-semibold">Persistence via Context</span>
          </div>
          <p class="text-sm text-[#8b949e]">
            Injected instructions survive context compaction, persisting across
            sessions. Security-critical context gets dropped while malicious
            instructions remain.
          </p>
        </div>
      </div>
    </div>
  </section>

  <!-- How It Works -->
  <section class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-6">How It Works</h2>

      <div class="code-block p-5 mb-8">
        <div class="text-[#8b949e] text-sm mb-2">$ npx claude-defense-kit</div>
        <div class="text-[#3fb950]">Starting Claude Defense Kit...</div>
      </div>

      <div class="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <div class="text-center">
          <div class="w-10 h-10 rounded-full bg-[#21262d] border border-[#30363d] flex items-center justify-center mx-auto mb-3 text-[#58a6ff] font-bold">1</div>
          <p class="text-sm text-[#8b949e]">Scans your Claude Code configuration</p>
        </div>
        <div class="text-center">
          <div class="w-10 h-10 rounded-full bg-[#21262d] border border-[#30363d] flex items-center justify-center mx-auto mb-3 text-[#58a6ff] font-bold">2</div>
          <p class="text-sm text-[#8b949e]">Identifies MCP servers, tools, file access</p>
        </div>
        <div class="text-center">
          <div class="w-10 h-10 rounded-full bg-[#21262d] border border-[#30363d] flex items-center justify-center mx-auto mb-3 text-[#58a6ff] font-bold">3</div>
          <p class="text-sm text-[#8b949e]">Calculates blast radius and attack chains</p>
        </div>
        <div class="text-center">
          <div class="w-10 h-10 rounded-full bg-[#21262d] border border-[#30363d] flex items-center justify-center mx-auto mb-3 text-[#58a6ff] font-bold">4</div>
          <p class="text-sm text-[#8b949e]">Shows one-click remediation options</p>
        </div>
      </div>
    </div>
  </section>

  <!-- Features -->
  <section class="border-b border-[#30363d]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-6">Features</h2>

      <div class="grid sm:grid-cols-2 gap-6">
        <div class="flex gap-4">
          <div class="text-[#3fb950] text-xl">&#10003;</div>
          <div>
            <div class="font-semibold mb-1">Local-Only</div>
            <p class="text-sm text-[#8b949e]">No data leaves your machine. All analysis happens locally.</p>
          </div>
        </div>
        <div class="flex gap-4">
          <div class="text-[#3fb950] text-xl">&#10003;</div>
          <div>
            <div class="font-semibold mb-1">One-Click Remediation</div>
            <p class="text-sm text-[#8b949e]">Fix issues directly from the report with config changes.</p>
          </div>
        </div>
        <div class="flex gap-4">
          <div class="text-[#3fb950] text-xl">&#10003;</div>
          <div>
            <div class="font-semibold mb-1">Integrity Monitoring</div>
            <p class="text-sm text-[#8b949e]">Track changes to MCP server scripts over time.</p>
          </div>
        </div>
        <div class="flex gap-4">
          <div class="text-[#3fb950] text-xl">&#10003;</div>
          <div>
            <div class="font-semibold mb-1">Configurable Restrictions</div>
            <p class="text-sm text-[#8b949e]">Restrict tools, paths, and bash commands from the UI.</p>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Enterprise -->
  <section class="border-b border-[#30363d] bg-[#161b22]">
    <div class="max-w-5xl mx-auto px-6 py-16">
      <h2 class="text-2xl font-bold mb-2">Managing Claude Code Across Your Organization?</h2>
      <p class="text-[#8b949e] mb-6">
        Beyond Identity provides enterprise-grade security controls for Claude Code deployments.
      </p>

      <div class="flex flex-wrap gap-x-6 gap-y-2 mb-8 text-sm">
        <span class="flex items-center gap-2">
          <span class="text-[#3fb950]">&#10003;</span>
          <span class="text-[#c9d1d9]">Fleet-wide policy enforcement</span>
        </span>
        <span class="flex items-center gap-2">
          <span class="text-[#3fb950]">&#10003;</span>
          <span class="text-[#c9d1d9]">Centralized audit logs</span>
        </span>
        <span class="flex items-center gap-2">
          <span class="text-[#3fb950]">&#10003;</span>
          <span class="text-[#c9d1d9]">Compliance reporting</span>
        </span>
      </div>

      <a href="https://beyondidentity.ai" target="_blank"
        class="inline-block px-6 py-3 bg-[#58a6ff] text-white rounded-lg font-semibold hover:brightness-110 transition">
        Learn More
      </a>
    </div>
  </section>

  <!-- Footer -->
  <footer class="py-12">
    <div class="max-w-5xl mx-auto px-6 text-center">
      <p class="text-[#8b949e] mb-4">
        <a href="https://github.com/gobeyondidentity/claude-defense-kit" target="_blank" class="text-[#58a6ff] hover:underline">GitHub</a>
        <span class="mx-2">·</span>
        <span>MIT License</span>
        <span class="mx-2">·</span>
        <a href="/" class="text-[#58a6ff] hover:underline">Run Audit</a>
      </p>
      <p class="text-sm text-[#8b949e]">
        No data leaves your machine. All analysis happens locally.
      </p>
    </div>
  </footer>

</body>
</html>`;
}
