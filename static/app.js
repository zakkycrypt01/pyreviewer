/**
 * PyReviewer Frontend Application Controller
 * Handles Codebase Repository Scanning, Interactive File Tree,
 * AST Review, Refactoring Diffs, and Executive Audit Reports.
 * Resilient to VS Code Live Server (port 5500), file://, and direct deployment.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Determine API Base URL
  // If running via Live Server (port 5500) or file://, target Python backend on localhost:8080
  const API_BASE = (window.location.port === '8080' || window.location.hostname.includes('render.com'))
    ? ''
    : 'http://localhost:8080';

  // DOM Elements - Editor & Navigation
  const codeEditor = document.getElementById('code-editor');
  const editorGutter = document.getElementById('editor-gutter');
  const cursorPos = document.getElementById('cursor-pos');
  const currentFilename = document.getElementById('current-filename');
  const activeFileTitle = document.getElementById('active-file-title');
  const fileStatusIndicator = document.getElementById('file-status-indicator');
  const snippetSelector = document.getElementById('snippet-selector');
  const btnRunAnalysis = document.getElementById('btn-run-analysis');
  const btnClearCode = document.getElementById('btn-clear-code');
  const btnFormatCode = document.getElementById('btn-format-code');
  const btnApplyAllFixes = document.getElementById('btn-apply-all-fixes');
  const btnExportPR = document.getElementById('btn-export-pr');
  const btnCopyDiff = document.getElementById('btn-copy-diff');
  const btnCopyDocker = document.getElementById('btn-copy-docker');
  const btnCopyPRMd = document.getElementById('btn-copy-pr-md');

  // DOM Elements - GitHub Repository Scanner
  const repoUrlInput = document.getElementById('repo-url-input');
  const btnScanRepo = document.getElementById('btn-scan-repo');
  const btnDemoRepo = document.getElementById('btn-demo-repo');
  const repoScanStatus = document.getElementById('repo-scan-status');
  const repoTitleText = document.getElementById('repo-title-text');
  const treeFilesCount = document.getElementById('tree-files-count');
  const treeContainer = document.getElementById('tree-container');

  // DOM Elements - Metrics HUD
  const metricGrade = document.getElementById('metric-grade');
  const metricVulnsCount = document.getElementById('metric-vulns-count');
  const metricMaintainability = document.getElementById('metric-maintainability');
  const metricComplexity = document.getElementById('metric-complexity');
  const metricLoc = document.getElementById('metric-loc');
  const metricFuncs = document.getElementById('metric-funcs');
  const metricDocker = document.getElementById('metric-docker');

  // DOM Elements - Tabs & Panels
  const paneTabs = document.querySelectorAll('.pane-tab');
  const tabContents = document.querySelectorAll('.tab-content');
  const findingsList = document.getElementById('findings-list');
  const findingsCountBadge = document.getElementById('findings-count-badge');
  const findingsSummaryText = document.getElementById('findings-summary-text');
  const diffCodeText = document.getElementById('diff-code-text');
  const dockerCodeDisplay = document.getElementById('docker-code-display');
  const prMarkdownOutput = document.getElementById('pr-markdown-output');
  const dockerSubtabs = document.querySelectorAll('.docker-subtab');
  const reportMarkdownPreview = document.getElementById('report-markdown-preview');
  const btnCopyReport = document.getElementById('btn-copy-report');
  const btnDownloadReport = document.getElementById('btn-download-report');

  // State
  let currentAnalysis = null;
  let activeDockerFile = 'dockerfile';
  let snippets = {};
  let currentRepoData = null;
  let activeFilePath = null;

  // Safe HTTP Request Helper
  async function requestJson(path, options = {}) {
    const url = `${API_BASE}${path}`;
    let res;
    try {
      res = await fetch(url, options);
    } catch (netErr) {
      throw new Error(`Cannot connect to PyReviewer backend at ${url}. Ensure 'python3 server.py' is running on port 8080.`);
    }

    const rawText = await res.text();
    let json;
    try {
      json = rawText ? JSON.parse(rawText) : {};
    } catch (parseErr) {
      throw new Error(`Server returned non-JSON response (${res.status} ${res.statusText}): ${rawText.slice(0, 120)}`);
    }

    if (!res.ok || json.error) {
      throw new Error(json.error || `Request failed with HTTP ${res.status}`);
    }

    return json;
  }

  function setStatus(msg, type = 'info') {
    if (!repoScanStatus) return;
    repoScanStatus.textContent = msg;
    repoScanStatus.style.color = type === 'error' ? '#f87171' : type === 'success' ? '#34d399' : '#818cf8';
  }

  // ================= 1. GUTTER & EDITOR SYNCHRONIZATION =================
  function updateGutter() {
    const lines = codeEditor.value.split('\n');
    const lineCount = lines.length || 1;
    let gutterHTML = '';
    for (let i = 1; i <= lineCount; i++) {
      gutterHTML += `<div>${i}</div>`;
    }
    editorGutter.innerHTML = gutterHTML;
  }

  codeEditor.addEventListener('input', () => {
    updateGutter();
    fileStatusIndicator.textContent = 'Modified';
    fileStatusIndicator.style.color = '#fbbf24';
  });

  codeEditor.addEventListener('scroll', () => {
    editorGutter.scrollTop = codeEditor.scrollTop;
  });

  codeEditor.addEventListener('keyup', updateCursorPosition);
  codeEditor.addEventListener('click', updateCursorPosition);

  function updateCursorPosition() {
    const text = codeEditor.value.substring(0, codeEditor.selectionStart);
    const lines = text.split('\n');
    const line = lines.length;
    const col = lines[lines.length - 1].length + 1;
    cursorPos.textContent = `Ln ${line}, Col ${col}`;
  }

  codeEditor.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const start = codeEditor.selectionStart;
      const end = codeEditor.selectionEnd;
      codeEditor.value = codeEditor.value.substring(0, start) + '    ' + codeEditor.value.substring(end);
      codeEditor.selectionStart = codeEditor.selectionEnd = start + 4;
      updateGutter();
    }
  });

  // ================= 2. TABS MANAGEMENT =================
  paneTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetId = tab.getAttribute('data-tab');
      paneTabs.forEach(t => t.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      tab.classList.add('active');
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add('active');
    });
  });

  dockerSubtabs.forEach(subtab => {
    subtab.addEventListener('click', () => {
      dockerSubtabs.forEach(s => s.classList.remove('active'));
      subtab.classList.add('active');
      activeDockerFile = subtab.getAttribute('data-file');
      renderDockerCode();
    });
  });

  function renderDockerCode() {
    const source = currentRepoData || currentAnalysis;
    if (!source) return;
    if (activeDockerFile === 'dockerfile') {
      dockerCodeDisplay.textContent = source.dockerfile || '// No Dockerfile generated';
    } else if (activeDockerFile === 'render_yaml') {
      dockerCodeDisplay.textContent = source.render_yaml || '// No render.yaml generated';
    } else if (activeDockerFile === 'dockerignore') {
      dockerCodeDisplay.textContent = source.dockerignore || '// No .dockerignore generated';
    }
  }

  // ================= 3. GITHUB REPOSITORY SCANNER =================
  async function triggerRepoScan(url) {
    if (!url || !url.trim()) {
      setStatus('Please enter a valid GitHub repository URL.', 'error');
      return;
    }

    btnScanRepo.disabled = true;
    btnScanRepo.innerHTML = '<span>Cloning &amp; Auditing Codebase...</span>';
    setStatus('Cloning shallow repository & running multi-file AST security inspection...', 'info');

    try {
      const data = await requestJson('/api/scan-repo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: url.trim() })
      });

      currentRepoData = data;
      renderRepoScanResults(data);
      setStatus(`Successfully scanned ${data.total_files} Python files in ${data.repo_name}`, 'success');
    } catch (err) {
      console.error(err);
      setStatus(`Scan Failed: ${err.message}`, 'error');
    } finally {
      btnScanRepo.disabled = false;
      btnScanRepo.innerHTML = `
        <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <span>Clone &amp; Scan Codebase</span>
      `;
    }
  }

  if (btnScanRepo && repoUrlInput) {
    btnScanRepo.addEventListener('click', () => triggerRepoScan(repoUrlInput.value));
    repoUrlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') triggerRepoScan(repoUrlInput.value);
    });
  }

  if (btnDemoRepo) {
    btnDemoRepo.addEventListener('click', () => {
      repoUrlInput.value = 'https://github.com/demo/ecommerce-microservices';
      triggerRepoScan(repoUrlInput.value);
    });
  }

  function renderRepoScanResults(data) {
    // 1. Update Top Title & File Count
    repoTitleText.textContent = data.repo_name;
    treeFilesCount.textContent = `${data.total_files} files (${data.total_loc.toLocaleString()} LOC)`;

    // 2. Update HUD Metrics
    metricGrade.textContent = data.repo_grade;
    metricGrade.className = 'grade-badge grade-' + data.repo_grade.toLowerCase();
    metricVulnsCount.textContent = `${data.total_critical} Critical / ${data.total_high} High`;
    metricLoc.textContent = data.total_loc.toLocaleString();
    metricFuncs.textContent = `${data.total_files} files`;
    metricDocker.textContent = "100% Ready";

    // 3. Render File Tree
    treeContainer.innerHTML = '';
    const files = data.files;

    Object.keys(files).forEach((filePath, idx) => {
      const fileInfo = files[filePath];
      const item = document.createElement('div');
      item.className = 'tree-item' + (idx === 0 ? ' active' : '');
      item.setAttribute('data-path', filePath);
      item.innerHTML = `
        <span class="tree-risk-dot ${fileInfo.risk}"></span>
        <span class="tree-item-name">${filePath}</span>
        <span class="tree-item-badge">${fileInfo.issues.length}</span>
      `;
      item.addEventListener('click', () => selectRepoFile(filePath));
      treeContainer.appendChild(item);
    });

    // 4. Render Markdown Report Tab
    renderMarkdownReportPreview(data.detailed_report);

    // Switch to Report Tab by default
    const reportTabBtn = document.getElementById('tab-btn-report');
    if (reportTabBtn) reportTabBtn.click();

    // 5. Select primary hotspot or first file
    const primaryFile = (data.hotspots && data.hotspots[0]) || Object.keys(files)[0];
    if (primaryFile) {
      selectRepoFile(primaryFile);
    }

    // 6. Update Docker Code
    renderDockerCode();
  }

  function selectRepoFile(filePath) {
    if (!currentRepoData || !currentRepoData.files[filePath]) return;

    activeFilePath = filePath;
    const fileInfo = currentRepoData.files[filePath];

    // Highlight in tree
    document.querySelectorAll('.tree-item').forEach(el => {
      el.classList.toggle('active', el.getAttribute('data-path') === filePath);
    });

    // Update Header Pill
    currentFilename.textContent = filePath;
    activeFileTitle.textContent = filePath;
    fileStatusIndicator.textContent = `${fileInfo.issues.length} issues`;
    fileStatusIndicator.style.color = fileInfo.risk === 'danger' ? '#f87171' : fileInfo.risk === 'warning' ? '#fbbf24' : '#34d399';

    // Populate Editor
    codeEditor.value = fileInfo.content;
    updateGutter();

    // Render this file's findings and diff
    currentAnalysis = {
      metrics: fileInfo.metrics,
      issues: fileInfo.issues,
      diff_text: fileInfo.diff_text,
      refactored_code: fileInfo.refactored_code,
      dockerfile: currentRepoData.dockerfile,
      render_yaml: currentRepoData.render_yaml,
      dockerignore: currentRepoData.dockerignore
    };

    renderAnalysis(currentAnalysis);
  }

  function renderMarkdownReportPreview(mdText) {
    if (!mdText) {
      reportMarkdownPreview.innerHTML = '<p>No report available.</p>';
      return;
    }

    let html = mdText
      .replace(/^### (.*$)/gim, '<h3>$1</h3>')
      .replace(/^## (.*$)/gim, '<h2>$1</h2>')
      .replace(/^# (.*$)/gim, '<h1>$1</h1>')
      .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/gim, '<em>$1</em>')
      .replace(/`([^`]+)`/gim, '<code>$1</code>')
      .replace(/\n\n/gim, '<br><br>');

    if (html.includes('|')) {
      const tableRows = html.split('<br><br>').map(block => {
        if (block.includes('| :--- |')) {
          const lines = block.split('\n').filter(l => l.trim().startsWith('|'));
          let tableHtml = '<table>';
          lines.forEach((line, i) => {
            if (line.includes(':---')) return;
            const cells = line.split('|').filter(c => c.trim().length > 0);
            const tag = i === 0 ? 'th' : 'td';
            tableHtml += '<tr>' + cells.map(c => `<${tag}>${c.trim()}</${tag}>`).join('') + '</tr>';
          });
          tableHtml += '</table>';
          return tableHtml;
        }
        return block;
      });
      html = tableRows.join('<br><br>');
    }

    reportMarkdownPreview.innerHTML = html;
  }

  // Copy / Download Report Buttons
  if (btnCopyReport) {
    btnCopyReport.addEventListener('click', () => {
      if (currentRepoData && currentRepoData.detailed_report) {
        navigator.clipboard.writeText(currentRepoData.detailed_report).then(() => {
          btnCopyReport.textContent = 'Copied Report!';
          setTimeout(() => { btnCopyReport.textContent = 'Copy Report (MD)'; }, 2000);
        });
      }
    });
  }

  if (btnDownloadReport) {
    btnDownloadReport.addEventListener('click', () => {
      if (currentRepoData && currentRepoData.detailed_report) {
        const blob = new Blob([currentRepoData.detailed_report], { type: 'text/markdown;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `audit-report-${(currentRepoData.repo_name || 'codebase').replace(/[\/\\]/g, '-')}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    });
  }

  // ================= 4. SINGLE FILE SNIPPET LOADER =================
  async function loadSnippets() {
    try {
      snippets = await requestJson('/api/snippets');
      const selected = snippetSelector.value;
      if (snippets[selected]) {
        codeEditor.value = snippets[selected];
        updateGutter();
        runAnalysis();
      }
    } catch (e) {
      console.log('Snippet load info:', e.message);
    }
  }

  snippetSelector.addEventListener('change', () => {
    const val = snippetSelector.value;
    if (snippets[val]) {
      currentRepoData = null;
      repoTitleText.textContent = 'Single File Mode';
      treeFilesCount.textContent = '1 file';
      treeContainer.innerHTML = '<div class="tree-empty-state"><p>Loaded: ' + val + '.py</p></div>';
      currentFilename.textContent = `${val}.py`;
      activeFileTitle.textContent = `${val}.py`;
      codeEditor.value = snippets[val];
      updateGutter();
      runAnalysis();
    }
  });

  // ================= 5. AST CODE REVIEW EXECUTION (ACTIVE FILE) =================
  async function runAnalysis() {
    const code = codeEditor.value;
    if (!code.trim()) {
      setStatus('Please enter Python code to review.', 'error');
      return;
    }

    btnRunAnalysis.disabled = true;
    btnRunAnalysis.innerHTML = '<span>Analyzing AST...</span>';

    try {
      const data = await requestJson('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      });

      currentAnalysis = data;
      renderAnalysis(data);
      fileStatusIndicator.textContent = 'Analyzed';
      fileStatusIndicator.style.color = '#34d399';
    } catch (err) {
      console.error(err);
      setStatus(`Analysis Error: ${err.message}`, 'error');
    } finally {
      btnRunAnalysis.disabled = false;
      btnRunAnalysis.innerHTML = `
        <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
        <span>Run File Review</span>
      `;
    }
  }

  btnRunAnalysis.addEventListener('click', runAnalysis);

  function renderAnalysis(data) {
    const metrics = data.metrics;
    const issues = data.issues || [];

    metricGrade.textContent = metrics.security_rating;
    metricGrade.className = 'grade-badge grade-' + metrics.security_rating.toLowerCase();

    const criticalCount = issues.filter(i => i.severity === 'CRITICAL').length;
    metricVulnsCount.textContent = `${criticalCount} Critical Vuln${criticalCount === 1 ? '' : 's'}`;

    metricMaintainability.textContent = metrics.maintainability_score;
    metricComplexity.textContent = metrics.cyclomatic_complexity;
    metricLoc.textContent = metrics.code_lines;
    metricFuncs.textContent = `${metrics.functions_count} funcs`;
    metricDocker.textContent = metrics.container_readiness;

    findingsCountBadge.textContent = issues.length;
    findingsSummaryText.textContent = `Found ${issues.length} issue${issues.length === 1 ? '' : 's'} (${criticalCount} critical)`;
    findingsList.innerHTML = '';

    if (issues.length === 0) {
      findingsList.innerHTML = `
        <div class="empty-state">
          <svg class="empty-icon" style="color:#10b981; opacity:1;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14M22 4L12 14.01l-3-3"/></svg>
          <p style="color:#f4f4f5; font-weight:600;">Clean, Idiomatic Python Code!</p>
          <span style="font-size:11px; color:#71717a;">No security vulnerabilities, blocking async calls, or anti-patterns detected.</span>
        </div>
      `;
    } else {
      issues.forEach(issue => {
        const card = document.createElement('div');
        const sevClass = issue.severity.toLowerCase();
        card.className = `issue-card ${sevClass}`;
        card.innerHTML = `
          <div class="issue-header">
            <div class="issue-title-group">
              <span class="issue-line-badge">Line ${issue.line}</span>
              <span class="issue-code">${issue.code}</span>
              <span class="issue-sev sev-${sevClass}">${issue.severity}</span>
            </div>
            <span style="font-size:10px; color:#71717a;">${issue.category}</span>
          </div>
          <div class="issue-title">${issue.title}</div>
          <div class="issue-msg">${issue.message}</div>
          <div class="issue-fix-box">
            <span class="fix-text"><strong>Fix:</strong> ${issue.suggestion}</span>
          </div>
        `;
        findingsList.appendChild(card);
      });
    }

    if (data.diff_text) {
      const formattedDiff = data.diff_text.split('\n').map(line => {
        if (line.startsWith('+') && !line.startsWith('+++')) {
          return `<span class="diff-line-add">${escapeHtml(line)}</span>`;
        } else if (line.startsWith('-') && !line.startsWith('---')) {
          return `<span class="diff-line-del">${escapeHtml(line)}</span>`;
        }
        return escapeHtml(line);
      }).join('\n');
      diffCodeText.innerHTML = formattedDiff;
    } else {
      diffCodeText.textContent = '// Code is already optimal. No diff required.';
    }

    renderDockerCode();
    fetchPRMarkdown(codeEditor.value);
  }

  async function fetchPRMarkdown(code) {
    try {
      const data = await requestJson('/api/export-pr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      });
      prMarkdownOutput.value = data.pr_markdown;
    } catch (e) {
      console.error(e);
    }
  }

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ================= 6. ACTIONS =================
  if (btnApplyAllFixes) {
    btnApplyAllFixes.addEventListener('click', () => {
      if (currentAnalysis && currentAnalysis.refactored_code) {
        codeEditor.value = currentAnalysis.refactored_code;
        updateGutter();
        runAnalysis();
      }
    });
  }

  if (btnClearCode) {
    btnClearCode.addEventListener('click', () => {
      codeEditor.value = '';
      updateGutter();
      findingsList.innerHTML = `<div class="empty-state"><p>Code cleared.</p></div>`;
      metricGrade.textContent = '--';
      metricGrade.className = 'grade-badge';
      metricVulnsCount.textContent = '0 Vulnerabilities';
    });
  }

  if (btnFormatCode) {
    btnFormatCode.addEventListener('click', () => {
      if (currentAnalysis && currentAnalysis.refactored_code) {
        codeEditor.value = currentAnalysis.refactored_code;
        updateGutter();
      }
    });
  }

  if (btnExportPR) {
    btnExportPR.addEventListener('click', () => {
      const prTabBtn = document.getElementById('tab-btn-pr');
      if (prTabBtn) prTabBtn.click();
    });
  }

  if (btnCopyDiff) {
    btnCopyDiff.addEventListener('click', () => {
      if (currentAnalysis && currentAnalysis.diff_text) {
        navigator.clipboard.writeText(currentAnalysis.diff_text).then(() => {
          btnCopyDiff.textContent = 'Copied!';
          setTimeout(() => { btnCopyDiff.textContent = 'Copy Diff'; }, 2000);
        });
      }
    });
  }

  if (btnCopyDocker) {
    btnCopyDocker.addEventListener('click', () => {
      const textToCopy = dockerCodeDisplay.textContent;
      navigator.clipboard.writeText(textToCopy).then(() => {
        btnCopyDocker.textContent = 'Copied!';
        setTimeout(() => { btnCopyDocker.textContent = 'Copy File'; }, 2000);
      });
    });
  }

  if (btnCopyPRMd) {
    btnCopyPRMd.addEventListener('click', () => {
      navigator.clipboard.writeText(prMarkdownOutput.value).then(() => {
        btnCopyPRMd.textContent = 'Copied!';
        setTimeout(() => { btnCopyPRMd.textContent = 'Copy Markdown'; }, 2000);
      });
    });
  }

  // Initialize
  loadSnippets();
});
