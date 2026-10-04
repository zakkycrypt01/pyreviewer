/**
 * PyReviewer Frontend Application Controller
 * Handles code editing, synchronized gutter, AST review rendering, and Dockerfile exports.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const codeEditor = document.getElementById('code-editor');
  const editorGutter = document.getElementById('editor-gutter');
  const cursorPos = document.getElementById('cursor-pos');
  const snippetSelector = document.getElementById('snippet-selector');
  const btnRunAnalysis = document.getElementById('btn-run-analysis');
  const btnClearCode = document.getElementById('btn-clear-code');
  const btnFormatCode = document.getElementById('btn-format-code');
  const btnApplyAllFixes = document.getElementById('btn-apply-all-fixes');
  const btnExportPR = document.getElementById('btn-export-pr');
  const btnCopyDiff = document.getElementById('btn-copy-diff');
  const btnCopyDocker = document.getElementById('btn-copy-docker');
  const btnCopyPRMd = document.getElementById('btn-copy-pr-md');

  // Metrics DOM
  const metricGrade = document.getElementById('metric-grade');
  const metricVulnsCount = document.getElementById('metric-vulns-count');
  const metricMaintainability = document.getElementById('metric-maintainability');
  const metricComplexity = document.getElementById('metric-complexity');
  const metricLoc = document.getElementById('metric-loc');
  const metricFuncs = document.getElementById('metric-funcs');
  const metricDocker = document.getElementById('metric-docker');
  const fileStatusIndicator = document.getElementById('file-status-indicator');

  // Tabs DOM
  const paneTabs = document.querySelectorAll('.pane-tab');
  const tabContents = document.querySelectorAll('.tab-content');
  const findingsList = document.getElementById('findings-list');
  const findingsCountBadge = document.getElementById('findings-count-badge');
  const findingsSummaryText = document.getElementById('findings-summary-text');
  const diffCodeText = document.getElementById('diff-code-text');
  const dockerCodeDisplay = document.getElementById('docker-code-display');
  const prMarkdownOutput = document.getElementById('pr-markdown-output');
  const dockerSubtabs = document.querySelectorAll('.docker-subtab');

  // State
  let currentAnalysis = null;
  let activeDockerFile = 'dockerfile';
  let snippets = {};

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

  // Support Tab key in editor
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
    if (!currentAnalysis) return;
    if (activeDockerFile === 'dockerfile') {
      dockerCodeDisplay.textContent = currentAnalysis.dockerfile || '// No Dockerfile generated';
    } else if (activeDockerFile === 'render_yaml') {
      dockerCodeDisplay.textContent = currentAnalysis.render_yaml || '// No render.yaml generated';
    } else if (activeDockerFile === 'dockerignore') {
      dockerCodeDisplay.textContent = currentAnalysis.dockerignore || '// No .dockerignore generated';
    }
  }

  // ================= 3. SNIPPET LOADER =================
  async function loadSnippets() {
    try {
      const res = await fetch('/api/snippets');
      if (res.ok) {
        snippets = await res.json();
        const selected = snippetSelector.value;
        if (snippets[selected]) {
          codeEditor.value = snippets[selected];
          updateGutter();
          runAnalysis();
        }
      }
    } catch (e) {
      console.log('Using default client snippet fallback.');
    }
  }

  snippetSelector.addEventListener('change', () => {
    const val = snippetSelector.value;
    if (snippets[val]) {
      codeEditor.value = snippets[val];
      updateGutter();
      runAnalysis();
    }
  });

  // ================= 4. AST CODE REVIEW EXECUTION =================
  async function runAnalysis() {
    const code = codeEditor.value;
    if (!code.trim()) {
      alert('Please enter Python code to review.');
      return;
    }

    btnRunAnalysis.disabled = true;
    btnRunAnalysis.innerHTML = '<span>Analyzing AST...</span>';

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      });

      if (!response.ok) {
        throw new Error('Analysis failed with status ' + response.status);
      }

      const data = await response.json();
      currentAnalysis = data;
      renderAnalysis(data);
      fileStatusIndicator.textContent = 'Analyzed';
      fileStatusIndicator.style.color = '#34d399';
    } catch (err) {
      console.error(err);
      alert('Error analyzing code: ' + err.message);
    } finally {
      btnRunAnalysis.disabled = false;
      btnRunAnalysis.innerHTML = `
        <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
        <span>Run AST Review</span>
      `;
    }
  }

  btnRunAnalysis.addEventListener('click', runAnalysis);

  function renderAnalysis(data) {
    const metrics = data.metrics;
    const issues = data.issues || [];

    // 1. Update Metrics HUD
    metricGrade.textContent = metrics.security_rating;
    metricGrade.className = 'grade-badge grade-' + metrics.security_rating.toLowerCase();

    const criticalCount = issues.filter(i => i.severity === 'CRITICAL').length;
    metricVulnsCount.textContent = `${criticalCount} Critical Vuln${criticalCount === 1 ? '' : 's'}`;

    metricMaintainability.textContent = metrics.maintainability_score;
    metricComplexity.textContent = metrics.cyclomatic_complexity;
    metricLoc.textContent = metrics.code_lines;
    metricFuncs.textContent = `${metrics.functions_count} func${metrics.functions_count === 1 ? '' : 's'}`;
    metricDocker.textContent = metrics.container_readiness;

    // 2. Render Findings List
    findingsCountBadge.textContent = issues.length;
    findingsSummaryText.textContent = `Found ${issues.length} issue${issues.length === 1 ? '' : 's'} (${criticalCount} critical)`;
    findingsList.innerHTML = '';

    if (issues.length === 0) {
      findingsList.innerHTML = `
        <div class="empty-state">
          <svg class="empty-icon" style="color:#10b981; opacity:1;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14M22 4L12 14.01l-3-3"/></svg>
          <p style="color:#f4f4f5; font-weight:600;">Clean, Idiomatic Python Code!</p>
          <span style="font-size:11px; color:#71717a;">No security vulnerabilities, blocking async calls, or anti-patterns detected. Ready for Docker containerization!</span>
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

    // 3. Render Unified Diff
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

    // 4. Render Docker Files
    renderDockerCode();

    // 5. Render PR Markdown
    fetchPRMarkdown(codeEditor.value);
  }

  async function fetchPRMarkdown(code) {
    try {
      const res = await fetch('/api/export-pr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      });
      if (res.ok) {
        const data = await res.json();
        prMarkdownOutput.value = data.pr_markdown;
      }
    } catch (e) {
      console.error(e);
    }
  }

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ================= 5. ACTIONS =================
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
