(function () {
  'use strict';

  /* ---------- Mobile nav ---------- */
  var toggle = document.querySelector('.nav-toggle');
  var nav = document.getElementById('nav');
  if (toggle && nav) {
    toggle.addEventListener('click', function () {
      var open = nav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(open));
    });
    nav.addEventListener('click', function (e) {
      if (e.target.tagName === 'A') {
        nav.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  /* ---------- Cutoff demo (illustrative, made-up events) ---------- */
  var EVENTS = [
    { m: 0, label: 'Jan 2026', what: 'Repo created; first commits land', leak: 'history' },
    { m: 1, label: 'Feb 2026', what: 'parser 1.0 released to the package index', leak: 'package' },
    { m: 2, label: 'Mar 2026', what: 'Bug report filed in the issue tracker', leak: 'issue' },
    { m: 3, label: 'Apr 2026', what: 'Fix merged: the pull request with the answer', leak: 'pr' },
    { m: 4, label: 'May 2026', what: 'parser 1.1 published with the fix', leak: 'package' },
    { m: 5, label: 'Jun 2026', what: 'Blog post explaining the fix', leak: 'web' },
    { m: 6, label: 'Jul 2026', what: 'Task copied into a public benchmark cache', leak: 'cache' }
  ];
  var CUTOFF_LABELS = ['Jan 2026', 'Feb 2026', 'Mar 2026', 'Apr 2026', 'May 2026', 'Jun 2026', 'Jul 2026', 'Aug 2026'];
  var range = document.getElementById('cutoff-range');
  var dateEl = document.getElementById('cutoff-date');
  var summary = document.getElementById('cutoff-summary');
  var list = document.getElementById('timeline');
  var mode = 'sealed';

  function renderCutoff() {
    if (!range) return;
    var v = parseInt(range.value, 10);
    dateEl.textContent = CUTOFF_LABELS[v];
    var html = '';
    var hidden = 0, leaked = 0, cutDrawn = false;
    EVENTS.forEach(function (ev) {
      var after = ev.m >= v;
      if (after && !cutDrawn) {
        html += '<li class="cut"><span class="when">cutoff</span><span class="what">Task created here (' + CUTOFF_LABELS[v] + ')</span><span></span></li>';
        cutDrawn = true;
      }
      var cls, state;
      if (!after) { cls = 'in'; state = 'reachable'; }
      else if (mode === 'sealed') { cls = 'out'; state = 'sealed'; hidden++; }
      else { cls = 'leak'; state = 'leak'; leaked++; }
      html += '<li class="' + cls + '"><span class="when">' + ev.label + '</span><span class="what">' + ev.what + '</span><span class="state">' + state + '</span></li>';
    });
    if (!cutDrawn) {
      html += '<li class="cut"><span class="when">cutoff</span><span class="what">Task created here (' + CUTOFF_LABELS[v] + ')</span><span></span></li>';
    }
    list.innerHTML = html;
    if (mode === 'sealed') {
      summary.textContent = hidden === 0
        ? 'Nothing in this example is newer than the cutoff, so there is nothing to seal.'
        : hidden + ' later event' + (hidden > 1 ? 's are' : ' is') + ' unreachable. The agent has to derive the fix.';
    } else {
      summary.textContent = leaked === 0
        ? 'Nothing newer exists yet, so there is nothing to leak.'
        : leaked + ' later event' + (leaked > 1 ? 's are' : ' is') + ' still reachable in an open world. The agent could retrieve the answer.';
    }
  }
  if (range) {
    range.addEventListener('input', renderCutoff);
    document.querySelectorAll('.presets button').forEach(function (b) {
      b.addEventListener('click', function () { range.value = b.getAttribute('data-v'); renderCutoff(); });
    });
    document.querySelectorAll('.seg button').forEach(function (b) {
      b.addEventListener('click', function () {
        mode = b.getAttribute('data-mode');
        document.querySelectorAll('.seg button').forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); });
        renderCutoff();
      });
    });
    renderCutoff();
  }

  /* ---------- Run stepper (from README / ARCHITECTURE) ---------- */
  var STEPS = [
    { t: 'Stage the world', z: 'online', title: 'Build a frozen world', text: 'On the online staging host, the sealer builds the world for a task: the repo cut at the base commit, a root filesystem stamped at the cutoff, and a package mirror and web archive dated at or before it.' },
    { t: 'Run sealcheck', z: 'online', title: 'Prove nothing newer is reachable', text: 'sealcheck scans the frozen world for anything created after the cutoff. This is the gate: the run host only receives a world that passes.' },
    { t: 'Boot the AgentVM', z: 'offline', title: 'The agent works as root in a microVM', text: 'On the offline run host, the agent runs inside a Firecracker AgentVM. Its clock is the guest clock, and it can only reach what the frozen world provides.' },
    { t: 'Serve from NetVM', z: 'offline', title: 'All network traffic goes to the frozen world', text: 'A NetVM answers only from the frozen world. Model traffic is routed separately, through a default-deny gateway.' },
    { t: 'Extract the work', z: 'offline', title: 'A throwaway VM pulls out the result', text: 'When the agent stops, a separate ExtractorVM pulls out its work, so nothing the agent controls is trusted by the grader.' },
    { t: 'Grade it clean', z: 'offline', title: 'Three passes in a clean GraderVM', text: 'A clean GraderVM the agent never touched runs the tests three ways: normal, mutant and equivalence. Together they help detect forged results.' },
    { t: 'Sign the record', z: 'offline', title: 'The host signs everything', text: 'The host signs a record of the run, including how well each channel was closed. Anyone can check it later with the verify command.' }
  ];
  var stepsEl = document.getElementById('steps');
  if (stepsEl) {
    var cur = 0;
    var tagEl = document.getElementById('step-tag');
    var titleEl = document.getElementById('step-title');
    var textEl = document.getElementById('step-text');
    var prev = document.getElementById('step-prev');
    var next = document.getElementById('step-next');
    STEPS.forEach(function (s, i) {
      var li = document.createElement('li');
      li.setAttribute('role', 'presentation');
      var b = document.createElement('button');
      b.type = 'button';
      b.setAttribute('role', 'tab');
      b.innerHTML = '<span class="n">' + (i + 1) + '</span><span></span>';
      b.lastChild.textContent = s.t;
      b.addEventListener('click', function () { go(i); });
      li.appendChild(b);
      stepsEl.appendChild(li);
    });
    function go(i) {
      cur = Math.max(0, Math.min(STEPS.length - 1, i));
      var s = STEPS[cur];
      stepsEl.querySelectorAll('button').forEach(function (b, j) { b.setAttribute('aria-selected', String(j === cur)); });
      tagEl.innerHTML = 'Step ' + (cur + 1) + ' of ' + STEPS.length + ' <span class="zone ' + (s.z === 'online' ? 'on' : 'off') + '">' + s.z + '</span>';
      titleEl.textContent = s.title;
      textEl.textContent = s.text;
      prev.disabled = cur === 0; next.disabled = cur === STEPS.length - 1;
      prev.style.opacity = prev.disabled ? .4 : 1; next.style.opacity = next.disabled ? .4 : 1;
    }
    prev.addEventListener('click', function () { go(cur - 1); });
    next.addEventListener('click', function () { go(cur + 1); });
    go(0);
  }

  /* ---------- CLI tabs (planned commands, from README) ---------- */
  var CLI = [
    { c: 'seal', out: '<span class="p">$</span> hermetic seal --task &lt;id&gt;\n<span class="c"># compute cutoffs, build the world bundle and manifest\n# arguments fixed by the spec</span>' },
    { c: 'verify-bundle', out: '<span class="p">$</span> hermetic verify-bundle\n<span class="c"># run sealcheck against a bundle\n# arguments still to be designed</span>' },
    { c: 'probe', out: '<span class="p">$</span> hermetic probe\n<span class="c"># escape probe from a rooted throwaway AgentVM\n# arguments still to be designed</span>' },
    { c: 'run', out: '<span class="p">$</span> hermetic run\n<span class="c"># boot, work, stop, extract, grade, sign\n# arguments still to be designed</span>' },
    { c: 'verify', out: '<span class="p">$</span> hermetic verify\n<span class="c"># check a signed run record\n# arguments still to be designed</span>' }
  ];
  var tabs = document.getElementById('cli-tabs');
  var body = document.getElementById('cli-body');
  if (tabs && body) {
    CLI.forEach(function (x, i) {
      var b = document.createElement('button');
      b.type = 'button'; b.setAttribute('role', 'tab'); b.textContent = x.c;
      b.addEventListener('click', function () { sel(i); });
      tabs.appendChild(b);
    });
    function sel(i) {
      tabs.querySelectorAll('button').forEach(function (b, j) { b.setAttribute('aria-selected', String(i === j)); });
      body.innerHTML = CLI[i].out;
    }
    sel(0);
  }

  /* ---------- Count-up numbers + reveal on scroll ---------- */
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  function animateCount(el) {
    var target = parseFloat(el.getAttribute('data-count'));
    var dec = parseInt(el.getAttribute('data-decimals') || '0', 10);
    var suf = el.getAttribute('data-suffix') || '';
    var start = null, dur = 900;
    function tick(ts) {
      if (start === null) start = ts;
      var p = Math.min((ts - start) / dur, 1);
      var e = 1 - Math.pow(1 - p, 3);
      el.textContent = (target * e).toFixed(dec) + suf;
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }
  var targets = document.querySelectorAll('.feature, .stat, .prop, .card, .roadmap li, details');
  targets.forEach(function (t) { t.classList.add('reveal'); });
  if ('IntersectionObserver' in window && !reduce) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        en.target.classList.add('in');
        en.target.querySelectorAll('[data-count]').forEach(animateCount);
        if (en.target.hasAttribute('data-count')) animateCount(en.target);
        io.unobserve(en.target);
      });
    }, { threshold: 0.15 });
    targets.forEach(function (t) { io.observe(t); });
  } else {
    targets.forEach(function (t) { t.classList.add('in'); });
  }
})();
