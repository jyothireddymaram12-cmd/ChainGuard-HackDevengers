
const authScreen=document.getElementById("authScreen");
const signinForm=document.getElementById("signinForm");
const signupForm=document.getElementById("signupForm");
const toast=document.getElementById("toast");
const input=document.getElementById("messageInput");
const count=document.getElementById("charCount");
const clearBtn=document.getElementById("clearBtn");
const scanBtn=document.getElementById("scanBtn");
const report=document.getElementById("report");
const emptyState=document.getElementById("emptyState");
const scoreValue=document.getElementById("scoreValue");
const scoreBar=document.getElementById("scoreBar");
const riskTitle=document.getElementById("riskTitle");
const verdict=document.getElementById("verdict");
const aiExplanation=document.getElementById("aiExplanation");
const recommendation=document.getElementById("recommendation");
const signalList=document.getElementById("signalList");
const signinEmail=document.getElementById("signinEmail");
const signinPassword=document.getElementById("signinPassword");
const signupName=document.getElementById("signupName");
const signupEmail=document.getElementById("signupEmail");
const signupPassword=document.getElementById("signupPassword");
const forgotBtn=document.getElementById("forgotBtn");
const userMenuBtn=document.getElementById("userMenuBtn");
const userDropdown=document.getElementById("userDropdown");
const logoutBtn=document.getElementById("logoutBtn");

function showToast(m){toast.textContent=m;toast.classList.add("show");setTimeout(()=>toast.classList.remove("show"),2200)}
function updateUserUI(u){
  document.getElementById("userNameDisplay").textContent=u.name;
  document.getElementById("userEmailDisplay").textContent=u.email;
  document.querySelector(".user-avatar").textContent=u.name.split(/\s+/).map(x=>x[0]).slice(0,2).join("").toUpperCase();
}
function switchAuth(m){
  document.querySelectorAll(".auth-tab").forEach(t=>t.classList.toggle("active",t.dataset.authTab===m));
  signinForm.classList.toggle("hidden",m!=="signin");
  signupForm.classList.toggle("hidden",m!=="signup");
}
async function authRequest(url,payload){
  const r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  const d=await r.json();
  if(!r.ok) throw new Error(d.error||"Authentication failed");
  return d;
}
document.querySelectorAll(".auth-tab").forEach(t=>t.onclick=()=>switchAuth(t.dataset.authTab));
signinForm.onsubmit=async e=>{
  e.preventDefault();
  try{
    const d=await authRequest("/api/auth/login",{email:signinEmail.value.trim(),password:signinPassword.value});
    updateUserUI(d.user);authScreen.classList.add("hidden");showToast("Welcome back, "+d.user.name+"!");await loadServerScans();
  }catch(err){showToast(err.message)}
};
signupForm.onsubmit=async e=>{
  e.preventDefault();
  if(signupPassword.value.length<6)return showToast("Password must be at least 6 characters.");
  try{
    const d=await authRequest("/api/auth/signup",{name:signupName.value.trim(),email:signupEmail.value.trim(),password:signupPassword.value});
    updateUserUI(d.user);authScreen.classList.add("hidden");showToast("Account created successfully!");await loadServerScans();
  }catch(err){showToast(err.message)}
};
document.querySelectorAll(".show-pass").forEach(b=>b.onclick=()=>{const x=document.getElementById(b.dataset.target);x.type=x.type==="password"?"text":"password";b.textContent=x.type==="password"?"Show":"Hide"});
forgotBtn.onclick=()=>showToast("For the prototype, password recovery is not enabled yet.");
userMenuBtn.onclick=()=>userDropdown.classList.toggle("open");
logoutBtn.onclick=async()=>{
  await fetch("/api/auth/logout",{method:"POST"});
  authScreen.classList.remove("hidden");switchAuth("signin");signinForm.reset();showToast("Signed out.");
};
async function loadCurrentUser(){
  try{
    const r=await fetch("/api/auth/me"); const d=await r.json();
    if(d.user){updateUserUI(d.user);authScreen.classList.add("hidden");await loadServerScans();}
  }catch(e){console.warn(e)}
}
const HISTORY_KEY = "chainguard_scan_history_v1";
const THREAT_KEY = "chainguard_threat_counts_v1";
let lastResult = null;
let lastInput = "";

function getHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); }
  catch { return []; }
}
function getThreats() {
  try { return JSON.parse(localStorage.getItem(THREAT_KEY) || "{}"); }
  catch { return {}; }
}
function saveScan(result, source, text) {
  const history = getHistory();
  history.unshift({
    score: result.score, level: result.level, title: result.title,
    source, preview: text.slice(0, 92), time: new Date().toLocaleString()
  });
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 20)));

  const counts = getThreats();
  (result.signals || []).forEach(s => {
    const k = s.label.toLowerCase();
    const key = k.includes("reward") ? "reward" :
                k.includes("forward") ? "forward" :
                k.includes("credential") ? "credential" :
                k.includes("financial") || k.includes("payment") ? "payment" :
                k.includes("link") ? "link" :
                k.includes("urgency") || k.includes("pressure") ? "urgency" : null;
    if (key) counts[key] = (counts[key] || 0) + 1;
  });
  localStorage.setItem(THREAT_KEY, JSON.stringify(counts));
  renderDashboard();
}

async function saveServerScan(result, source, text, aiText=""){
  try{
    await fetch("/api/scans",{
      method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        input_type:source,input_preview:text,risk_score:Number(result.score)||0,
        risk_level:result.level||"low",
        signals:(result.signals||[]).map(s=>typeof s==="string"?s:s.label),
        ai_explanation:aiText
      })
    });
  }catch(e){console.warn("Could not save scan:",e)}
}
async function loadServerScans(){
  try{
    const r=await fetch("/api/scans");
    if(!r.ok)return;
    const d=await r.json();
    const items=d.scans||[];
    document.getElementById("statTotal").textContent=items.length;
    document.getElementById("statHigh").textContent=items.filter(x=>x.risk_level==="high").length;
    document.getElementById("statMedium").textContent=items.filter(x=>x.risk_level==="medium").length;
    document.getElementById("statLow").textContent=items.filter(x=>x.risk_level==="low").length;
    const list=document.getElementById("historyList");
    list.innerHTML=items.length?items.slice(0,10).map(x=>
      `<div class="history-item"><span class="history-dot ${x.risk_level}"></span><div class="history-text"><strong>${escapeHtml(x.input_preview)}</strong><small>${escapeHtml(x.input_type)} • ${escapeHtml(x.created_at)}</small></div><span class="history-score">${x.risk_score}</span></div>`
    ).join(""):`<div class="history-empty">No scans yet.</div>`;
  }catch(e){console.warn(e)}
}
function renderDashboard() {
  const history = getHistory();
  const high = history.filter(x => x.level === "high").length;
  const medium = history.filter(x => x.level === "medium").length;
  const low = history.filter(x => x.level === "low").length;
  document.getElementById("statTotal").textContent = history.length;
  document.getElementById("statHigh").textContent = high;
  document.getElementById("statMedium").textContent = medium;
  document.getElementById("statLow").textContent = low;

  const list = document.getElementById("historyList");
  list.innerHTML = history.length ? history.slice(0,10).map(x =>
    `<div class="history-item">
      <span class="history-dot ${x.level}"></span>
      <div class="history-text"><strong>${escapeHtml(x.preview)}</strong><small>${escapeHtml(x.source)} • ${escapeHtml(x.time)}</small></div>
      <span class="history-score">${x.score}</span>
    </div>`).join("") :
    `<div class="history-empty">No scans yet. Analyze a message to build your local history.</div>`;

  const counts = getThreats();
  const max = Math.max(1, ...Object.values(counts));
  ["reward","forward","credential","payment","link","urgency"].forEach(k => {
    const el = document.getElementById("bar" + k.charAt(0).toUpperCase() + k.slice(1));
    if (el) el.style.width = `${Math.max(4, ((counts[k] || 0) / max) * 100)}%`;
  });
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
}
renderDashboard();


document.querySelectorAll(".scan-tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".scan-tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(tab.dataset.tab).classList.add("active");
  });
});


input.addEventListener("input", () => count.textContent = `${input.value.length} characters`);
clearBtn.addEventListener("click", () => {
  input.value = "";
  count.textContent = "0 characters";
  report.classList.add("hidden");
  emptyState.classList.remove("hidden");
});

document.querySelectorAll("[data-example]").forEach(btn => {
  btn.addEventListener("click", () => {
    const examples = {
      reward: "🎉 Congratulations! You have won ₹10,000 cashback! Forward this message to 10 people within 5 minutes and click https://claim-reward.example to receive your prize. Act now!",
      bank: "Your bank account will be blocked today. Verify immediately by sharing your OTP and clicking https://secure-account.example. Do not ignore this urgent message.",
      safe: "Hey! The library workshop starts at 10 AM tomorrow. Please bring your college ID and notebook. See you there!"
    };
    input.value = examples[btn.dataset.example];
    count.textContent = `${input.value.length} characters`;
    document.getElementById("scanner").scrollIntoView({behavior:"smooth", block:"center"});
  });
});

async function analyzeWithBackend(text) {
  const response = await fetch("/api/analyze", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({message: text})
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Analysis failed");
  return data;
}


async function analyzeUrl(url) {
  const response = await fetch("/api/analyze-url", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({url})
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "URL analysis failed");
  return data;
}

async function showUrlResult(result) {
  scoreValue.textContent = result.score;
  scoreBar.style.width = `${result.score}%`;
  riskTitle.textContent = result.level === "high" ? "High risk URL" :
                          result.level === "medium" ? "Suspicious URL" : "Low risk URL";
  verdict.textContent = result.message;
  aiExplanation.textContent = result.signals.length
    ? `ChainGuard found ${result.signals.length} URL signal${result.signals.length > 1 ? "s" : ""}: ${result.signals.join(", ")}.`
    : "The URL did not match the main warning patterns in this prototype. Treat unfamiliar links cautiously.";
  recommendation.textContent = result.level === "high"
    ? "Do not log in, enter payment details, download files, or share credentials on this destination."
    : result.level === "medium"
    ? "Verify the domain through an official source before entering sensitive information."
    : "No major URL warning pattern was detected. Still verify unfamiliar links before using them.";

  signalList.innerHTML = result.signals.length
    ? result.signals.map(s => `<div class="signal-item"><span class="mark">⚠</span>${s}</div>`).join("")
    : `<div class="signal-item"><span class="mark">✓</span>No major URL warning signal matched</div>`;

  scoreBar.style.background = result.level === "high" ? "var(--danger)" :
                               result.level === "medium" ? "var(--warning)" : "var(--mint)";
  scoreValue.style.color = result.level === "high" ? "var(--danger)" :
                            result.level === "medium" ? "var(--warning)" : "var(--mint)";
  emptyState.classList.add("hidden");
  report.classList.remove("hidden");
  lastResult = {score: result.score, level: result.level, title: riskTitle.textContent, verdict: result.message, signals: result.signals.map(s => ({label:s})), recommendation: recommendation.textContent};
  lastInput = result.url;
  saveScan(lastResult, "URL", result.url);
  try {
    const ai = await requestAIExplanation(result.url, lastResult);
    aiExplanation.textContent = ai.ai;
    document.getElementById("aiLiveBadge").textContent = ai.live ? "🤖 Live Gemini AI" : "🤖 AI fallback mode";
    lastResult.explanation = ai.ai;
    await saveServerScan(lastResult, "URL", result.url, ai.ai);
    await loadServerScans();
  } catch (e) {
    await saveServerScan(lastResult, "URL", result.url, "");
    await loadServerScans();
    console.warn("AI URL explanation unavailable:", e);
  }
}

urlScanBtn.addEventListener("click", async () => {
  const url = urlInput.value.trim();
  if (!url) { urlInput.focus(); return; }
  urlScanBtn.disabled = true;
  urlScanBtn.innerHTML = "Checking…";
  try {
    showUrlResult(await analyzeUrl(url));
  } catch (e) {
    alert("URL analysis failed. Make sure the Flask server is running.");
    console.error(e);
  } finally {
    urlScanBtn.disabled = false;
    urlScanBtn.innerHTML = "Check URL <span>→</span>";
  }
});

imageInput.addEventListener("change", () => {
  selectedImage = imageInput.files[0] || null;
  if (selectedImage) {
    imageStatus.textContent = `Selected: ${selectedImage.name}`;
    ocrScanBtn.disabled = false;
  } else {
    imageStatus.textContent = "";
    ocrScanBtn.disabled = true;
  }
});

ocrScanBtn.addEventListener("click", async () => {
  if (!selectedImage) return;
  ocrScanBtn.disabled = true;
  ocrScanBtn.innerHTML = "Reading screenshot…";
  imageStatus.textContent = "Extracting visible text. This may take a few seconds…";
  try {
    if (!window.Tesseract) throw new Error("OCR library did not load");
    const result = await Tesseract.recognize(selectedImage, "eng");
    const extracted = (result.data.text || "").trim();
    if (!extracted) {
      imageStatus.textContent = "No readable text found. Try a clearer screenshot.";
      return;
    }
    input.value = extracted;
    count.textContent = `${extracted.length} characters`;
    document.querySelector('[data-tab="messageTab"]').click();
    scanBtn.click();
  } catch (e) {
    imageStatus.textContent = "Could not read this image. You can paste the message manually.";
    console.error(e);
  } finally {
    ocrScanBtn.disabled = !selectedImage;
    ocrScanBtn.innerHTML = "Extract & analyze <span>→</span>";
  }
});


document.getElementById("clearHistoryBtn").addEventListener("click", () => {
  showToast("Database history is retained for the account in this prototype.");
});

document.getElementById("exportBtn").addEventListener("click", () => {
  if (!lastResult) { alert("Analyze something first."); return; }
  const reportText = [
    "CHAIN GUARD — SECURITY REPORT",
    "==============================",
    `Risk: ${lastResult.title}`,
    `Score: ${lastResult.score}/100`,
    "",
    "Detected signals:",
    ...(lastResult.signals || []).map(s => `- ${s.label}`),
    "",
    "Explanation:",
    lastResult.explanation || lastResult.verdict || "",
    "",
    "Recommended action:",
    lastResult.recommendation || "",
    "",
    "Prototype disclaimer: A risk score is not proof that content is malicious."
  ].join("\n");
  const blob = new Blob([reportText], {type:"text/plain"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "ChainGuard_Report.txt";
  a.click();
  URL.revokeObjectURL(a.href);
});

document.getElementById("shareBtn").addEventListener("click", async () => {
  if (!lastResult) { alert("Analyze something first."); return; }
  const text = `ChainGuard result: ${lastResult.title} — ${lastResult.score}/100. Detected ${lastResult.signals?.length || 0} warning signals.`;
  if (navigator.share) {
    try { await navigator.share({title:"ChainGuard Security Result", text}); } catch {}
  } else {
    await navigator.clipboard.writeText(text);
    alert("Result copied to clipboard.");
  }
});

scanBtn.addEventListener("click", async () => {
  const text = input.value.trim();
  if (!text) {
    input.focus();
    input.style.borderColor = "rgba(255,107,117,.6)";
    setTimeout(() => input.style.borderColor = "", 900);
    return;
  }

  scanBtn.disabled = true;
  scanBtn.innerHTML = "Analyzing…";

  try {
    const result = await analyzeWithBackend(text);

    scoreValue.textContent = result.score;
    scoreBar.style.width = `${result.score}%`;
    riskTitle.textContent = result.title;
    verdict.textContent = result.verdict;
    aiExplanation.textContent = result.explanation;
    recommendation.textContent = result.recommendation;

    signalList.innerHTML = result.signals.length
      ? result.signals.map(s => `<div class="signal-item"><span class="mark">⚠</span>${s.label}</div>`).join("")
      : `<div class="signal-item"><span class="mark">✓</span>No major warning signal matched</div>`;

    scoreBar.style.background =
      result.level === "high" ? "var(--danger)" :
      result.level === "medium" ? "var(--warning)" : "var(--mint)";

    scoreValue.style.color =
      result.level === "high" ? "var(--danger)" :
      result.level === "medium" ? "var(--warning)" : "var(--mint)";

    emptyState.classList.add("hidden");
    report.classList.remove("hidden");
    lastResult = result;
    lastInput = text;
    saveScan(result, "Message", text);
    try {
      const ai = await requestAIExplanation(text, result);
      aiExplanation.textContent = ai.ai;
      document.getElementById("aiLiveBadge").textContent = ai.live ? "🤖 Live Gemini AI" : "🤖 AI fallback mode";
      if (lastResult) lastResult.explanation = ai.ai;
      await saveServerScan(result, "Message", text, ai.ai);
      await loadServerScans();
    } catch (e) {
      await saveServerScan(result, "Message", text, "");
      await loadServerScans();
      console.warn("AI explanation unavailable:", e);
    }
  } catch (error) {
    alert("Could not connect to ChainGuard backend. Start it with: python app.py");
    console.error(error);
  } finally {
    scanBtn.disabled = false;
    scanBtn.innerHTML = "Analyze again <span>→</span>";
  }
});


async function requestAIExplanation(text, result) {
  const response = await fetch("/api/ai-explain", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({message:text,result})
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "AI explanation failed");
  return data;
}
async function askChainGuard(question) {
  const response = await fetch("/api/ai-chat", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({question, context:lastInput ? `Latest scanned content: ${lastInput}\nLatest result: ${lastResult?.score}/100, ${lastResult?.title}` : ""})
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "AI chat failed");
  return data;
}
function addAIMessage(role, text) {
  const box=document.getElementById("aiChatMessages");
  const el=document.createElement("div");
  el.className=`ai-msg ${role}`;
  el.innerHTML=`<span>${role==="user"?"YOU":"AI"}</span><p></p>`;
  el.querySelector("p").textContent=text;
  box.appendChild(el);
  box.scrollTop=box.scrollHeight;
}
document.querySelectorAll("[data-ai-prompt]").forEach(b=>b.addEventListener("click",()=> {
  document.getElementById("aiQuestion").value=b.dataset.aiPrompt;
  document.getElementById("aiAssistant").scrollIntoView({behavior:"smooth",block:"center"});
  document.getElementById("aiQuestion").focus();
}));
document.getElementById("aiChatForm").addEventListener("submit",async e=>{
  e.preventDefault();
  const input=document.getElementById("aiQuestion"), q=input.value.trim();
  if(!q)return;
  addAIMessage("user",q); input.value="";
  addAIMessage("bot","Thinking…");
  const box=document.getElementById("aiChatMessages"), last=box.lastElementChild;
  try {
    const data=await askChainGuard(q);
    last.querySelector("p").textContent=data.answer;
    document.getElementById("aiLiveBadge").textContent=data.live?"🤖 Live Gemini AI":"🤖 AI fallback mode";
  } catch(err) {
    last.querySelector("p").textContent="AI is temporarily unavailable. Use the rule-based result above and verify through official channels.";
    console.error(err);
  }
});

loadCurrentUser();


// Safety Center: lightweight client-side checklist for the hackathon demo.
const safetyChecks = [...document.querySelectorAll("[data-safety]")];
const safetyScoreEl = document.getElementById("safetyScore");
const safetyProgressEl = document.getElementById("safetyProgress");
const SAFETY_KEY = "chainguard_safety_checklist_v1";

function updateSafetyScore() {
  const done = safetyChecks.filter(c => c.checked).length;
  const percent = Math.round((done / Math.max(1, safetyChecks.length)) * 100);
  if (safetyScoreEl) safetyScoreEl.textContent = percent + "%";
  if (safetyProgressEl) safetyProgressEl.style.width = percent + "%";
  localStorage.setItem(SAFETY_KEY, JSON.stringify(safetyChecks.map(c => ({key:c.dataset.safety, checked:c.checked}))));
}
try {
  const saved = JSON.parse(localStorage.getItem(SAFETY_KEY) || "[]");
  saved.forEach(item => {
    const check = document.querySelector(`[data-safety="${item.key}"]`);
    if (check) check.checked = !!item.checked;
  });
} catch {}
safetyChecks.forEach(c => c.addEventListener("change", updateSafetyScore));
updateSafetyScore();

document.querySelectorAll(".playbook-card").forEach(card => {
  card.addEventListener("click", () => {
    const prompt = card.dataset.aiPrompt || "";
    const input = document.getElementById("aiQuestion");
    const aiSection = document.getElementById("aiAssistant");
    if (input && aiSection) {
      input.value = prompt;
      aiSection.scrollIntoView({behavior:"smooth", block:"center"});
      setTimeout(() => input.focus(), 450);
    }
  });
});
