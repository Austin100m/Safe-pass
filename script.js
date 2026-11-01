// ---------- Helpers ----------
const $ = (id) => document.getElementById(id);

// SHA-1 hash in the browser -> uppercase hex string
async function sha1(text) {
  const data = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest("SHA-1", data);
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

// ---------- API: Have I Been Pwned (free, no key needed) ----------
// Returns how many times the password appears in known breaches (0 = not found)
async function getBreachCount(password) {
  const hash = await sha1(password);
  const prefix = hash.slice(0, 5);   // only this part is sent
  const suffix = hash.slice(5);      // compared locally

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "Add-Padding": "true" }, // hides response size from observers
  });
  if (!res.ok) throw new Error(`API error ${res.status}`);

  const text = await res.text();
  for (const line of text.split("\n")) {
    const [hashSuffix, count] = line.trim().split(":");
    if (hashSuffix === suffix) return parseInt(count, 10);
  }
  return 0;
}

// ---------- Strength meter (runs fully offline) ----------
function scorePassword(pw) {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return Math.min(score, 6);
}

const LEVELS = [
  { label: "Enter a password", color: "#b42318" },
  { label: "Very weak", color: "#b42318" },
  { label: "Weak", color: "#b42318" },
  { label: "Fair", color: "#b54708" },
  { label: "Good", color: "#b54708" },
  { label: "Strong", color: "#067647" },
  { label: "Very strong", color: "#067647" },
];

$("pw").addEventListener("input", (e) => {
  const pw = e.target.value;
  const s = pw ? scorePassword(pw) : 0;
  $("bar").style.width = `${(s / 6) * 100}%`;
  $("bar").style.background = LEVELS[s].color;
  $("strength").textContent = pw ? `Strength: ${LEVELS[s].label}` : "";
  $("result").textContent = "";
});

// ---------- Show / hide ----------
$("toggle").addEventListener("click", () => {
  const input = $("pw");
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  $("toggle").textContent = show ? "Hide" : "Show";
});

// ---------- Breach check ----------
$("check").addEventListener("click", async () => {
  const pw = $("pw").value;
  const out = $("result");
  if (!pw) {
    out.className = "err";
    out.textContent = "Enter a password first.";
    return;
  }
  $("check").disabled = true;
  out.className = "";
  out.textContent = "Checking…";
  try {
    const count = await getBreachCount(pw);
    if (count > 0) {
      out.className = "bad";
      out.textContent = `Found in ${count.toLocaleString()} breaches. Do not use this password.`;
    } else {
      out.className = "ok";
      out.textContent = "Not found in any known breach.";
    }
  } catch (err) {
    out.className = "err";
    out.textContent = "Could not reach the breach database. Check your connection and try again.";
    console.error(err);
  } finally {
    $("check").disabled = false;
  }
});

// ---------- Secure generator ----------
// Uses crypto.getRandomValues (NOT Math.random, which is predictable)
function generatePassword(length = 16) {
  const chars =
    "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_?";
  const limit = Math.floor(256 / chars.length) * chars.length; // avoid modulo bias
  let out = "";
  while (out.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    for (const b of bytes) {
      if (b < limit && out.length < length) out += chars[b % chars.length];
    }
  }
  return out;
}

$("gen").addEventListener("click", () => {
  $("gen-out").value = generatePassword(16);
});