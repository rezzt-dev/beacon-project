// sign-in: the token comes in the url fragment (never sent to the server in a request line or a
// referer), is exchanged once for a session cookie, and is wiped from the address bar.

const status = document.getElementById("signin-status");
const form = document.getElementById("signin-form");
const spanish = (navigator.language || "").startsWith("es");
const text = {
  signing: spanish ? "Iniciando sesión…" : "Signing in…",
  bad: spanish ? "El enlace no es válido. Ejecuta `beacon live --url` y abre el enlace que muestra." : "This link is not valid. Run `beacon live --url` and open the link it prints.",
  manual: spanish ? "Pega el token de acceso o abre el enlace de `beacon live --url`." : "Paste the sign-in token, or open the link from `beacon live --url`.",
  offline: spanish ? "No se puede contactar con beacon live. ¿Sigue en marcha?" : "beacon live is not reachable. Is it still running?",
};

async function signIn(token) {
  status.textContent = text.signing;
  let response;
  try {
    response = await fetch("/api/v1/session", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
  } catch {
    status.textContent = text.offline;
    form.hidden = false;
    return;
  }
  if (response.ok) {
    location.replace("/");
    return;
  }
  status.textContent = text.bad;
  form.hidden = false;
  document.getElementById("token").focus();
}

const fragment = new URLSearchParams(location.hash.slice(1));
const token = fragment.get("token");
history.replaceState(null, "", location.pathname);
if (token) {
  signIn(token);
} else {
  status.textContent = text.manual;
  form.hidden = false;
}
form.addEventListener("submit", (event) => {
  event.preventDefault();
  signIn(document.getElementById("token").value.trim());
});
