(function () {
  const $ = (s, r) => (r || document).querySelector(s);
  const size = (b) => b > 1048576 ? (b / 1048576).toFixed(1) + " Mo" : Math.max(1, Math.round(b / 1024)) + " Ko";

  function banner(box, cls, title, text, extra) {
    box.replaceChildren();
    const d = document.createElement("div");
    d.className = "ban " + cls;
    const t = document.createElement("div");
    const b = document.createElement("b"); b.textContent = title;
    const s = document.createElement("div"); s.textContent = text;
    t.append(b, s); d.append(t);
    if (extra) d.append(extra);
    box.append(d);
  }

  // Sélecteurs de fichiers + glisser-déposer
  document.querySelectorAll("[data-pick]").forEach((btn) => {
    const input = document.getElementById(btn.dataset.pick);
    btn.addEventListener("click", () => input.click());
    input.addEventListener("change", () => {
      const info = document.getElementById(input.id === "file" ? "fileinfo" : "keyinfo");
      const f = input.files[0];
      info.hidden = !f;
      if (f) info.textContent = f.name + " · " + size(f.size);
    });
  });
  document.querySelectorAll("[data-drop]").forEach((zone) => {
    const input = $("input[type=file]", zone);
    ["dragover", "dragenter"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("over"); }));
    ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, () => zone.classList.remove("over")));
    zone.addEventListener("drop", (e) => {
      e.preventDefault();
      if (e.dataTransfer.files.length) { input.files = e.dataTransfer.files; input.dispatchEvent(new Event("change")); }
    });
  });

  // Chiffrer / déchiffrer sans recharger la page
  const form = $("form[data-ajax]");
  if (form) form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const go = $("#go"), box = $("#result"), label = go.textContent;
    go.disabled = true; go.textContent = form.dataset.busy;
    box.replaceChildren(); const p = document.createElement("div"); p.className = "progress"; p.append(document.createElement("i")); box.append(p);
    try {
      const res = await fetch(form.action, { method: "POST", body: new FormData(form) });
      if (!res.ok) {
        let msg = "Une erreur est survenue.";
        try { msg = (await res.json()).error || msg; } catch (_) {}
        banner(box, "err", "Opération impossible", msg);
      } else {
        const cd = res.headers.get("Content-Disposition") || "";
        const m = cd.match(/filename\*=UTF-8''([^;]+)/i) || cd.match(/filename="?([^";]+)"?/i);
        const name = m ? decodeURIComponent(m[1]) : "resultat";
        const blob = await res.blob();
        const a = document.createElement("a");
        a.className = "btn pri"; a.href = URL.createObjectURL(blob); a.download = name;
        a.textContent = "Télécharger " + (name.endsWith(".rsa") ? "le fichier chiffré" : "le fichier original");
        banner(box, "ok", form.dataset.ok, name + " · " + size(blob.size), a);
      }
    } catch (_) {
      banner(box, "err", "Connexion impossible", "Le serveur ne répond pas.");
    }
    go.disabled = false; go.textContent = label;
  });

  // Page des clés
  const gen = $("#gen");
  if (gen) {
    let pub = "", priv = "";
    const save = (name, text) => {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([text], { type: "application/json" }));
      a.download = name; a.click(); URL.revokeObjectURL(a.href);
    };
    gen.addEventListener("click", async () => {
      const err = $("#error"); err.hidden = true;
      gen.disabled = true; gen.textContent = "Génération en cours…";
      try {
        const res = await fetch("/keys/generate", { method: "POST", body: new URLSearchParams({ bits: $("#bits").value }) });
        const d = await res.json();
        if (!res.ok) throw new Error(d.error);
        $("#pub-n").textContent = d.n; $("#priv-n").textContent = d.n;
        $("#pub-e").textContent = d.e; $("#priv-d").textContent = d.d;
        pub = d.public_json; priv = d.private_json; $("#keys").hidden = false;
      } catch (e2) { err.textContent = e2.message || "Génération impossible."; err.hidden = false; }
      gen.disabled = false; gen.textContent = "Générer les clés";
    });
    $("#dl-pub").addEventListener("click", () => save("cle_publique.json", pub));
    $("#dl-priv").addEventListener("click", () => save("cle_privee.json", priv));
    $("#copy-pub").addEventListener("click", (e) => navigator.clipboard.writeText(pub).then(() => { e.target.textContent = "Copié"; }));
  }
})();
