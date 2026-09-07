"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const state = {
    session: null, status: null, targets: [], profiles: [], certificates: [], presets: [], runs: [],
    activeRunId: null, viewedRunId: null, run: null, pollTimer: null, viewToken: 0,
    logs: [], cursor: 0, seenSeq: -1, logTrimmed: false, serverTruncated: false,
    editTargetId: null, editProfileId: null, duplicateId: null, certificateId: null, confirmAction: null,
  };
  const methods = {
    "eap-tls": ["EAP-TLS", "Certificate-based client authentication."],
    "peap-mschapv2": ["PEAP / MSCHAPv2", "Password authentication in a TLS tunnel."],
    "ttls-pap": ["EAP-TTLS / PAP", "PAP credentials protected by outer TLS."],
    "ttls-mschapv2": ["EAP-TTLS / MSCHAPv2", "MSCHAPv2 inside an EAP-TTLS tunnel."],
  };
  const outcomeNames = {accept: "Accept", reject: "Reject", certificate_error: "Certificate error"};
  const activeStates = new Set(["queued", "running"]);
  const pillClasses = new Set(["accept", "reject", "certificate_error", "timeout", "configuration_error", "cancelled", "interrupted", "error", "pass", "fail", "inconclusive", "queued", "running", "completed"]);
  const path = (collection, id, suffix = "") => `/api/${collection}/${encodeURIComponent(id)}${suffix}`;
  const text = (value, fallback = "—") => value === null || value === undefined || value === "" ? fallback : String(value);
  const pretty = (value) => text(value).replaceAll("_", " ");
  const methodName = (method) => methods[method]?.[0] || text(method);
  const date = (value) => {
    if (!value) return "—";
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? text(value) : parsed.toLocaleString();
  };
  const node = (tag, content, className) => {
    const result = document.createElement(tag);
    if (content !== undefined) result.textContent = text(content, "");
    if (className) result.className = className;
    return result;
  };
  function icon(name) {
    const graphic = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    graphic.classList.add("icon");
    graphic.setAttribute("aria-hidden", "true");
    graphic.setAttribute("focusable", "false");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#icon-${name}`);
    graphic.append(use);
    return graphic;
  }
  function pill(label, kind = "neutral") {
    return node("span", label, `pill ${pillClasses.has(kind) ? kind : "neutral"}`);
  }
  function errorMessage(error) {
    return error instanceof Error ? error.message : "The request could not be completed. Try again.";
  }
  function setError(container, message = "") {
    const output = container.querySelector(".form-error");
    if (!output) return notify(message, true);
    output.textContent = message;
    output.hidden = !message;
  }
  function notify(message, isError = false) {
    const target = $(isError ? "global-error" : "notification");
    target.textContent = message;
    target.hidden = !message;
  }
  function clearSecrets(container) {
    container.querySelectorAll('input[type="password"]').forEach((input) => {
      input.value = "";
      const replacement = input.closest(".attribute-row")?.querySelector('[data-attribute="replace"]');
      if (replacement) { replacement.checked = false; replacement.dispatchEvent(new Event("change")); }
    });
  }
  function errorDetail(body, status) {
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) {
      return body.detail.map((item) => {
        const location = Array.isArray(item.loc) ? item.loc.filter((part) => part !== "body").join(" → ") : "Input";
        return `${location}: ${text(item.msg, "Invalid value")}`;
      }).join(". ");
    }
    return `Request failed (${status}). Try again or check the service.`;
  }
  async function api(url, {method = "GET", body, form, download = false} = {}) {
    const requestSession = state.session;
    const headers = {Accept: download ? "*/*" : "application/json"};
    if (method !== "GET") {
      headers["X-EapolKit-Request"] = "1";
      if (state.session?.csrf_token) headers["X-CSRF-Token"] = state.session.csrf_token;
    }
    if (body !== undefined) headers["Content-Type"] = "application/json";
    let response;
    try {
      response = await fetch(url, {method, headers, body: form || (body === undefined ? undefined : JSON.stringify(body)), credentials: "same-origin", cache: "no-store"});
    } catch {
      throw new Error("Cannot reach the workbench. Check the connection and try again.");
    }
    if (!response.ok) {
      let data = {};
      try { data = await response.json(); } catch { /* The response may be an upstream error page. */ }
      if (response.status === 401 && state.session === requestSession && url !== "/api/login" && url !== "/api/setup") {
        showAuth({setup_required: false, authenticated: false, csrf_token: null});
      }
      throw new Error(errorDetail(data, response.status));
    }
    if (download) return response.blob();
    if (response.status === 204) return null;
    const contentType = response.headers.get("content-type") || "";
    return contentType.includes("application/json") ? response.json() : null;
  }
  async function task(button, action, container = null) {
    if (button?.dataset.busy === "true") return;
    const oldContent = button ? [...button.childNodes] : [];
    const wasDisabled = button?.disabled;
    if (button) { button.dataset.busy = "true"; button.disabled = true; button.textContent = "Working…"; }
    try { await action(); }
    catch (error) { container ? setError(container, errorMessage(error)) : notify(errorMessage(error), true); }
    finally {
      if (button) { delete button.dataset.busy; button.disabled = wasDisabled; button.replaceChildren(...oldContent); }
    }
  }
  function bindButton(id, action) {
    $(id).addEventListener("click", (event) => task(event.currentTarget, action));
  }
  function button(label, action, kind = "quiet") {
    const result = node("button", label, `button ${kind} small`);
    result.type = "button";
    result.addEventListener("click", () => task(result, action));
    return result;
  }
  function bindForm(id, action) {
    const form = $(id);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (form.dataset.busy) return;
      form.dataset.busy = "true";
      form.setAttribute("aria-busy", "true");
      setError(form);
      const buttons = [...form.querySelectorAll('button[type="submit"]')];
      buttons.forEach((item) => { item.disabled = true; });
      const submitter = event.submitter;
      const content = submitter ? [...submitter.childNodes] : [];
      if (submitter) submitter.textContent = "Working…";
      try { await action(event); }
      catch (error) { setError(form, errorMessage(error)); }
      finally {
        clearSecrets(form);
        delete form.dataset.busy;
        form.removeAttribute("aria-busy");
        buttons.forEach((item) => { item.disabled = false; });
        if (submitter) submitter.replaceChildren(...content);
        if (id === "run-form") updateRunControls();
      }
    });
  }
  function openDialog(id) {
    const dialog = $(id);
    setError(dialog);
    if (!dialog.open) dialog.showModal();
    dialog.scrollTop = 0;
  }
  document.querySelectorAll("[data-close]").forEach((item) => {
    item.addEventListener("click", () => item.closest("dialog").close());
  });
  document.querySelectorAll("dialog").forEach((dialog) => {
    dialog.addEventListener("close", () => {
      clearSecrets(dialog);
      dialog.querySelectorAll('input[type="file"]').forEach((input) => { input.value = ""; });
    });
  });
  function showPage(name, focus = true) {
    document.querySelectorAll(".page").forEach((page) => { page.hidden = page.id !== `page-${name}`; });
    document.querySelectorAll("[data-page]").forEach((item) => {
      if (item.dataset.page === name) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    });
    $("notification").hidden = true;
    if (focus) $("main").focus({preventScroll: true});
  }
  document.querySelectorAll("[data-page], [data-go]").forEach((item) => {
    item.addEventListener("click", () => showPage(item.dataset.page || item.dataset.go));
  });
  function showAuth(session) {
    clearTimeout(state.pollTimer);
    state.session = session;
    state.status = null;
    state.activeRunId = null;
    state.viewedRunId = null;
    state.run = null;
    state.logs = [];
    state.viewToken++;
    state.targets = []; state.profiles = []; state.certificates = []; state.runs = []; state.presets = [];
    document.querySelectorAll("dialog[open]").forEach((dialog) => dialog.close());
    document.querySelectorAll('input[type="password"]').forEach((input) => { input.value = ""; });
    $("app-view").hidden = true;
    $("boot").hidden = true;
    $("auth-view").hidden = false;
    const setup = session.setup_required;
    $("auth-title").textContent = setup ? "Set password" : "Log in";
    $("auth-description").textContent = setup ? "Create the workbench password." : "Enter the workbench password.";
    $("auth-submit").textContent = setup ? "Save password" : "Log in";
    $("auth-confirm-field").hidden = !setup;
    $("auth-confirm").required = setup;
    $("auth-password").autocomplete = setup ? "new-password" : "current-password";
    setError($("auth-form"));
    $("auth-password").focus();
  }
  async function enterWorkspace(session) {
    state.session = session;
    $("boot").hidden = true;
    $("auth-view").hidden = true;
    $("app-view").hidden = false;
    $("global-error").hidden = true;
    $("notification").hidden = true;
    resetRunView();
    showPage("workbench", false);
    await loadWorkspace();
  }
  bindForm("auth-form", async () => {
    const password = $("auth-password").value;
    if (state.session.setup_required && password !== $("auth-confirm").value) throw new Error("The passwords do not match.");
    const endpoint = state.session.setup_required ? "/api/setup" : "/api/login";
    clearSecrets($("auth-form"));
    const session = await api(endpoint, {method: "POST", body: {password}});
    if (!session?.authenticated) throw new Error("The server did not establish an authenticated session. Try again.");
    await enterWorkspace(session);
  });
  bindButton("logout", async () => {
    await api("/api/logout", {method: "POST"});
    showAuth({setup_required: false, authenticated: false, csrf_token: null});
  });
  function options(select, items, emptyLabel, selected = select.value) {
    select.replaceChildren(new Option(emptyLabel, ""));
    items.forEach((item) => select.add(new Option(item.label, item.id)));
    select.value = items.some((item) => item.id === selected) ? selected : "";
  }
  function empty(container, title, description) {
    const wrapper = node("div", undefined, "empty-state panel");
    wrapper.append(node("h3", title), node("p", description));
    container.append(wrapper);
  }
  function addFacts(container, pairs) {
    container.replaceChildren();
    pairs.forEach(([label, value]) => {
      const item = node("div");
      item.append(node("dt", label), node("dd", text(value)));
      container.append(item);
    });
  }
  function warnings(container, values) {
    container.replaceChildren();
    if (Array.isArray(values)) values.forEach((value) => container.append(node("p", value, "notice warning")));
  }
  async function loadWorkspace() {
    $("loading").hidden = false;
    try {
      const session = state.session;
      const [status, targets, profiles, certificates, presets, runs] = await Promise.all([
        api("/api/status"), api("/api/targets"), api("/api/profiles"), api("/api/certificates"), api("/api/presets"), api("/api/runs?limit=50"),
      ]);
      if (!state.session?.authenticated || state.session !== session) return;
      Object.assign(state, {status, targets, profiles, certificates, presets, runs, activeRunId: status.active_run_id});
      renderWorkspace();
      if (state.activeRunId && (!state.viewedRunId || activeStates.has(state.run?.status))) await viewRun(state.activeRunId);
      else if (state.viewedRunId) await fetchRun(state.viewedRunId);
      schedulePoll();
      $("global-error").hidden = true;
    } catch (error) {
      notify(`${errorMessage(error)} Use Refresh to reload the workspace.`, true);
    } finally { $("loading").hidden = true; }
  }
  bindButton("refresh-all", async () => {
    const session = await api("/api/session");
    if (!session.authenticated) return showAuth(session);
    state.session = session;
    await loadWorkspace();
  });
  function renderWorkspace() {
    $("version").textContent = state.status?.version ? `v${state.status.version}` : "";
    $("service-status").textContent = state.activeRunId ? "Run in progress" : state.status?.eapol_test_available ? "Runner ready" : "Runner unavailable";
    $("runner-warning").hidden = state.status?.eapol_test_available !== false;
    $("onboarding").hidden = state.targets.length > 0 && state.profiles.length > 0 && state.certificates.length > 0;
    $("profile-count").textContent = state.profiles.length;
    $("target-count").textContent = state.targets.length;
    $("certificate-count").textContent = state.certificates.length;
    options($("run-target"), state.targets.map((item) => ({id: item.id, label: item.name})), "Select a target");
    options($("run-profile"), state.profiles.map((item) => ({id: item.id, label: `${item.name} · ${methodName(item.method)}`})), "Select a profile");
    if (state.targets.length === 1) $("run-target").value = state.targets[0].id;
    if (state.profiles.length === 1) $("run-profile").value = state.profiles[0].id;
    renderTargets(); renderProfiles(); renderCertificates(); renderHistory(); updateRunControls();
  }
  function updateRunControls() {
    const target = state.targets.find((item) => item.id === $("run-target").value);
    const profile = state.profiles.find((item) => item.id === $("run-profile").value);
    $("run-target-description").textContent = target ? `${target.host}:${target.port}` : "";
    $("run-profile-description").textContent = profile ? `${methodName(profile.method)}${profile.identity ? ` · ${profile.identity}` : ""}` : "";
    $("start-run").disabled = !target || !profile || Boolean(state.activeRunId) || !state.status?.eapol_test_available || Boolean($("run-form").dataset.busy);
    if (!$("run-form").dataset.busy) $("start-run").replaceChildren(icon("play"), document.createTextNode(state.activeRunId ? "A run is already active" : "Start"));
    $("workbench-preview").disabled = !profile;
    $("show-active").hidden = !state.activeRunId || state.activeRunId === state.viewedRunId;
    $("service-status").textContent = state.activeRunId ? "Run in progress" : state.status?.eapol_test_available ? "Runner ready" : "Runner unavailable";
  }
  $("run-target").addEventListener("change", updateRunControls);
  $("run-profile").addEventListener("change", updateRunControls);
  function renderTargets() {
    const list = $("target-list"); list.replaceChildren();
    if (!state.targets.length) empty(list, "No targets yet", "Add a RADIUS server and its shared secret to prepare your first test.");
    state.targets.forEach((target) => {
      const card = node("article", undefined, "item-card");
      card.append(node("h3", target.name), node("p", `${target.host}:${target.port}`, "card-description"));
      const meta = node("div", undefined, "card-meta");
      meta.append(pill(`${target.timeout_seconds} s timeout`), pill(target.has_secret ? "Secret saved" : "Secret missing"));
      card.append(meta, node("p", text(target.nas_identifier), "card-description"));
      const actions = node("div", undefined, "card-actions");
      actions.append(button("Edit", () => editTarget(target)), button("Delete", () => confirmDelete("target", target, async () => {
        await api(path("targets", target.id), {method: "DELETE"}); await loadWorkspace();
      }), "danger"));
      card.append(actions); list.append(card);
    });
  }
  function editTarget(target = null) {
    const form = $("target-form"); form.reset();
    state.editTargetId = target?.id || null;
    $("target-dialog-title").textContent = target ? "Edit target" : "Add target";
    if (target) ["name", "host", "port", "timeout_seconds", "nas_identifier", "nas_ip_address"].forEach((key) => { form.elements.namedItem(key).value = target[key] ?? ""; });
    $("target-secret").required = !target?.has_secret;
    $("target-secret-hint").textContent = target?.has_secret ? "Leave blank to keep the saved secret." : "Required.";
    form.querySelector("details").open = false;
    openDialog("target-dialog");
  }
  const privateAttributeIds = new Set([2, 3, 24, 60, 69, 79, 80, 103, 105, 106, 107, 112, 113, 116, 117, 118]);
  const opaqueAttribute = (id) => id === 26 || (id >= 241 && id <= 246);
  function addAttribute(value = {}) {
    const saved = Boolean(value.key);
    const originalPrivate = value.sensitivity === "private" || privateAttributeIds.has(value.id);
    const row = node("fieldset", undefined, "attribute-row");
    row.append(node("legend", "RADIUS attribute"));
    if (saved) row.dataset.key = value.key;
    const controls = node("div", undefined, "attribute-controls");
    const id = node("input"); id.type = "number"; id.min = "1"; id.max = "255"; id.required = true; id.value = value.id ?? ""; id.dataset.attribute = "id";
    const type = node("select"); type.dataset.attribute = "type";
    ["string", "integer", "hex", "ipaddr"].forEach((item) => type.add(new Option(item, item)));
    type.value = value.type || "string";
    const sensitivity = node("select"); sensitivity.dataset.attribute = "sensitivity";
    sensitivity.add(new Option("Public", "public")); sensitivity.add(new Option("Private", "private"));
    sensitivity.value = value.sensitivity || (opaqueAttribute(Number(id.value)) || privateAttributeIds.has(Number(id.value)) ? "private" : "public");
    [["ID", id], ["Encoding", type], ["Visibility", sensitivity]].forEach(([label, control]) => { const wrapper = node("label", label); wrapper.append(control); controls.append(wrapper); });
    const remove = button("Remove", () => { clearSecrets(row); row.remove(); }); remove.replaceChildren(icon("close")); remove.className = "icon-button"; remove.setAttribute("aria-label", "Remove attribute"); controls.append(remove); row.append(controls);
    if (saved) {
      const current = node("div", undefined, "attribute-saved");
      if (!value.has_value) current.append(node("span", "No saved value."));
      else if (originalPrivate) current.append(node("span", "Saved private value — hidden. It is never loaded into this editor."));
      else {
        current.append(node("span", value.value === "" ? "Saved public value (empty):" : "Saved public value:"));
        current.append(node("code", value.value === "" ? "(empty value)" : value.value));
      }
      row.append(current);
    }
    const replace = node("input"); replace.type = "checkbox"; replace.dataset.attribute = "replace";
    const replaceLabel = node("label", undefined, "check attribute-replace"); replaceLabel.append(replace, node("span", saved ? "Replace the saved value" : "Supply a value (an empty value is allowed when its encoding supports it)")); row.append(replaceLabel);
    const input = node("input"); input.maxLength = 506; input.dataset.attribute = "value"; input.autocomplete = "new-password"; input.spellcheck = false; input.autocapitalize = "none";
    if (!saved && !originalPrivate) input.value = value.value ?? "";
    const inputLabel = node("label", saved ? "Replacement value" : "Value", "attribute-value"); inputLabel.append(input); row.append(inputLabel);
    const hint = node("p", undefined, "hint attribute-hint"); row.append(hint);
    const confirm = node("input"); confirm.type = "checkbox"; confirm.dataset.attribute = "confirm-public";
    const confirmLabel = node("label", undefined, "check attribute-confirm"); confirmLabel.append(confirm, node("span", "I confirm that this newly supplied value may appear in readable snapshots and exports.")); row.append(confirmLabel);
    const update = () => {
      const number = Number(id.value);
      const forcedPrivate = privateAttributeIds.has(number);
      if (forcedPrivate) sensitivity.value = "private";
      sensitivity.disabled = forcedPrivate;
      const privateValue = originalPrivate || sensitivity.value === "private";
      const guarded = saved || privateValue;
      const changedEncoding = saved && (number !== value.id || type.value !== value.type);
      const promotion = originalPrivate && sensitivity.value === "public";
      replaceLabel.hidden = !guarded; replace.disabled = !guarded;
      replace.required = guarded && (!saved || changedEncoding || promotion);
      input.disabled = guarded && !replace.checked;
      input.type = privateValue ? "password" : "text";
      input.placeholder = input.disabled ? (saved ? "No replacement supplied" : "No value supplied yet") : "Leave empty only intentionally";
      const disclosure = sensitivity.value === "public" && (promotion || (opaqueAttribute(number) && !input.disabled));
      confirmLabel.hidden = !disclosure; confirm.disabled = !disclosure; confirm.required = disclosure;
      if (!disclosure) confirm.checked = false;
      hint.textContent = forcedPrivate ? "This credential-bearing attribute always stays private. Replacement inputs are cleared after submission." : changedEncoding ? "Changing the ID or encoding requires a replacement value. The saved value is not converted." : input.disabled ? (saved ? "Leave replacement unchecked to keep the current saved state by row key. Check it to supply a replacement, including an intentional empty value." : "Select Supply a value before saving. An empty input is sent only when you explicitly check the box.") : privateValue ? "Private replacements are masked and cleared after submission. An unchecked saved row keeps its hidden value." : opaqueAttribute(number) ? "Vendor-specific and extended containers default to private. Public values need your explicit confirmation." : "Public values are readable in this tool and its exports. The server validates the selected wire encoding.";
    };
    const payloadChanged = () => {
      if (opaqueAttribute(Number(id.value)) && (!saved || Number(id.value) !== value.id || type.value !== value.type)) sensitivity.value = "private";
      confirm.checked = false; update();
    };
    id.addEventListener("input", payloadChanged); type.addEventListener("change", payloadChanged);
    [sensitivity, replace].forEach((control) => control.addEventListener("change", () => { confirm.checked = false; update(); }));
    input.addEventListener("input", () => { confirm.checked = false; });
    update(); $("attribute-list").append(row);
  }
  function attributePayload(row) {
    const get = (name) => row.querySelector(`[data-attribute="${name}"]`);
    const payload = {id: Number(get("id").value), type: get("type").value, sensitivity: get("sensitivity").value};
    if (row.dataset.key) payload.key = row.dataset.key;
    if (!get("value").disabled) payload.value = get("value").value;
    return payload;
  }
  bindButton("new-target", () => editTarget());
  bindButton("add-attribute", () => addAttribute());
  bindForm("target-form", async () => {
    const form = $("target-form"); const value = (name) => form.elements.namedItem(name).value;
    const payload = {name: value("name"), host: value("host"), port: Number(value("port")), timeout_seconds: Number(value("timeout_seconds")), nas_identifier: value("nas_identifier"), nas_ip_address: value("nas_ip_address") || null};
    if (value("secret") !== "") payload.secret = value("secret");
    clearSecrets(form);
    await api(state.editTargetId ? path("targets", state.editTargetId) : "/api/targets", {method: state.editTargetId ? "PUT" : "POST", body: payload});
    $("target-dialog").close(); await loadWorkspace(); notify("Target saved.");
  });
  function renderProfiles() {
    const presets = $("preset-list"); presets.replaceChildren();
    state.presets.forEach((preset, index) => {
      const item = node("button", undefined, "preset-card"); item.type = "button";
      item.append(node("h3", methodName(preset.method)), node("span", "Use", "preset-action"));
      item.querySelector(".preset-action").append(icon("arrow"));
      item.addEventListener("click", () => editProfile(preset, true)); presets.append(item);
    });
    const list = $("profile-list"); list.replaceChildren();
    if (!state.profiles.length) empty(list, "No saved profiles", "Choose one of the four starting points or create a profile. You can save an incomplete recipe before adding trust assets.");
    state.profiles.forEach((profile) => {
      const card = node("article", undefined, "item-card");
      card.append(node("h3", profile.name), node("p", text(profile.identity, "Identity not set"), "card-description"));
      const meta = node("div", undefined, "card-meta"); meta.append(pill(methodName(profile.method))); card.append(meta);
      const missing = [];
      if (!profile.ca_certificate_id) missing.push("server CA");
      if (!profile.server_name) missing.push("server name");
      if (!profile.identity) missing.push("identity");
      if (profile.method === "eap-tls" ? !profile.client_identity_id : !profile.has_password) missing.push(profile.method === "eap-tls" ? "client certificate" : "password");
      card.append(node("p", missing.length ? `Draft: add ${missing.join(", ")}.` : `Server name: ${profile.server_name}. Readiness is validated before execution.`, missing.length ? "card-warning" : "card-description"));
      const actions = node("div", undefined, "card-actions");
      actions.append(button("Edit", () => editProfile(profile)), button("Preview", () => preview(profile.id)), button("Duplicate", () => duplicateProfile(profile)), button("Delete", () => confirmDelete("profile", profile, async () => {
        await api(path("profiles", profile.id), {method: "DELETE"}); await loadWorkspace();
      }), "danger"));
      card.append(actions); list.append(card);
    });
  }
  function editProfile(profile = null, fromPreset = false, copied = false) {
    const form = $("profile-form"); form.reset();
    state.editProfileId = fromPreset ? null : profile?.id || null;
    $("profile-dialog-title").textContent = state.editProfileId ? "Edit profile" : fromPreset ? `New ${methodName(profile.method)} profile` : "New profile";
    const trust = state.certificates.filter((item) => ["trust", "ca"].includes(item.kind));
    options($("profile-ca"), trust.map((item) => ({id: item.id, label: `${item.name}${item.kind === "ca" ? " (kit CA — verify intended trust)" : ""}`})), "Select server trust (can add later)", profile?.ca_certificate_id);
    options($("profile-client"), state.certificates.filter((item) => item.kind === "identity").map((item) => ({id: item.id, label: item.name})), "Select client identity (can add later)", profile?.client_identity_id);
    if (profile) ["name", "method", "identity", "anonymous_identity", "server_name", "tls_min_version", "tls_max_version", "fragment_size", "calling_station_id"].forEach((key) => { if (profile[key] !== undefined && form.elements.namedItem(key)) form.elements.namedItem(key).value = profile[key] ?? ""; });
    $("profile-expired").checked = Boolean(profile?.allow_expired_client_certificate);
    $("attribute-list").replaceChildren();
    (profile?.extra_attributes || []).forEach(addAttribute);
    $("profile-copy-note").hidden = !copied;
    $("profile-copy-note").textContent = "Copy saved. The server preserved its saved password without exposing it. Change only the fields you intend to test, then save.";
    $("profile-password-hint").textContent = profile?.has_password && !fromPreset ? "A password is saved. Leave blank to preserve it; enter a value to replace it. Cleared after every submission." : "Add a password before running this method. You can save a draft without one. Cleared after every submission.";
    form.querySelector("details").open = false;
    profileMethodChanged(); openDialog("profile-dialog");
  }
  function profileMethodChanged() {
    const tls = $("profile-method").value === "eap-tls";
    $("profile-password-field").hidden = tls;
    $("profile-client-field").hidden = !tls;
    if (tls) $("profile-password").value = "";
  }
  $("profile-method").addEventListener("change", profileMethodChanged);
  bindButton("new-profile", () => editProfile(state.presets[0] || null, Boolean(state.presets[0])));
  bindForm("profile-form", async (event) => {
    const form = $("profile-form"); const value = (name) => form.elements.namedItem(name).value;
    const payload = {};
    ["name", "method", "identity", "server_name", "tls_min_version", "tls_max_version", "calling_station_id"].forEach((key) => { payload[key] = value(key); });
    ["anonymous_identity", "ca_certificate_id", "client_identity_id"].forEach((key) => { payload[key] = value(key) || null; });
    payload.fragment_size = Number(value("fragment_size"));
    payload.allow_expired_client_certificate = $("profile-expired").checked;
    payload.extra_attributes = [...$("attribute-list").children].map(attributePayload);
    if (payload.method !== "eap-tls" && value("password") !== "") payload.password = value("password");
    clearSecrets(form);
    const saved = await api(state.editProfileId ? path("profiles", state.editProfileId) : "/api/profiles", {method: state.editProfileId ? "PUT" : "POST", body: payload});
    $("profile-dialog").close(); await loadWorkspace(); notify("Profile saved.");
    if (event.submitter?.value === "preview") await preview(saved.id);
  });
  function duplicateProfile(profile) {
    state.duplicateId = profile.id;
    $("duplicate-form").reset();
    $("duplicate-name").value = profile.name.slice(0, 113) + " (copy)";
    openDialog("duplicate-dialog");
  }
  bindForm("duplicate-form", async () => {
    const saved = await api(path("profiles", state.duplicateId, "/duplicate"), {method: "POST", body: {name: $("duplicate-name").value}});
    $("duplicate-dialog").close(); await loadWorkspace(); editProfile(saved, false, true);
  });
  async function preview(id) {
    $("preview-text").textContent = "Loading generated preview…";
    $("preview-warnings").replaceChildren(); $("copy-preview").disabled = true;
    openDialog("preview-dialog");
    try {
      const data = await api(path("profiles", id, "/preview"));
      $("preview-text").textContent = data.configuration;
      warnings($("preview-warnings"), data.warnings);
      $("copy-preview").disabled = false;
    } catch (error) { $("preview-text").textContent = "Preview unavailable."; setError($("preview-dialog"), errorMessage(error)); }
  }
  bindButton("workbench-preview", () => preview($("run-profile").value));
  bindButton("copy-preview", async () => {
    try { await navigator.clipboard.writeText($("preview-text").textContent); setError($("preview-dialog")); }
    catch { setError($("preview-dialog"), "Clipboard access is unavailable. Select the preview text and copy it with your keyboard."); }
  });
  const kindNames = {trust: "Server trust", identity: "Client identity", ca: "Kit CA / client issuer", csr: "Client signing request"};
  function renderCertificates() {
    const list = $("certificate-list"); list.replaceChildren();
    if (!state.certificates.length) empty(list, "No certificate assets", "Import server trust, bring a client certificate, or generate a CA, client identity, or signing request.");
    state.certificates.forEach((certificate) => {
      const card = node("article", undefined, "item-card");
      card.append(node("h3", certificate.name), node("p", text(certificate.subject, "Signing request"), "card-description"));
      const meta = node("div", undefined, "card-meta"); meta.append(pill(kindNames[certificate.kind] || certificate.kind), pill(certificate.has_private_key ? "Protected key saved" : "Public material only")); card.append(meta);
      if (certificate.not_after) card.append(node("p", `Valid until ${date(certificate.not_after)}`, "card-description"));
      if (certificate.warnings?.length) card.append(node("p", certificate.warnings.join(" · "), "card-warning"));
      const actions = node("div", undefined, "card-actions");
      actions.append(button("Inspect", () => inspectCertificate(certificate)));
      const format = certificate.kind === "csr" ? "csr" : "certificate";
      actions.append(button(format === "csr" ? "Download public CSR" : certificate.kind === "ca" ? "Download public CA" : "Download public PEM", () => download(path("certificates", certificate.id, `/download?format=${format}`), `eapolkit-${format}.pem`)));
      if (certificate.kind === "csr") actions.append(button("Complete CSR", () => completeCSR(certificate)));
      if (certificate.kind === "identity" && certificate.has_private_key) actions.append(button("Export protected PFX…", () => exportPFX(certificate)));
      actions.append(button("Delete", () => confirmDelete("certificate", certificate, async () => {
        await api(path("certificates", certificate.id), {method: "DELETE"}); await loadWorkspace();
      }), "danger"));
      card.append(actions); list.append(card);
    });
  }
  function inspectCertificate(certificate) {
    $("certificate-title").textContent = certificate.name;
    const names = {kind: "Purpose", subject: "Subject", issuer: "Issuer", not_before: "Valid from", not_after: "Valid until", fingerprint_sha256: "SHA-256 fingerprint", key_type: "Key type", san_dns: "DNS subject alternative names", san_email: "Email subject alternative names", san_uri: "URI subject alternative names", eku: "Extended key usage", has_private_key: "Protected private key", id: "Asset ID"};
    addFacts($("certificate-facts"), Object.entries(names).filter(([key]) => certificate[key] !== undefined).map(([key, label]) => {
      let value = certificate[key];
      if (key === "kind") value = kindNames[value] || value;
      else if (["not_before", "not_after"].includes(key)) value = date(value);
      else if (key === "has_private_key") value = value ? "Present (not displayed)" : "Not present";
      else if (Array.isArray(value)) value = value.join("\n") || "None";
      return [label, value];
    }));
    warnings($("certificate-warnings"), certificate.warnings); openDialog("certificate-dialog");
  }
  async function download(url, filename, options = {}) {
    const blob = await api(url, {...options, download: true});
    const objectURL = URL.createObjectURL(blob);
    const link = node("a"); link.href = objectURL; link.download = filename; link.hidden = true;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(objectURL), 1000);
  }
  function importChanged() {
    const identity = $("import-kind").value === "identity";
    const pfx = identity && $("import-format").value === "pfx";
    $("import-format-field").hidden = !identity;
    $("import-certificate-field").hidden = pfx;
    $("import-key-field").hidden = !identity || pfx;
    $("import-pfx-field").hidden = !pfx;
    $("import-passphrase-field").hidden = !identity;
    $("import-cert-file").required = !pfx;
    $("import-key-file").required = identity && !pfx;
    $("import-pfx-file").required = pfx;
    clearSecrets($("import-form"));
  }
  ["import-kind", "import-format"].forEach((id) => $(id).addEventListener("change", importChanged));
  bindButton("import-certificate", () => { $("import-form").reset(); importChanged(); openDialog("import-dialog"); });
  bindForm("import-form", async () => {
    const data = new FormData(); const kind = $("import-kind").value;
    data.append("name", $("import-name").value); data.append("kind", kind);
    if (kind === "identity" && $("import-format").value === "pfx") data.append("pfx", $("import-pfx-file").files[0]);
    else {
      data.append("certificate", $("import-cert-file").files[0]);
      if (kind === "identity") data.append("private_key", $("import-key-file").files[0]);
    }
    if (kind === "identity" && $("import-passphrase").value !== "") data.append("passphrase", $("import-passphrase").value);
    clearSecrets($("import-form"));
    await api("/api/certificates/import", {method: "POST", form: data});
    $("import-dialog").close(); await loadWorkspace(); notify("Certificate imported. Inspect its metadata and warnings before using it.");
  });
  function generationChanged() {
    const kind = $("generate-kind").value;
    $("generate-issuer-field").hidden = kind !== "client";
    $("generate-issuer").required = kind === "client";
    $("generate-days-field").hidden = kind === "csr";
    $("generate-days").required = kind !== "csr";
    $("generate-days").value = kind === "ca" ? "3650" : "365";
    $("generate-sans").hidden = kind === "ca";
    $("generate-csr-hint").hidden = kind !== "csr";
  }
  $("generate-kind").addEventListener("change", generationChanged);
  bindButton("generate-certificate", () => {
    $("generate-form").reset();
    options($("generate-issuer"), state.certificates.filter((item) => item.kind === "ca" && item.has_private_key).map((item) => ({id: item.id, label: item.name})), "Select a signing CA");
    generationChanged(); openDialog("generate-dialog");
  });
  bindForm("generate-form", async () => {
    const kind = $("generate-kind").value;
    const payload = {name: $("generate-name").value, common_name: $("generate-cn").value, key_type: $("generate-key-type").value};
    if (kind !== "csr") payload.days = Number($("generate-days").value);
    if (kind === "client") payload.issuer_id = $("generate-issuer").value;
    if (kind !== "ca") ["dns", "email", "uri"].forEach((key) => { payload[`san_${key}`] = $(`generate-${key}`).value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean); });
    await api(`/api/certificates/generate-${kind}`, {method: "POST", body: payload});
    $("generate-dialog").close(); await loadWorkspace(); notify(kind === "csr" ? "CSR generated. Download the public request, then complete it with the signed certificate." : "Certificate material generated. Configure client issuer trust in FreeRADIUS separately.");
  });
  function completeCSR(certificate) {
    state.certificateId = certificate.id; $("complete-form").reset();
    $("complete-description").textContent = `Import the issued certificate for ${certificate.name}.`;
    openDialog("complete-dialog");
  }
  bindForm("complete-form", async () => {
    const data = new FormData(); data.append("certificate", $("complete-certificate").files[0]);
    await api(path("certificates", state.certificateId, "/complete"), {method: "POST", form: data});
    $("complete-dialog").close(); await loadWorkspace(); notify("CSR completed. The matching client identity is ready to select in a profile.");
  });
  function exportPFX(certificate) {
    state.certificateId = certificate.id; $("pfx-form").reset();
    $("pfx-description").textContent = `Export client identity: ${certificate.name}`;
    openDialog("pfx-dialog");
  }
  bindForm("pfx-form", async () => {
    const passphrase = $("pfx-passphrase").value;
    if (!$("pfx-confirm").checked) throw new Error("Confirm that you intend to export the private client identity.");
    if (passphrase.length < 8) throw new Error("Use an export passphrase of at least 8 characters.");
    if (passphrase !== $("pfx-confirm-passphrase").value) throw new Error("The export passphrases do not match.");
    clearSecrets($("pfx-form"));
    await download(path("certificates", state.certificateId, "/export-pfx"), "eapolkit-client-identity.p12", {method: "POST", body: {passphrase}});
    $("pfx-dialog").close(); notify("Protected PFX download requested. Keep the file and its passphrase secure.");
  });
  function confirmDelete(kind, item, action) {
    state.confirmAction = action;
    $("confirm-title").textContent = `Delete ${kind}?`;
    $("confirm-description").textContent = `Delete “${item.name || item.id}”? This cannot be undone.${kind === "certificate" ? " Certificates referenced by saved profiles cannot be deleted." : ""}`;
    openDialog("confirm-dialog");
  }
  bindForm("confirm-form", async () => {
    await state.confirmAction(); $("confirm-dialog").close(); notify("Deleted.");
  });
  function resetRunView() {
    state.viewToken++; state.viewedRunId = null; state.run = null; state.logs = []; state.cursor = 0; state.seenSeq = -1; state.logTrimmed = false; state.serverTruncated = false;
    $("run-empty").hidden = false; $("run-detail").hidden = true;
    $("run-log").textContent = "Output appears after a run starts."; $("log-status").textContent = "No run selected";
  }
  async function viewRun(id) {
    clearTimeout(state.pollTimer);
    resetRunView(); state.viewedRunId = id;
    const token = state.viewToken;
    $("run-empty").hidden = true; $("log-status").textContent = "Loading run…"; $("run-log").textContent = "Loading sanitized output…";
    showPage("workbench");
    try { await fetchRun(id, token); }
    catch (error) { $("log-status").textContent = "Could not load run"; $("run-log").textContent = "Use Refresh to retry."; throw error; }
    finally { updateRunControls(); schedulePoll(); }
  }
  async function fetchRun(id, token = state.viewToken) {
    const viewed = id === state.viewedRunId;
    const session = state.session;
    const run = await api(path("runs", id, `?after=${viewed ? state.cursor : 0}`));
    if (!state.session?.authenticated || session !== state.session) return;
    const wasActive = state.activeRunId === id;
    if (activeStates.has(run.status)) state.activeRunId = id;
    else if (wasActive) state.activeRunId = null;
    if (viewed && state.viewedRunId === id && token === state.viewToken) {
      state.run = run;
      appendLogs(run);
      renderRun(run);
    }
    updateRunControls();
    if (wasActive && !state.activeRunId) await refreshHistory();
  }
  function appendLogs(run) {
    const lines = Array.isArray(run.log_lines) ? run.log_lines : [];
    for (const item of lines) {
      if (!Number.isFinite(item.seq) || item.seq <= state.seenSeq) continue;
      const value = text(item.line, "");
      state.logs.push(value.length > 4000 ? `${value.slice(0, 4000)} [browser line shortened]` : value);
      state.seenSeq = item.seq;
    }
    if (Number.isFinite(run.next_seq)) state.cursor = Math.max(state.cursor, run.next_seq);
    let chars = state.logs.reduce((total, line) => total + line.length + 1, 0);
    while (state.logs.length > 600 || chars > 120000) {
      chars -= state.logs.shift().length + 1; state.logTrimmed = true;
    }
    state.serverTruncated ||= Boolean(run.truncated);
    $("run-log").textContent = state.logs.length ? state.logs.join("\n") : "No sanitized output has been recorded yet.";
    if ($("log-follow").checked) $("run-log").scrollTop = $("run-log").scrollHeight;
    const notes = [`${state.logs.length} displayed lines`, "Latest 600 lines / 120,000 characters maximum"];
    if (state.logTrimmed) notes.push("Older output omitted from the browser view");
    if (state.serverTruncated) notes.push("Stored output was truncated by the server limit");
    $("log-limit").textContent = notes.join(" · ");
  }
  function renderRun(run) {
    $("run-empty").hidden = true; $("run-detail").hidden = false;
    const badges = $("run-badges"); badges.replaceChildren(pill(pretty(run.status), run.status));
    if (run.outcome) badges.append(pill(pretty(run.outcome), run.outcome));
    const summary = run.summary || (activeStates.has(run.status) ? "Authentication is in progress. Waiting for an observed result." : "No diagnostic summary was recorded.");
    if ($("run-summary").textContent !== summary) $("run-summary").textContent = summary;
    const facts = [["Started", date(run.started_at)], ["Finished", date(run.finished_at)], ["Duration", run.duration_seconds == null ? "—" : `${Number(run.duration_seconds).toFixed(2)} s`], ["Exit code", run.exit_code]];
    if (run.radius_response !== undefined && run.radius_response !== null) facts.push(["RADIUS response", run.radius_response]);
    if (run.peer_success !== undefined && run.peer_success !== null) facts.push(["Peer / keying success", run.peer_success ? "Observed" : "Not observed"]);
    if (run.mppe_keys_match !== undefined && run.mppe_keys_match !== null) facts.push(["MPPE keys match", run.mppe_keys_match ? "Yes (key material is never displayed)" : "No"]);
    addFacts($("run-facts"), facts);
    $("run-snapshot").textContent = JSON.stringify(run.snapshot || {}, null, 2);
    $("cancel-run").hidden = !activeStates.has(run.status);
    $("cancel-run").disabled = false;
    $("log-status").textContent = activeStates.has(run.status) ? "Live · refreshes every second" : `${pretty(run.status)} · sanitized record`;
  }
  function schedulePoll() {
    clearTimeout(state.pollTimer);
    if (!state.activeRunId || !state.session?.authenticated) return;
    state.pollTimer = setTimeout(async () => {
      const id = state.activeRunId;
      if (!id) return;
      try { await fetchRun(id); }
      catch (error) {
        $("log-status").textContent = `${errorMessage(error)} Retrying live output; do not start another run.`;
      } finally { schedulePoll(); }
    }, 1000);
  }
  bindForm("run-form", async () => {
    const payload = {target_id: $("run-target").value, profile_id: $("run-profile").value};
    try {
      const run = await api("/api/runs", {method: "POST", body: payload});
      state.activeRunId = activeStates.has(run.status) ? run.id : null;
      await viewRun(run.id); await refreshHistory();
    } catch (error) {
      await loadWorkspace(); throw error;
    }
  });
  bindButton("show-active", () => viewRun(state.activeRunId));
  bindButton("cancel-run", async () => {
    const id = state.viewedRunId;
    await api(path("runs", id, "/cancel"), {method: "POST"});
    await fetchRun(id); schedulePoll();
  });
  bindButton("download-run", () => download(path("runs", state.viewedRunId, "/export"), "eapolkit-run-sanitized.json"));
  async function refreshHistory() {
    const session = state.session;
    const runs = await api("/api/runs?limit=50");
    if (!state.session?.authenticated || session !== state.session) return;
    state.runs = runs; renderHistory();
  }
  bindButton("refresh-history", refreshHistory);
  function renderHistory() {
    const list = $("history-list"); list.replaceChildren();
    if (!state.runs.length) { empty(list, "No recorded runs", "Start a test in the workbench. Only real runs appear in this history."); return; }
    const wrap = node("div", undefined, "table-wrap");
    const table = node("table"); const caption = node("caption", "Recent authentication runs", "skip-link"); table.append(caption);
    const head = node("thead"); const header = node("tr");
    ["Run", "Result", "Actions"].forEach((label) => { const cell = node("th", label); cell.scope = "col"; header.append(cell); }); head.append(header); table.append(head);
    const body = node("tbody");
    state.runs.forEach((run) => {
      const row = node("tr"); const description = node("td");
      description.append(node("strong", run.profile_name || run.profile_id || run.id), node("p", `${run.target_name || run.target_id || "Target"} · ${date(run.started_at || run.created_at)}`, "muted"));
      const observed = node("td"); observed.append(pill(pretty(run.outcome || run.status), run.outcome || run.status));
      const actions = node("td"); const buttons = node("div", undefined, "actions");
      buttons.append(button("View", () => viewRun(run.id)), button("JSON", () => download(path("runs", run.id, "/export"), "eapolkit-run-sanitized.json")));
      if (!activeStates.has(run.status)) buttons.append(button("Delete", () => confirmDelete("run", run, async () => {
        await api(path("runs", run.id), {method: "DELETE"});
        if (state.viewedRunId === run.id) resetRunView();
        await refreshHistory();
      }), "danger"));
      actions.append(buttons); row.append(description, observed, actions); body.append(row);
    });
    table.append(body); wrap.append(table); list.append(wrap);
  }
  window.addEventListener("pagehide", () => { clearTimeout(state.pollTimer); clearSecrets(document); });
  window.addEventListener("pageshow", (event) => { if (event.persisted) initialize(); });
  async function initialize() {
    try {
      const session = await api("/api/session");
      if (session.authenticated) await enterWorkspace(session);
      else showAuth(session);
    } catch (error) {
      $("boot").replaceChildren(node("p", errorMessage(error)), button("Retry connection", initialize, "secondary"));
      $("boot").hidden = false;
    }
  }
  initialize();
})();
