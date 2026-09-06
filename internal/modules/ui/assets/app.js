(function () {
  "use strict";

  var session = null;
  var identity = null;
  var revealed = null;
  var sealVersion = 0;

  function el(id) {
    return document.getElementById(id);
  }

  function toast(message, bad) {
    var box = el("toast");
    box.textContent = message;
    box.classList.toggle("bad", Boolean(bad));
    box.hidden = false;
    window.clearTimeout(toast.timer);
    toast.timer = window.setTimeout(function () {
      box.hidden = true;
    }, 6000);
  }

  function problem(status, body) {
    if (body && body.error && body.error.code) {
      return body.error.code + " (" + status + ")";
    }
    return "request failed (" + status + ")";
  }

  function call(method, path, body) {
    var options = {
      method: method,
      headers: { "Accept": "application/json" },
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer"
    };
    if (session) {
      options.headers["Authorization"] = "Bearer " + session;
    }
    if (body !== undefined) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }

    return window.fetch(path, options).then(function (response) {
      if (response.status === 204) {
        return { status: 204, body: null };
      }
      return response.json().then(function (parsed) {
        return { status: response.status, body: parsed };
      }, function () {
        return { status: response.status, body: null };
      });
    }).then(function (result) {
      if (result.status >= 400) {
        throw new Error(problem(result.status, result.body));
      }
      return result.body;
    });
  }

  function fail(error) {
    toast(error.message, true);
  }

  function text(id, value) {
    el(id).textContent = value === null || value === undefined ? "—" : String(value);
  }

  function show(id, visible) {
    el(id).hidden = !visible;
  }

  function encodePath(tenant, path) {
    var parts = String(path).split("/").filter(function (part) {
      return part.length > 0;
    }).map(encodeURIComponent);
    return "/v1/secret/data/" + encodeURIComponent(tenant) + "/" + parts.join("/");
  }

  function encodeParam(tenant, path) {
    var parts = String(path).split("/").filter(function (part) {
      return part.length > 0;
    }).map(encodeURIComponent);
    return "/v1/param/data/" + encodeURIComponent(tenant) + "/" + parts.join("/");
  }

  function pillFor(state) {
    if (state === "unsealed") {
      return "ms-pill-ok";
    }
    if (state === "sealed") {
      return "ms-pill-warn";
    }
    return "ms-pill-danger";
  }

  function refreshSeal() {
    return call("GET", "/v1/sys/seal-status").then(function (status) {
      sealVersion = status.kek_version;
      text("fact-state", status.state);
      text("fact-shares", status.shares);
      text("fact-threshold", status.threshold);
      text("fact-progress", status.progress);
      text("fact-kek", status.kek_version);

      var banner = el("seal-banner");
      banner.textContent = status.state;
      banner.className = "ms-pill " + pillFor(status.state);

      show("init-panel", status.state === "uninitialized");
      show("unseal-panel", status.state === "sealed");
      show("rotate-panel", status.state === "unsealed" && Boolean(session));
      return status;
    });
  }

  function setSession(token, expires) {
    session = token;
    forgetValue();
    call("GET", "/v1/auth/self").then(function (self) {
      identity = self;
      el("session-who").textContent = self.identity + " @ " + self.tenant;
      show("sign-out", true);
      show("login-panel", false);
      if (expires) {
        toast("signed in until " + expires);
      }
      refreshSeal();
    }).catch(fail);
  }

  function signOut() {
    var ending = session ? call("POST", "/v1/auth/logout") : Promise.resolve();
    ending.catch(function () {
      return null;
    }).then(function () {
      session = null;
      identity = null;
      forgetValue();
      el("session-who").textContent = "not signed in";
      show("sign-out", false);
      show("login-panel", true);
      refreshSeal();
      toast("signed out");
    });
  }

  function forgetValue() {
    revealed = null;
    el("secret-value").textContent = "";
    el("secret-value").classList.add("masked");
    el("secret-reveal").textContent = "Reveal";
    show("secret-value-panel", false);
  }

  function holdValue(value) {
    revealed = value;
    var output = el("secret-value");
    output.textContent = "•".repeat(Math.min(value.length, 32));
    output.classList.add("masked");
    el("secret-reveal").textContent = "Reveal";
    show("secret-value-panel", true);
  }

  function toggleReveal() {
    if (revealed === null) {
      return;
    }
    var output = el("secret-value");
    var hidden = output.classList.contains("masked");
    output.textContent = hidden ? revealed : "•".repeat(Math.min(revealed.length, 32));
    output.classList.toggle("masked", !hidden);
    el("secret-reveal").textContent = hidden ? "Hide" : "Reveal";
  }

  function copyValue() {
    if (revealed === null) {
      return;
    }
    if (!navigator.clipboard) {
      toast("this browser offers no clipboard access", true);
      return;
    }
    navigator.clipboard.writeText(revealed).then(function () {
      toast("copied; the value is now on your system clipboard");
    }, function () {
      toast("the browser refused clipboard access", true);
    });
  }

  function selectView(name) {
    var buttons = document.querySelectorAll("#tabs button");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].classList.toggle("active", buttons[i].dataset.view === name);
    }
    var views = document.querySelectorAll(".view");
    for (var j = 0; j < views.length; j++) {
      views[j].hidden = views[j].id !== "view-" + name;
    }
  }

  function readSecret() {
    var version = el("secret-version").value;
    var path = encodePath(el("secret-tenant").value, el("secret-path").value);
    if (version) {
      path = path + "?version=" + encodeURIComponent(version);
    }
    call("GET", path).then(function (found) {
      holdValue(found.value);
      toast("version " + found.version + ", lease " + (found.lease_id || "none"));
    }).catch(fail);
  }

  function writeSecret() {
    var body = { value: el("secret-new").value };
    var cas = el("secret-cas").value;
    if (cas !== "") {
      body.cas = Number(cas);
    }
    call("PUT", encodePath(el("secret-tenant").value, el("secret-path").value), body)
      .then(function (written) {
        el("secret-new").value = "";
        toast("wrote version " + written.version);
      }).catch(fail);
  }

  function deleteSecret() {
    call("DELETE", encodePath(el("secret-tenant").value, el("secret-path").value))
      .then(function () {
        forgetValue();
        toast("the current version is deleted; it can be undeleted");
      }).catch(fail);
  }

  function secretMetadata() {
    var tenant = encodeURIComponent(el("secret-tenant").value);
    var parts = el("secret-path").value.split("/").filter(function (part) {
      return part.length > 0;
    }).map(encodeURIComponent);
    call("GET", "/v1/secret/metadata/" + tenant + "/" + parts.join("/")).then(function (meta) {
      toast("current " + meta.current_version + ", keeping " + meta.max_versions +
        ", updated " + meta.updated_at);
    }).catch(fail);
  }

  function listParams() {
    var tenant = encodeURIComponent(el("param-tenant").value);
    var prefix = encodeURIComponent(el("param-prefix").value);
    call("GET", "/v1/param/list/" + tenant + "?prefix=" + prefix).then(function (listed) {
      var rows = el("param-rows");
      rows.textContent = "";
      var entries = listed.parameters || [];
      entries.forEach(function (entry) {
        var tr = document.createElement("tr");
        [entry.path, entry.kind, entry.updated_at, entry.updated_by].forEach(function (cell) {
          var td = document.createElement("td");
          td.textContent = cell;
          tr.appendChild(td);
        });
        rows.appendChild(tr);
      });
      show("param-table", true);
      toast(entries.length + " parameter(s); values are not decrypted by a list");
    }).catch(fail);
  }

  function readParam() {
    call("GET", encodeParam(el("param-tenant").value, el("param-path").value))
      .then(function (found) {
        el("param-value").textContent = found.value;
        el("param-origin").textContent = found.inherited
          ? "inherited from " + found.resolved_from
          : "set here";
        show("param-value-panel", true);
      }).catch(fail);
  }

  function writeParam() {
    call("PUT", encodeParam(el("param-tenant").value, el("param-path").value), {
      kind: el("param-kind").value,
      value: el("param-new").value
    }).then(function () {
      toast("written");
    }).catch(fail);
  }

  function deleteParam() {
    call("DELETE", encodeParam(el("param-tenant").value, el("param-path").value))
      .then(function () {
        show("param-value-panel", false);
        toast("removed");
      }).catch(fail);
  }

  function listLeases() {
    call("GET", "/v1/sys/leases").then(function (listed) {
      var rows = el("lease-rows");
      rows.textContent = "";
      var leases = listed.leases || [];
      leases.forEach(function (held) {
        var tr = document.createElement("tr");
        [held.lease_id, held.path, held.version, held.expires_at].forEach(function (cell) {
          var td = document.createElement("td");
          td.textContent = cell;
          tr.appendChild(td);
        });

        var actions = document.createElement("td");
        var revoke = document.createElement("button");
        revoke.type = "button";
        revoke.className = "danger";
        revoke.textContent = "revoke";
        revoke.addEventListener("click", function () {
          call("PUT", "/v1/sys/leases/revoke", { lease_id: held.lease_id }).then(function () {
            toast("revoked");
            listLeases();
          }).catch(fail);
        });
        actions.appendChild(revoke);
        tr.appendChild(actions);
        rows.appendChild(tr);
      });
      show("lease-table", true);
      toast(leases.length + " active lease(s)");
    }).catch(fail);
  }

  function initialise() {
    call("POST", "/v1/sys/init", {
      shares: Number(el("init-shares").value),
      threshold: Number(el("init-threshold").value)
    }).then(function (created) {
      var out = el("init-shares-out");
      out.textContent = created.shares.join("\n");
      out.hidden = false;
      toast("copy these now; they are never shown again", true);
      refreshSeal();
    }).catch(fail);
  }

  function unseal() {
    var field = el("unseal-share");
    call("POST", "/v1/sys/unseal", { share: field.value }).then(function (status) {
      field.value = "";
      toast(status.state + "; " + status.progress + " of " + status.threshold + " share(s)");
      refreshSeal();
    }).catch(function (error) {
      field.value = "";
      fail(error);
    });
  }

  function rotate() {
    call("POST", "/v1/sys/rotate", { current_version: sealVersion }).then(function (result) {
      var out = el("rotate-out");
      out.textContent = JSON.stringify(result, null, 2);
      out.hidden = false;
      toast("rotated " + result.from + " to " + result.to);
      refreshSeal();
    }).catch(fail);
  }

  function login() {
    var field = el("login-bootstrap");
    call("POST", "/v1/auth/bootstrap/login", { token: field.value }).then(function (issued) {
      field.value = "";
      setSession(issued.token, issued.expires_at);
    }).catch(function (error) {
      field.value = "";
      fail(error);
    });
  }

  function check() {
    call("POST", "/v1/sys/policies/check", {
      tenant: el("check-tenant").value,
      path: el("check-path").value,
      capability: el("check-capability").value
    }).then(function (decision) {
      var out = el("check-out");
      out.textContent = JSON.stringify(decision, null, 2);
      out.hidden = false;
    }).catch(fail);
  }

  function self() {
    call("GET", "/v1/auth/self").then(function (found) {
      var out = el("self-out");
      out.textContent = JSON.stringify(found, null, 2);
      out.hidden = false;
    }).catch(fail);
  }

  function wire() {
    var actions = {
      "do-init": initialise,
      "do-unseal": unseal,
      "do-rotate": rotate,
      "do-login": login,
      "sign-out": signOut,
      "secret-read": readSecret,
      "secret-write": writeSecret,
      "secret-delete": deleteSecret,
      "secret-meta": secretMetadata,
      "secret-reveal": toggleReveal,
      "secret-copy": copyValue,
      "secret-forget": forgetValue,
      "param-list": listParams,
      "param-read": readParam,
      "param-write": writeParam,
      "param-delete": deleteParam,
      "lease-list": listLeases,
      "do-check": check,
      "do-self": self
    };
    Object.keys(actions).forEach(function (id) {
      el(id).addEventListener("click", actions[id]);
    });

    var tabs = document.querySelectorAll("#tabs button");
    for (var i = 0; i < tabs.length; i++) {
      tabs[i].addEventListener("click", function (event) {
        selectView(event.currentTarget.dataset.view);
      });
    }

    window.addEventListener("pagehide", function () {
      session = null;
      revealed = null;
    });
  }

  wire();
  refreshSeal().catch(fail);
})();
