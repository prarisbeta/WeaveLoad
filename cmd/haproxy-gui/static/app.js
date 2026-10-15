// app.js — small, dependency-free helpers loaded alongside htmx.
//
// 1. Surfaces failed htmx requests. By default htmx does nothing visible
//    when a request comes back non-2xx (CSRF rejected, permission denied,
//    server error, network drop) — a button just looks like it "doesn't
//    work". Every failure here gets an explicit red banner instead.
// 2. When a page is opened at a "#member-<name>" anchor (used by the
//    dashboard's "Ubah" link to point at a specific pool member row),
//    briefly highlights that row so it's obvious which one to edit.
// 3. On the logs page, an auto-refresh dropdown (5s/10s/20s/off) that just
//    reloads the page on a timer, keeping the current filters (they're in
//    the URL query string). The choice is remembered in localStorage so it
//    survives the reload and later visits to the page.
(function () {
  "use strict";

  function showError(target, msg) {
    var el = target && typeof target.insertBefore === "function" ? target : document.body;
    var div = document.createElement("div");
    div.className = "panel notice-bad";
    div.style.marginBottom = "12px";
    var strong = document.createElement("strong");
    strong.textContent = msg;
    div.appendChild(strong);
    el.insertBefore(div, el.firstChild);
    setTimeout(function () {
      if (div.parentNode) {
        div.parentNode.removeChild(div);
      }
    }, 10000);
  }

  document.body.addEventListener("htmx:responseError", function (evt) {
    var xhr = evt.detail && evt.detail.xhr;
    var target = evt.detail && evt.detail.target;
    var status = xhr ? xhr.status : "?";
    var body = xhr && xhr.responseText ? xhr.responseText.trim() : "";
    var msg = "Aksi gagal (kode " + status + ")" + (body ? ": " + body : ".");
    showError(target, msg);
  });

  document.body.addEventListener("htmx:sendError", function (evt) {
    var elt = evt.detail && evt.detail.elt;
    var isRestart = elt && (elt.getAttribute("data-restart-action") === "true" || (elt.getAttribute("hx-post") && elt.getAttribute("hx-post").indexOf("restart") !== -1));
    if (isRestart) {
      // Reconnection polling is active; don't show raw network failure
      return;
    }
    showError(evt.detail && evt.detail.target, "Tidak bisa terhubung ke server. Periksa koneksi jaringan Anda lalu coba lagi.");
  });

  document.addEventListener("DOMContentLoaded", function () {
    var restartBtn = document.getElementById("btn-restart-haproxy");
    if (restartBtn) {
      restartBtn.addEventListener("htmx:beforeRequest", function () {
        var out = document.getElementById("restart-out");
        if (out) {
          out.innerHTML = '<div class="panel notice-warn" style="margin-top:12px;"><strong>🔄 Merestart layanan HAProxy...</strong><p class="hint" style="margin:4px 0 0 0">Koneksi sedang terputus sesaat. Menghubungkan kembali secara otomatis...</p></div>';
        }
        pollForReconnect();
      });
    }

    if (location.hash.indexOf("#member-") !== 0) {
      return;
    }
    var row = document.getElementById(location.hash.slice(1));
    if (!row) {
      return;
    }
    row.style.outline = "2px solid var(--accent)";
    row.style.outlineOffset = "-2px";
    setTimeout(function () {
      row.style.outline = "";
    }, 3000);
  });

  function pollForReconnect() {
    var attempts = 0;
    var maxAttempts = 30;
    var timer = setInterval(function () {
      attempts++;
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "/api/v1/status?_=" + new Date().getTime(), true);
      xhr.timeout = 2000;
      xhr.onload = function () {
        if (xhr.status >= 200 && xhr.status < 500) {
          clearInterval(timer);
          var out = document.getElementById("restart-out");
          if (out) {
            out.innerHTML = '<div class="panel notice-ok" style="margin-top:12px;"><strong style="color:var(--ok)">✓ Layanan HAProxy berhasil direstart dan aktif kembali.</strong></div>';
          }
          setTimeout(function () {
            window.location.reload();
          }, 1000);
        }
      };
      xhr.onerror = function () {
        // still restarting
      };
      xhr.ontimeout = function () {
        // timeout, wait next attempt
      };
      if (attempts >= maxAttempts) {
        clearInterval(timer);
        var out = document.getElementById("restart-out");
        if (out) {
          out.innerHTML = '<div class="panel notice-bad" style="margin-top:12px;"><strong style="color:var(--bad)">Layanan belum merespons. Silakan muat ulang halaman secara manual.</strong></div>';
        }
      }
      try {
        xhr.send();
      } catch (e) {}
    }, 1500);
  }

  var AUTO_REFRESH_KEY = "haproxy-gui:logs-auto-refresh";

  document.addEventListener("DOMContentLoaded", function () {
    var select = document.getElementById("log-auto-refresh");
    if (!select) {
      return;
    }
    var saved = "0";
    try {
      saved = localStorage.getItem(AUTO_REFRESH_KEY) || "0";
    } catch (e) {
      // localStorage unavailable (private mode, etc.) — fall back to off.
    }
    select.value = saved;
    scheduleAutoRefresh(parseInt(saved, 10));
    select.addEventListener("change", function () {
      try {
        localStorage.setItem(AUTO_REFRESH_KEY, select.value);
      } catch (e) {
        // ignore — the timer still applies for the rest of this page view.
      }
      scheduleAutoRefresh(parseInt(select.value, 10));
    });
  });

  var autoRefreshTimer = null;

  function scheduleAutoRefresh(seconds) {
    if (autoRefreshTimer) {
      clearInterval(autoRefreshTimer);
      autoRefreshTimer = null;
    }
    if (seconds > 0) {
      autoRefreshTimer = setInterval(function () {
        window.location.reload();
      }, seconds * 1000);
    }
  }

  // Global CSP-compliant UI Event Handlers
  document.addEventListener("change", function (evt) {
    var target = evt.target;
    if (!target) return;

    // Language switcher auto-submit
    if (target.matches && target.matches(".language-form select[name='language']")) {
      if (target.form) target.form.submit();
    }

    // Role selector auto-submit in user management
    if (target.matches && target.matches("form.field-inline select[name='role']")) {
      if (target.form && typeof target.form.requestSubmit === "function") {
        target.form.requestSubmit();
      } else if (target.form) {
        target.form.submit();
      }
    }

    // Pool Mode selector toggle
    if (target.id === "mode_select") {
      updateModeUI();
    }

    // Pool Health Check selector toggle
    if (target.id === "health_check_type") {
      updateHealthCheckUI();
    }
  });

  document.addEventListener("click", function (evt) {
    var target = evt.target;
    if (!target) return;

    // Pool member edit cancel
    if (target.matches && (target.matches(".btn-cancel-edit") || target.matches("[data-dismiss='#pool-edit-panel']"))) {
      var panel = document.getElementById("pool-edit-panel");
      if (panel) panel.innerHTML = "";
    }

    // Preset profile card selector
    var card = target.closest ? target.closest(".preset-card[data-profile]") : null;
    if (card) {
      var prof = card.getAttribute("data-profile");
      if (prof) selectProfile(prof);
    }
  });

  document.addEventListener("submit", function (evt) {
    var form = evt.target;
    if (!form) return;
    var confirmMsg = form.getAttribute("data-confirm");
    if (confirmMsg) {
      if (!window.confirm(confirmMsg)) {
        evt.preventDefault();
        evt.stopPropagation();
      }
    }
  });

  function selectProfile(prof) {
    var cards = document.querySelectorAll(".preset-card");
    for (var i = 0; i < cards.length; i++) {
      cards[i].style.borderColor = "var(--border)";
      cards[i].style.background = "rgba(255,255,255,0.01)";
    }
    var active = document.getElementById("card-" + prof);
    if (active) {
      active.style.borderColor = "var(--accent)";
      active.style.background = "rgba(255,255,255,0.05)";
    }
    var inputProf = document.getElementById("input_profile");
    if (inputProf) inputProf.value = prof;

    var mode = document.getElementById("mode_select");
    var balance = document.getElementById("balance_select");
    var port = document.getElementById("member_port");
    var hc = document.getElementById("health_check_type");
    var hcUser = document.getElementById("health_check_user");
    var toClient = document.getElementById("timeout_client");
    var toServer = document.getElementById("timeout_server");

    if (prof === "web") {
      if (mode) mode.value = "http";
      if (balance) balance.value = "roundrobin";
      if (port) {
        port.placeholder = "80";
        if (!port.value || port.value === "3306" || port.value === "5432" || port.value === "6379") port.value = "80";
      }
      if (hc) hc.value = "httpchk";
      if (toClient) toClient.value = "";
      if (toServer) toServer.value = "";
    } else if (prof === "mysql") {
      if (mode) mode.value = "tcp";
      if (balance) balance.value = "leastconn";
      if (port) port.value = "3306";
      if (hc) hc.value = "mysql-check";
      if (hcUser) hcUser.value = "haproxy_check";
      if (toClient) toClient.value = "8h";
      if (toServer) toServer.value = "8h";
    } else if (prof === "postgres") {
      if (mode) mode.value = "tcp";
      if (balance) balance.value = "leastconn";
      if (port) port.value = "5432";
      if (hc) hc.value = "pgsql-check";
      if (hcUser) hcUser.value = "postgres";
      if (toClient) toClient.value = "8h";
      if (toServer) toServer.value = "8h";
    } else if (prof === "redis") {
      if (mode) mode.value = "tcp";
      if (balance) balance.value = "first";
      if (port) port.value = "6379";
      if (hc) hc.value = "redis-check";
      if (toClient) toClient.value = "1h";
      if (toServer) toServer.value = "1h";
    } else if (prof === "tcp") {
      if (mode) mode.value = "tcp";
      if (balance) balance.value = "leastconn";
      if (hc) hc.value = "tcp-check";
    }
    updateModeUI();
    updateHealthCheckUI();
  }

  function updateModeUI() {
    var modeEl = document.getElementById("mode_select");
    var mode = modeEl ? modeEl.value : "http";
    var webFeat = document.getElementById("web-features");
    if (webFeat) {
      webFeat.style.display = (mode === "http") ? "block" : "none";
    }
  }

  function updateHealthCheckUI() {
    var hcEl = document.getElementById("health_check_type");
    var hc = hcEl ? hcEl.value : "httpchk";
    var httpFields = document.getElementById("hc-http-fields");
    var userFields = document.getElementById("hc-user-fields");
    if (httpFields) httpFields.style.display = (hc === "httpchk") ? "contents" : "none";
    if (userFields) userFields.style.display = (hc === "mysql-check" || hc === "pgsql-check") ? "contents" : "none";
  }

  // --- Dynamic Member Rows in Pool Creation Wizard ---
  document.addEventListener("click", function (e) {
    var target = e.target;
    if (!target) return;

    // Add Member Row Button Click
    var addBtn = target.closest ? target.closest(".btn-add-member-row, #btn-add-member-row") : null;
    if (addBtn) {
      var container = document.getElementById("members-container");
      if (container) {
        var rows = container.querySelectorAll(".member-row");
        var nextNum = rows.length + 1;
        var defaultPort = document.getElementById("member_port") ? document.getElementById("member_port").value : "80";

        var newRow = document.createElement("div");
        newRow.className = "member-row panel";
        newRow.style.marginBottom = "0";
        newRow.style.background = "rgba(255,255,255,0.02)";
        newRow.style.border = "1px solid var(--border)";
        newRow.style.padding = "14px";
        newRow.style.borderRadius = "6px";

        newRow.innerHTML =
          '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">' +
            '<strong style="font-size:13px;" class="member-row-title">Node #' + nextNum + '</strong>' +
            '<button type="button" class="btn danger btn-remove-member-row" style="font-size:11px; padding:2px 6px;">✕ Hapus</button>' +
          '</div>' +
          '<div class="member-form">' +
            '<label>Nama Server<input type="text" name="member_name" required maxlength="64" placeholder="node' + nextNum + '" value="node' + nextNum + '"></label>' +
            '<label>Alamat Host (IP / Domain)<input type="text" name="member_host" required placeholder="192.168.200.' + (120 + nextNum - 1) + '"></label>' +
            '<label>Port Layanan<input type="text" name="member_port" required size="5" inputmode="numeric" placeholder="80" value="' + defaultPort + '"></label>' +
            '<details class="advanced-toggle" style="grid-column: 1 / -1;">' +
              '<summary>Pengaturan Lanjutan Server</summary>' +
              '<div class="member-form" style="margin-top:8px;">' +
                '<label>Bobot (Weight) <span class="muted">(0-256)</span><input type="text" name="member_weight" size="4" inputmode="numeric" placeholder="100"></label>' +
                '<label>Batas Maks Koneksi<input type="text" name="member_maxconn" size="6" inputmode="numeric" placeholder="1000"></label>' +
                '<label class="check"><input type="checkbox" name="member_backup" value="1"> Jadikan Server Cadangan (Backup)</label>' +
              '</div>' +
            '</details>' +
          '</div>';

        container.appendChild(newRow);
        updateMemberRowIndices(container);
      }
      return;
    }

    // Remove Member Row Button Click
    var removeBtn = target.closest ? target.closest(".btn-remove-member-row") : null;
    if (removeBtn) {
      var row = removeBtn.closest(".member-row");
      var parent = row ? row.parentElement : null;
      if (row) {
        row.remove();
        if (parent) updateMemberRowIndices(parent);
      }
    }
  });

  function updateMemberRowIndices(container) {
    if (!container) container = document.getElementById("members-container");
    if (!container) return;
    var rows = container.querySelectorAll(".member-row");
    rows.forEach(function (r, idx) {
      var title = r.querySelector(".member-row-title");
      if (title) title.textContent = "Node #" + (idx + 1);
      var delBtn = r.querySelector(".btn-remove-member-row");
      if (delBtn) {
        delBtn.style.display = rows.length > 1 ? "inline-block" : "none";
      }
    });
  }
  function getCSRFToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && meta.getAttribute("content")) {
      return meta.getAttribute("content");
    }
    var input = document.querySelector('input[name="csrf_token"]');
    return input ? input.value : "";
  }

  // --- Custom Error Pages & Live Previewer ---
  document.addEventListener("DOMContentLoaded", function () {
    var loadPresetBtn = document.getElementById("btn-load-preset");
    var errorForm = document.getElementById("error-page-form");
    var updatePreviewBtn = document.getElementById("btn-update-preview");
    var previewFrame = document.getElementById("error-preview-frame");
    var previewWrapper = document.getElementById("preview-wrapper");
    var viewportControls = document.getElementById("preview-viewport-controls");

    if (loadPresetBtn) {
      loadPresetBtn.addEventListener("click", function () {
        var code = loadPresetBtn.getAttribute("data-code");
        fetch("/api/config/error-pages/" + code + "/preset")
          .then(function (res) { return res.text(); })
          .then(function (text) {
            var contentArea = document.getElementById("error-page-content");
            if (contentArea) {
              contentArea.value = text;
              refreshPreviewFromContent(text);
            }
          })
          .catch(function (err) {
            alert("Gagal memuat preset: " + err);
          });
      });
    }

    if (updatePreviewBtn) {
      updatePreviewBtn.addEventListener("click", function () {
        var contentArea = document.getElementById("error-page-content");
        if (contentArea) {
          refreshPreviewFromContent(contentArea.value);
        }
      });
    }

    if (viewportControls) {
      viewportControls.addEventListener("click", function (e) {
        var btn = e.target.closest("button[data-viewport]");
        if (!btn) return;
        var vp = btn.getAttribute("data-viewport");
        if (previewWrapper) {
          previewWrapper.style.maxWidth = vp;
        }
        var allBtns = viewportControls.querySelectorAll("button[data-viewport]");
        allBtns.forEach(function (b) { b.classList.remove("active-viewport"); });
        btn.classList.add("active-viewport");
      });
    }

    if (errorForm) {
      errorForm.addEventListener("submit", function (e) {
        e.preventDefault();
        var code = errorForm.getAttribute("data-error-code");
        var contentArea = document.getElementById("error-page-content");
        var content = contentArea ? contentArea.value : "";
        var statusDiv = document.getElementById("error-save-status");
        var submitBtn = document.getElementById("btn-save-error-page");

        if (submitBtn) {
          submitBtn.disabled = true;
          submitBtn.textContent = "Menyimpan...";
        }

        var params = new URLSearchParams();
        params.append("code", code);
        params.append("content", content);

        fetch("/api/config/error-pages/" + code, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRF-Token": getCSRFToken()
          },
          body: params.toString()
        })
          .then(function (res) {
            if (!res.ok) {
              return res.text().then(function (t) { throw new Error(t || "Status " + res.status); });
            }
            return res.json();
          })
          .then(function (data) {
            if (statusDiv) {
              statusDiv.innerHTML = '<div class="panel notice-ok" style="margin:0; padding:10px;"><strong style="color:var(--ok)">✓ ' + (data.message || "Tersimpan") + '</strong></div>';
            }
            refreshPreviewFromContent(content);
          })
          .catch(function (err) {
            if (statusDiv) {
              statusDiv.innerHTML = '<div class="panel notice-bad" style="margin:0; padding:10px;"><strong style="color:var(--bad)">✗ ' + err.message + '</strong></div>';
            }
          })
          .finally(function () {
            if (submitBtn) {
              submitBtn.disabled = false;
              submitBtn.textContent = "💾 Simpan & Terapkan Halaman Error";
            }
          });
      });
    }

    function refreshPreviewFromContent(rawHTTP) {
      if (!previewFrame) return;
      var body = rawHTTP;
      var idx = rawHTTP.indexOf("\r\n\r\n");
      if (idx !== -1) {
        body = rawHTTP.substring(idx + 4);
      } else {
        var idx2 = rawHTTP.indexOf("\n\n");
        if (idx2 !== -1) {
          body = rawHTTP.substring(idx2 + 2);
        }
      }
      previewFrame.srcdoc = body;
    }

    // --- Enterprise Queue Actions ---
    var clearQueueBtn = document.getElementById("btn-clear-queue");
    if (clearQueueBtn) {
      clearQueueBtn.addEventListener("click", function () {
        if (!confirm("Kosongkan semua kejadian antrean rate-limit sekarang?")) return;
        fetch("/api/queue/clear", {
          method: "POST",
          headers: { "X-CSRF-Token": getCSRFToken() }
        })
          .then(function (res) { return res.json(); })
          .then(function (data) {
            var fb = document.getElementById("queue-action-feedback");
            if (fb) {
              fb.innerHTML = '<div class="panel notice-ok"><strong style="color:var(--ok)">✓ ' + (data.message || "Antrean berhasil dikosongkan") + '</strong></div>';
            }
            setTimeout(function () { window.location.reload(); }, 800);
          })
          .catch(function (err) {
            alert("Gagal mengosongkan antrean: " + err);
          });
      });
    }

    var refreshQueueBtn = document.getElementById("btn-refresh-queue");
    if (refreshQueueBtn) {
      refreshQueueBtn.addEventListener("click", function () {
        window.location.reload();
      });
    }

    document.body.addEventListener("click", function (e) {
      // Release IP
      var relBtn = e.target.closest(".btn-release-ip");
      if (relBtn) {
        var ip = relBtn.getAttribute("data-ip");
        var pool = relBtn.getAttribute("data-pool") || "";
        if (!confirm("Lepaskan pembatasan laju untuk IP " + ip + " pada pool " + pool + "?")) return;
        
        var params = new URLSearchParams();
        params.append("ip", ip);
        params.append("pool", pool);

        fetch("/api/queue/release-ip", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRF-Token": getCSRFToken()
          },
          body: params.toString()
        })
          .then(function (res) { return res.json(); })
          .then(function (data) {
            alert(data.message || "IP berhasil dilepaskan");
            window.location.reload();
          })
          .catch(function (err) { alert("Gagal melepaskan IP: " + err); });
      }

      // Whitelist IP
      var wlBtn = e.target.closest(".btn-whitelist-ip");
      if (wlBtn) {
        var ip = wlBtn.getAttribute("data-ip");
        if (!confirm("Tambahkan IP " + ip + " ke Allowlist (Bypass Rate-Limit & Block)?")) return;

        var params = new URLSearchParams();
        params.append("file", "/etc/haproxy/maps/allowlist_ip.lst");
        params.append("key", ip);

        fetch("/api/acl/add", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRF-Token": getCSRFToken()
          },
          body: params.toString()
        })
          .then(function (res) {
            if (res.ok) {
              alert("IP " + ip + " berhasil ditambahkan ke Allowlist.");
              window.location.reload();
            } else {
              return res.text().then(function (t) { alert("Gagal menambahkan whitelist: " + t); });
            }
          })
          .catch(function (err) { alert("Gagal whitelist: " + err); });
      }

      // Forward Incident
      var incBtn = e.target.closest(".btn-forward-incident");
      if (incBtn) {
        var ip = incBtn.getAttribute("data-ip");
        var pool = incBtn.getAttribute("data-pool") || "";
        var note = prompt("Catatan / Keterangan untuk insiden baru (IP: " + ip + "):", "Lonjakan antrean rate limit di pool " + pool);
        if (note === null) return;

        var params = new URLSearchParams();
        params.append("ip", ip);
        params.append("pool", pool);
        params.append("summary", note);
        params.append("severity", "high");

        fetch("/api/queue/forward-incident", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRF-Token": getCSRFToken()
          },
          body: params.toString()
        })
          .then(function (res) { return res.json(); })
          .then(function (data) {
            alert(data.message || "Insiden berhasil dibuat.");
            if (data.incident_id) {
              window.location.href = "/incidents/" + data.incident_id;
            }
          })
          .catch(function (err) { alert("Gagal membuat insiden: " + err); });
      }

      // Toggle Pool (Enable/Disable)
      var poolToggleBtn = e.target.closest(".btn-pool-toggle");
      if (poolToggleBtn) {
        var pName = poolToggleBtn.getAttribute("data-pool");
        var pDisabled = poolToggleBtn.getAttribute("data-disabled");
        var actionLabel = pDisabled === "true" ? "menonaktifkan (disable)" : "mengaktifkan kembali (enable)";
        if (!confirm("Konfirmasi " + actionLabel + " kelompok " + pName + "?")) return;

        var pParams = new URLSearchParams();
        pParams.append("disabled", pDisabled);

        fetch("/api/pools/" + encodeURIComponent(pName) + "/toggle-state", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRF-Token": getCSRFToken()
          },
          body: pParams.toString()
        })
          .then(function (res) {
            if (res.ok) {
              window.location.reload();
            } else {
              return res.text().then(function (t) { alert("Gagal mengubah status kelompok: " + t); });
            }
          })
          .catch(function (err) { alert("Gagal: " + err); });
      }

      // Delete Pool
      var poolDeleteBtn = e.target.closest(".btn-pool-delete");
      if (poolDeleteBtn) {
        var delName = poolDeleteBtn.getAttribute("data-pool");
        if (!confirm("PERINGATAN: Hapus seluruh kelompok pool " + delName + " dari konfigurasi HAProxy?\n\nTindakan ini akan menghapus backend dan rute terkait.")) return;

        fetch("/api/pools/" + encodeURIComponent(delName) + "/delete", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRF-Token": getCSRFToken()
          }
        })
          .then(function (res) {
            if (res.ok) {
              alert("Kelompok " + delName + " berhasil dihapus.");
              window.location.href = "/pools";
            } else {
              return res.text().then(function (t) { alert("Gagal menghapus kelompok: " + t); });
            }
          })
          .catch(function (err) { alert("Gagal menghapus: " + err); });
      }
    });

    // --- MCP Setup Panel Interactivity on /config ---
    var mcpBaseUrlInput = document.getElementById("mcp-base-url");
    var mcpApiTokenInput = document.getElementById("mcp-api-token");
    var mcpSnippetArea = document.getElementById("mcp-snippet");
    var mcpTabs = document.getElementById("mcp-tabs");
    var mcpTabHint = document.getElementById("mcp-tab-hint");
    var btnCopyMcp = document.getElementById("btn-copy-mcp");
    var btnTestMcpApi = document.getElementById("btn-test-mcp-api");
    var mcpTestStatus = document.getElementById("mcp-test-status");

    var activeMcpTab = "antigravity";

    if (mcpBaseUrlInput && mcpSnippetArea) {
      if (mcpBaseUrlInput.value === "http://127.0.0.1:9900/api/v1" && window.location.origin) {
        mcpBaseUrlInput.value = window.location.origin + "/api/v1";
      }

      function updateMcpSnippet() {
        var url = mcpBaseUrlInput ? mcpBaseUrlInput.value.trim() : "http://127.0.0.1:9900/api/v1";
        var token = mcpApiTokenInput ? mcpApiTokenInput.value.trim() : "";

        if (activeMcpTab === "antigravity") {
          var configObj = {
            mcpServers: {
              "konsolgw": {
                command: "konsolgw-mcp",
                args: [],
                env: {
                  KONSOLGW_API_URL: url,
                  KONSOLGW_API_TOKEN: token
                }
              }
            }
          };
          mcpSnippetArea.value = JSON.stringify(configObj, null, 2);
          if (mcpTabHint) mcpTabHint.innerHTML = 'Simpan konfigurasi di atas ke file <code>.agents/mcp_config.json</code> pada root workspace project Anda.';
        } else if (activeMcpTab === "claude") {
          var claudeObj = {
            mcpServers: {
              "konsol-gateway": {
                command: "/usr/local/bin/konsolgw-mcp",
                env: {
                  KONSOLGW_API_URL: url,
                  KONSOLGW_API_TOKEN: token
                }
              }
            }
          };
          mcpSnippetArea.value = JSON.stringify(claudeObj, null, 2);
          if (mcpTabHint) mcpTabHint.innerHTML = 'Tambahkan ke file <code>claude_desktop_config.json</code> (di <code>%APPDATA%\\Claude\\</code> atau <code>~/.config/Claude/</code>).';
        } else if (activeMcpTab === "cli") {
          var tokenParam = token ? 'export KONSOLGW_API_TOKEN="' + token + '"\n' : '';
          mcpSnippetArea.value = 'export KONSOLGW_API_URL="' + url + '"\n' + tokenParam + '# Sertifikat self-signed (akses lewat IP)? Aktifkan baris ini:\n# export KONSOLGW_INSECURE=1\n# Jalankan MCP server secara interaktif via stdio:\nkonsolgw-mcp';
          if (mcpTabHint) mcpTabHint.innerHTML = 'Gunakan perintah di atas di terminal untuk menguji komunikasi JSON-RPC 2.0 stdio langsung.';
        } else if (activeMcpTab === "remote") {
          var mcpUrl = mcpEndpointFromBase(url);
          var tok = token || "<API_TOKEN>";
          var plainHdr = "Authorization: Bearer " + tok;
          var mcpJson = {
            mcpServers: {
              "konsol-gateway": { url: mcpUrl, headers: { Authorization: "Bearer " + tok } }
            }
          };
          var viaProxy = {
            mcpServers: {
              "konsol-gateway": {
                command: "npx",
                args: ["-y", "mcp-remote", mcpUrl, "--header", plainHdr],
                env: { NODE_TLS_REJECT_UNAUTHORIZED: "0" }
              }
            }
          };
          mcpSnippetArea.value =
            "# 1) Claude Code (CLI)\n" +
            'claude mcp add --transport http konsol-gateway ' + mcpUrl + ' --header "' + plainHdr + '"\n\n' +
            "# 2) Cursor / VS Code / n8n / klien MCP HTTP lain (mcp.json)\n" +
            JSON.stringify(mcpJson, null, 2) + "\n\n" +
            "# 3) Claude Desktop (lewat mcp-remote, butuh Node.js)\n" +
            JSON.stringify(viaProxy, null, 2) + "\n\n" +
            "# 4) Uji cepat dari terminal\n" +
            "curl -sk " + mcpUrl + ' -H "' + plainHdr + '" -H "Content-Type: application/json" -d \'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\'';
          if (mcpTabHint) mcpTabHint.innerHTML = 'Endpoint MCP HTTP: <code>' + mcpUrl + '</code>. Butuh token dari <a href="/settings">Pengaturan → Token API</a>. Alamat ini hanya bisa dijangkau dari IP yang diizinkan (VPN); sertifikat self-signed perlu dipercaya klien (di Node: <code>NODE_EXTRA_CA_CERTS</code>, atau <code>NODE_TLS_REJECT_UNAUTHORIZED=0</code> hanya untuk uji).';
        }
        mcpSnippetArea.style.height = activeMcpTab === "remote" ? "300px" : "130px";
      }

      // The MCP endpoint lives next to the REST API: <origin>/mcp.
      function mcpEndpointFromBase(base) {
        return base.replace(/\/+$/, "").replace(/\/api\/v1$/, "") + "/mcp";
      }

      updateMcpSnippet();

      if (mcpBaseUrlInput) mcpBaseUrlInput.addEventListener("input", updateMcpSnippet);
      if (mcpApiTokenInput) mcpApiTokenInput.addEventListener("input", updateMcpSnippet);

      if (mcpTabs) {
        mcpTabs.addEventListener("click", function (e) {
          var btn = e.target.closest("button[data-mcp-tab]");
          if (!btn) return;
          activeMcpTab = btn.getAttribute("data-mcp-tab");
          var allBtns = mcpTabs.querySelectorAll("button[data-mcp-tab]");
          allBtns.forEach(function (b) {
            b.style.fontWeight = "normal";
            b.style.borderColor = "var(--border)";
            b.style.color = "var(--text-main)";
          });
          btn.style.fontWeight = "600";
          btn.style.borderColor = "var(--accent)";
          btn.style.color = "var(--accent)";
          updateMcpSnippet();
        });
      }

      if (btnCopyMcp) {
        btnCopyMcp.addEventListener("click", function () {
          if (!mcpSnippetArea) return;
          mcpSnippetArea.select();
          navigator.clipboard.writeText(mcpSnippetArea.value).then(function () {
            var orig = btnCopyMcp.textContent;
            btnCopyMcp.textContent = "✓ Tersalin!";
            setTimeout(function () { btnCopyMcp.textContent = orig; }, 1500);
          }).catch(function () {
            document.execCommand("copy");
            btnCopyMcp.textContent = "✓ Tersalin!";
            setTimeout(function () { btnCopyMcp.textContent = "📋 Salin Konfigurasi"; }, 1500);
          });
        });
      }

      if (btnTestMcpApi) {
        btnTestMcpApi.addEventListener("click", function () {
          if (mcpTestStatus) {
            mcpTestStatus.innerHTML = '<div class="panel" style="padding:8px 12px; margin:0;"><span class="spinner"></span> Menguji endpoint <code>/api/v1/status</code>...</div>';
          }
          var url = mcpBaseUrlInput ? mcpBaseUrlInput.value.trim() : "/api/v1";
          var statusEndpoint = url.replace(/\/+$/, "") + "/status";

          var headers = {};
          var token = mcpApiTokenInput ? mcpApiTokenInput.value.trim() : "";
          if (token) {
            headers["Authorization"] = "Bearer " + token;
          }

          // credentials "omit": a third-party app has no browser session, so the
          // test must pass or fail on the token alone, not on being logged in here.
          var restLine = "";
          fetch(statusEndpoint, { headers: headers, credentials: "omit", redirect: "manual" })
            .then(function (res) {
              if (res.type === "opaqueredirect" || res.status === 0) throw new Error("ditolak (butuh token API yang valid)");
              if (res.status === 401) throw new Error("token API tidak valid atau kosong (HTTP 401)");
              if (!res.ok) throw new Error("HTTP Status " + res.status);
              return res.json();
            })
            .then(function (data) {
              restLine = 'REST: Live ' + (data.data && data.data.live ? 'Online' : 'Offline') + ', Total Backends: ' + (data.data ? data.data.backends_total : '?');
              var mcpHeaders = { "Content-Type": "application/json" };
              if (token) mcpHeaders["Authorization"] = "Bearer " + token;
              return fetch(mcpEndpointFromBase(url), {
                method: "POST", headers: mcpHeaders, credentials: "omit",
                body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } })
              });
            })
            .then(function (res) {
              if (!res.ok) throw new Error("REST OK, tetapi endpoint MCP HTTP " + res.status);
              return res.json();
            })
            .then(function (rpc) {
              if (mcpTestStatus) {
                var srv = rpc.result && rpc.result.serverInfo ? rpc.result.serverInfo.name + " " + rpc.result.serverInfo.version : "?";
                mcpTestStatus.innerHTML = '<div class="panel notice-ok" style="padding:8px 12px; margin:0;"><strong style="color:var(--ok)">✓ Endpoint API dan MCP berhasil diakses</strong> — ' + restLine + ' · MCP: ' + srv + ' (protokol ' + (rpc.result ? rpc.result.protocolVersion : '?') + ')</div>';
              }
            })
            .catch(function (err) {
              if (mcpTestStatus) {
                mcpTestStatus.innerHTML = '<div class="panel notice-bad" style="padding:8px 12px; margin:0;"><strong style="color:var(--bad)">✗ Gagal Mengakses API</strong>: ' + err.message + '</div>';
              }
            });
        });
      }
    }
  });
})();


