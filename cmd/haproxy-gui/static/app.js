// app.js — small, dependency-free helpers loaded alongside htmx.
//
// 1. Surfaces failed htmx requests. By default htmx does nothing visible
//    when a request comes back non-2xx (CSRF rejected, permission denied,
//    server error, network drop) — a button just looks like it "doesn't
//    work". Every failure here gets an explicit red banner instead.
// 2. When a page is opened at a "#member-<name>" anchor (used by the
//    dashboard's "Ubah" link to point at a specific pool member row),
//    briefly highlights that row so it's obvious which one to edit.
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
    showError(evt.detail && evt.detail.target, "Tidak bisa terhubung ke server. Periksa koneksi jaringan Anda lalu coba lagi.");
  });

  document.addEventListener("DOMContentLoaded", function () {
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
})();
