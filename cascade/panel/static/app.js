// CASCADE панель — клиентский JS.
// Вынесен из инлайна: CSP (default-src 'self') блокирует onclick/onsubmit.
// Делегирование событий по data-атрибутам.
(function () {
  "use strict";

  // ── Тосты ──
  function toast(msg, ok) {
    var box = document.getElementById("toast-box");
    if (!box) {
      box = document.createElement("div");
      box.id = "toast-box";
      box.className = "toast-box";
      document.body.appendChild(box);
    }
    var t = document.createElement("div");
    t.className = "toast " + (ok === false ? "toast-err" : "toast-ok");
    t.textContent = msg;
    box.appendChild(t);
    requestAnimationFrame(function () { t.classList.add("show"); });
    setTimeout(function () {
      t.classList.remove("show");
      setTimeout(function () { t.remove(); }, 250);
    }, 1800);
  }

  // ── Копирование (clipboard API + fallback execCommand) ──
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy") ? resolve() : reject();
      } catch (e) { reject(e); }
      ta.remove();
    });
  }

  // Копирование по data-copy (значение атрибута) или data-copy-from (textContent элемента)
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-copy], [data-copy-from]");
    if (!btn) return;
    var text;
    if (btn.hasAttribute("data-copy-from")) {
      var src = document.querySelector(btn.getAttribute("data-copy-from"));
      text = src ? src.textContent : "";
    } else {
      text = btn.getAttribute("data-copy");
    }
    copyText(text).then(function () {
      toast("Скопировано");
      if (!btn.dataset.orig) btn.dataset.orig = btn.textContent;
      btn.textContent = "✓ Скопировано";
      setTimeout(function () { btn.textContent = btn.dataset.orig; }, 1400);
    }).catch(function () { toast("Не удалось скопировать", false); });
  });

  // Подтверждение по data-confirm перед сабмитом формы
  document.addEventListener("submit", function (e) {
    var form = e.target;
    var msg = form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) e.preventDefault();
  });
})();
