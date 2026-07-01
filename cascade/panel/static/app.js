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

  // Скачивание QR-кода (SVG → PNG через Canvas)
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-download-qr]");
    if (!btn) return;
    var row = btn.closest(".profile-row") || btn.closest(".share-card");
    if (!row) return;
    var svg = row.querySelector(".qr-box svg, .share-qr svg");
    if (!svg) return;
    var svgData = new XMLSerializer().serializeToString(svg);
    var blob = new Blob([svgData], { type: "image/svg+xml" });
    var url = URL.createObjectURL(blob);
    var img = new Image();
    img.onload = function () {
      var canvas = document.createElement("canvas");
      canvas.width = img.naturalWidth || 256;
      canvas.height = img.naturalHeight || 256;
      var ctx = canvas.getContext("2d");
      ctx.fillStyle = "#fff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0);
      URL.revokeObjectURL(url);
      canvas.toBlob(function (pngBlob) {
        var pngUrl = URL.createObjectURL(pngBlob);
        var a = document.createElement("a");
        a.href = pngUrl;
        a.download = "qr-" + btn.dataset.downloadQr + ".png";
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(pngUrl);
        toast("Файл скачан");
      }, "image/png");
    };
    img.onerror = function () {
      URL.revokeObjectURL(url);
      toast("Ошибка конвертации", false);
    };
    img.src = url;
  });

  // Подтверждение по data-confirm перед сабмитом формы
  document.addEventListener("submit", function (e) {
    var form = e.target;
    var msg = form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) e.preventDefault();
  });
})();
