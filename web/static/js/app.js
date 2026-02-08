"use strict";

(function () {
    console.log("sneaker ready");

    var statusEl = document.getElementById("status");
    var navEl = document.getElementById("nav-actions");

    // Check authentication state via session cookie
    var isLoggedIn = document.cookie.indexOf("session=") !== -1;

    // Update navigation based on auth state
    if (navEl && isLoggedIn) {
        navEl.innerHTML = "";

        var sendLink = document.createElement("a");
        sendLink.href = "/send.html";
        sendLink.className = "btn";
        sendLink.textContent = "Send a Secret";
        navEl.appendChild(sendLink);

        var logoutBtn = document.createElement("button");
        logoutBtn.className = "btn btn-outline";
        logoutBtn.textContent = "Log Out";
        logoutBtn.addEventListener("click", function () {
            fetch("/api/auth/logout", {
                method: "POST",
                credentials: "same-origin"
            }).then(function () {
                window.location.reload();
            }).catch(function () {
                window.location.reload();
            });
        });
        navEl.appendChild(logoutBtn);
    }

    // Health check
    if (!statusEl) return;

    fetch("/api/health")
        .then(function (res) {
            if (!res.ok) throw new Error("status " + res.status);
            return res.json();
        })
        .then(function (data) {
            if (data.status === "ok") {
                statusEl.textContent = "Connected";
                statusEl.className = "connected";
            }
        })
        .catch(function () {
            statusEl.textContent = "Server unreachable";
            statusEl.className = "error";
        });
})();
