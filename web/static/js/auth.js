"use strict";

(function () {
    var form = document.getElementById("auth-form");
    var errorEl = document.getElementById("auth-error");
    if (!form || !errorEl) return;

    var page = form.getAttribute("data-page");

    function showError(msg) {
        errorEl.textContent = msg;
        errorEl.style.display = "block";
    }

    function hideError() {
        errorEl.style.display = "none";
        errorEl.textContent = "";
    }

    form.addEventListener("submit", function (e) {
        e.preventDefault();
        hideError();

        var email = form.querySelector('input[name="email"]').value.trim();
        var password = form.querySelector('input[name="password"]').value;

        if (page === "signup") {
            var confirm = form.querySelector('input[name="confirm"]').value;
            if (password.length < 8) {
                showError("Password must be at least 8 characters.");
                return;
            }
            if (password !== confirm) {
                showError("Passwords do not match.");
                return;
            }
        }

        var endpoint = page === "signup" ? "/api/auth/signup" : "/api/auth/login";
        var body = JSON.stringify({ email: email, password: password });

        fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: body
        })
            .then(function (res) {
                if (page === "login") {
                    if (res.ok) {
                        window.location.href = "/";
                        return;
                    }
                    if (res.status === 401) {
                        showError("Invalid email or password.");
                        return;
                    }
                    showError("Something went wrong. Please try again.");
                } else {
                    if (res.status === 201 || res.ok) {
                        window.location.href = "/";
                        return;
                    }
                    if (res.status === 409) {
                        showError("Email already registered.");
                        return;
                    }
                    if (res.status === 400) {
                        return res.json().then(function (data) {
                            showError(data.error || "Invalid input.");
                        });
                    }
                    showError("Something went wrong. Please try again.");
                }
            })
            .catch(function () {
                showError("Something went wrong. Please try again.");
            });
    });
})();
