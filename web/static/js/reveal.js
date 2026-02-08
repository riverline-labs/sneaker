"use strict";

(function () {
    // --- DOM elements ---
    var interstitial = document.getElementById("reveal-interstitial");
    var content = document.getElementById("reveal-content");
    var errorEl = document.getElementById("reveal-error");
    var revealBtn = document.getElementById("reveal-btn");
    var secretEl = document.getElementById("secret-text");
    var copyBtn = document.getElementById("copy-btn");
    var passphrasePrompt = document.getElementById("passphrase-prompt");
    var passphraseInput = document.getElementById("passphrase-input");
    var passphraseError = document.getElementById("passphrase-error");
    var decryptBtn = document.getElementById("decrypt-btn");

    // --- Parse URL ---
    var fragment = window.location.hash.slice(1);
    // Clear fragment from address bar immediately
    if (window.location.hash) {
        history.replaceState(null, "", window.location.pathname);
    }

    // Extract secret ID from path: /s/{id}
    var pathParts = window.location.pathname.split("/");
    var secretId = pathParts[pathParts.length - 1];

    // --- Validation ---
    if (!fragment || !fragment.startsWith("AGE-SECRET-KEY-1")) {
        showError("Invalid link \u2014 no decryption key found in URL.");
        return;
    }
    if (!secretId || secretId.length !== 64) {
        showError("Invalid link \u2014 missing secret identifier.");
        return;
    }

    // Store identity for later use (fragment is already cleared from URL)
    var identity = fragment;

    // --- Show interstitial (two-step reveal) ---
    show(interstitial);
    revealBtn.addEventListener("click", function () {
        revealBtn.disabled = true;
        revealBtn.textContent = "Decrypting...";
        fetchAndDecrypt(secretId, identity);
    });

    // --- Copy button ---
    copyBtn.addEventListener("click", function () {
        var text = secretEl.textContent;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function () {
                copyBtn.textContent = "Copied!";
                copyBtn.classList.add("btn-success");
                setTimeout(function () {
                    copyBtn.textContent = "Copy to Clipboard";
                    copyBtn.classList.remove("btn-success");
                }, 2000);
            }).catch(function () {
                copyBtn.textContent = "Copy failed \u2014 select text manually";
                setTimeout(function () {
                    copyBtn.textContent = "Copy to Clipboard";
                }, 3000);
            });
        } else {
            copyBtn.textContent = "Copy not supported \u2014 select text manually";
            setTimeout(function () {
                copyBtn.textContent = "Copy to Clipboard";
            }, 3000);
        }
    });

    // --- Core decrypt logic ---
    async function fetchAndDecrypt(id, ident) {
        try {
            var resp = await fetch("/api/secrets/" + id);
            if (!resp.ok) {
                if (resp.status === 410) {
                    showError("This secret has already been viewed or has expired.");
                } else {
                    showError("Failed to retrieve secret. Please try again.");
                }
                return;
            }

            var data = await resp.json();
            var ciphertext = base64urlToUint8Array(data.ciphertext);

            if (data.passphrase_protected) {
                // Hold ciphertext in memory for passphrase retry
                hide(interstitial);
                show(passphrasePrompt);
                passphraseInput.focus();

                decryptBtn.addEventListener("click", function () {
                    var passphrase = passphraseInput.value;
                    if (!passphrase) {
                        passphraseError.textContent = "Please enter a passphrase.";
                        passphraseError.style.display = "block";
                        return;
                    }
                    decryptBtn.disabled = true;
                    decryptBtn.textContent = "Decrypting...";
                    passphraseError.style.display = "none";
                    decryptWithPassphrase(ciphertext, ident, passphrase);
                });

                passphraseInput.addEventListener("keydown", function (e) {
                    if (e.key === "Enter") {
                        e.preventDefault();
                        decryptBtn.click();
                    }
                });
            } else {
                // Standard X25519 decryption (no passphrase)
                var d = new age.Decrypter();
                d.addIdentity(ident);
                var plainBytes = await d.decrypt(ciphertext, "uint8array");
                var plaintext = new TextDecoder().decode(plainBytes);

                secretEl.textContent = plaintext;
                hide(interstitial);
                show(content);
            }
        } catch (e) {
            showError("Failed to decrypt this secret. The link may be corrupted.");
        }
    }

    // --- Passphrase decryption (two-layer: scrypt then X25519) ---
    async function decryptWithPassphrase(ciphertext, ident, passphrase) {
        try {
            // Layer 1: Decrypt scrypt passphrase layer
            var d1 = new age.Decrypter();
            d1.addPassphrase(passphrase);
            var x25519Ciphertext;
            try {
                x25519Ciphertext = await d1.decrypt(ciphertext, "uint8array");
            } catch (e) {
                // Wrong passphrase -- let user retry
                passphraseError.textContent = "Incorrect passphrase. Please try again.";
                passphraseError.style.display = "block";
                decryptBtn.disabled = false;
                decryptBtn.textContent = "Decrypt";
                passphraseInput.value = "";
                passphraseInput.focus();
                return;
            }
            // Layer 2: Decrypt X25519 layer
            var d2 = new age.Decrypter();
            d2.addIdentity(ident);
            var plainBytes = await d2.decrypt(x25519Ciphertext, "uint8array");
            var plaintext = new TextDecoder().decode(plainBytes);

            secretEl.textContent = plaintext;
            hide(passphrasePrompt);
            show(content);
        } catch (e) {
            showError("Failed to decrypt this secret. The link may be corrupted.");
        }
    }

    // --- Base64url helpers ---
    function base64urlToUint8Array(str) {
        var base64 = str.replace(/-/g, "+").replace(/_/g, "/");
        while (base64.length % 4 !== 0) {
            base64 += "=";
        }
        var binary = atob(base64);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    // --- UI helpers ---
    function show(el) { if (el) el.style.display = "block"; }
    function hide(el) { if (el) el.style.display = "none"; }
    function showError(msg) {
        if (errorEl) {
            errorEl.querySelector(".error-message").textContent = msg;
            hide(interstitial);
            hide(content);
            show(errorEl);
        }
    }
})();
