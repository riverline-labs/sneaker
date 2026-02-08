"use strict";

(function () {
    var form = document.getElementById("send-form");
    var errorEl = document.getElementById("send-error");
    var textarea = document.getElementById("secret-input");
    var charCount = document.getElementById("char-count");
    var sendBtn = document.getElementById("send-btn");
    var resultEl = document.getElementById("result");
    var resultUrl = document.getElementById("result-url");
    var copyBtn = document.getElementById("copy-btn");
    var modeRadios = document.querySelectorAll('input[name="mode"]');
    var recipientField = document.getElementById("recipient-field");
    var recipientInput = document.getElementById("recipient-email");
    var resultIdentity = document.getElementById("result-identity");
    var ttlSelect = document.getElementById("ttl-select");
    var passphraseField = document.getElementById("passphrase-field");
    var passphraseInput = document.getElementById("passphrase-input");
    var passphraseConfirm = document.getElementById("passphrase-confirm");
    var passphraseConfirmField = document.getElementById("passphrase-confirm-field");

    if (!form || !textarea) return;

    // Character count display
    textarea.addEventListener("input", function () {
        var len = textarea.value.length;
        charCount.textContent = len + " character" + (len !== 1 ? "s" : "");
    });

    // Mode toggle listener
    modeRadios.forEach(function (radio) {
        radio.addEventListener("change", function () {
            if (this.value === "identity") {
                recipientField.style.display = "block";
                passphraseField.style.display = "none";
            } else {
                recipientField.style.display = "none";
                passphraseField.style.display = "block";
            }
        });
    });

    // Show confirm field when passphrase is entered
    if (passphraseInput) {
        passphraseInput.addEventListener("input", function () {
            if (passphraseInput.value.length > 0) {
                passphraseConfirmField.style.display = "block";
            } else {
                passphraseConfirmField.style.display = "none";
                passphraseConfirm.value = "";
            }
        });
    }

    function getSelectedMode() {
        var checked = document.querySelector('input[name="mode"]:checked');
        return checked ? checked.value : "link";
    }

    function showError(msg) {
        errorEl.textContent = msg;
        errorEl.style.display = "block";
    }

    function hideError() {
        errorEl.style.display = "none";
        errorEl.textContent = "";
    }

    function uint8ArrayToBase64url(bytes) {
        var binary = "";
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
    }

    function handle401() {
        showError("Please log in first.");
        setTimeout(function () {
            window.location.href = "/login.html";
        }, 1500);
        sendBtn.disabled = false;
        sendBtn.textContent = "Encrypt & Send";
    }

    function resetBtn() {
        sendBtn.disabled = false;
        sendBtn.textContent = "Encrypt & Send";
    }

    function sendLinkMode(plaintext) {
        var identity;
        var passphrase = passphraseInput ? passphraseInput.value : "";
        var ttlSeconds = ttlSelect ? parseInt(ttlSelect.value, 10) : 0;

        // Validate passphrase confirmation
        if (passphrase && passphraseConfirm && passphraseConfirm.value !== passphrase) {
            showError("Passphrases do not match.");
            resetBtn();
            return;
        }

        age.generateIdentity()
            .then(function (id) {
                identity = id;
                return age.identityToRecipient(identity);
            })
            .then(function (recipient) {
                var encrypter = new age.Encrypter();
                encrypter.addRecipient(recipient);
                return encrypter.encrypt(new TextEncoder().encode(plaintext));
            })
            .then(function (x25519Ciphertext) {
                // If passphrase is set, apply second layer of encryption
                if (!passphrase) {
                    return x25519Ciphertext;
                }
                var outerEncrypter = new age.Encrypter();
                outerEncrypter.setPassphrase(passphrase);
                return outerEncrypter.encrypt(x25519Ciphertext);
            })
            .then(function (ciphertext) {
                var b64 = uint8ArrayToBase64url(ciphertext);

                sendBtn.textContent = "Sending...";

                var body = { ciphertext: b64 };
                if (ttlSeconds > 0) {
                    body.ttl_seconds = ttlSeconds;
                }
                if (passphrase) {
                    body.passphrase_protected = true;
                }

                return fetch("/api/secrets", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    credentials: "same-origin",
                    body: JSON.stringify(body)
                }).then(function (res) {
                    if (res.status === 401) {
                        handle401();
                        return;
                    }
                    if (!res.ok) {
                        return res.json().then(function (data) {
                            throw new Error(data.error || "Failed to send secret.");
                        });
                    }
                    return res.json();
                }).then(function (data) {
                    if (!data) return; // 401 redirect case

                    var url = window.location.origin + "/s/" + data.id + "#" + identity;

                    resultUrl.value = url;
                    form.style.display = "none";
                    resultEl.style.display = "block";

                    // Add note when passphrase was used
                    if (passphrase) {
                        var msgInfo = resultEl.querySelector(".msg-info");
                        if (msgInfo) {
                            msgInfo.textContent = "This link works once. The recipient will also need the passphrase you set to decrypt the secret.";
                        }
                    }
                });
            })
            .catch(function (err) {
                showError(err.message || "Something went wrong. Please try again.");
                resetBtn();
            });
    }

    function fetchTeamMembers(teamName) {
        return fetch("/api/teams/" + encodeURIComponent(teamName) + "/members", {
            credentials: "same-origin"
        }).then(function(res) {
            if (res.status === 401) { handle401(); return null; }
            if (res.status === 403) { throw new Error("You are not a member of team @" + teamName + "."); }
            if (res.status === 404) { throw new Error("Team @" + teamName + " not found."); }
            if (!res.ok) {
                return res.json().then(function(data) {
                    throw new Error(data.error || "Failed to look up team.");
                });
            }
            return res.json();
        });
    }

    function sendTeamMode(plaintext, teamName) {
        sendBtn.textContent = "Looking up team members...";

        var senderEmail = "";
        fetch("/api/auth/me", { credentials: "same-origin" })
            .then(function(res) {
                if (res.ok) return res.json();
                return null;
            })
            .then(function(me) {
                if (me) senderEmail = me.email;
                return fetchTeamMembers(teamName);
            })
            .then(function(members) {
                if (!members) return; // 401 redirect

                var ttlSeconds = ttlSelect ? parseInt(ttlSelect.value, 10) : 0;

                var eligible = [];
                var skipped = 0;
                for (var i = 0; i < members.length; i++) {
                    if (members[i].email === senderEmail) continue;
                    if (!members[i].public_key) {
                        skipped++;
                        continue;
                    }
                    eligible.push(members[i]);
                }

                if (eligible.length === 0) {
                    throw new Error("No team members with public keys to send to.");
                }

                sendBtn.textContent = "Encrypting for " + eligible.length + " members...";

                var chain = Promise.resolve();
                var sent = 0;
                eligible.forEach(function(member) {
                    chain = chain.then(function() {
                        var encrypter = new age.Encrypter();
                        encrypter.addRecipient(member.public_key);
                        return encrypter.encrypt(new TextEncoder().encode(plaintext))
                            .then(function(ciphertext) {
                                var b64 = uint8ArrayToBase64url(ciphertext);
                                var body = {
                                    ciphertext: b64,
                                    mode: "identity",
                                    recipient_email: member.email
                                };
                                if (ttlSeconds > 0) {
                                    body.ttl_seconds = ttlSeconds;
                                }
                                return fetch("/api/secrets", {
                                    method: "POST",
                                    headers: { "Content-Type": "application/json" },
                                    credentials: "same-origin",
                                    body: JSON.stringify(body)
                                });
                            })
                            .then(function(res) {
                                if (res.status === 401) { handle401(); return; }
                                if (!res.ok) {
                                    console.warn("Failed to send to " + member.email);
                                    return;
                                }
                                sent++;
                                sendBtn.textContent = "Sent " + sent + "/" + eligible.length + "...";
                            });
                    });
                });

                return chain.then(function() {
                    if (sent === 0) {
                        throw new Error("Failed to send to any team members.");
                    }
                    form.style.display = "none";
                    document.querySelector(".mode-toggle").style.display = "none";
                    var msgEl = resultIdentity.querySelector("p");
                    if (msgEl) {
                        msgEl.textContent =
                            "Secret sent to " + sent + " member" + (sent !== 1 ? "s" : "") +
                            " of @" + teamName + (skipped > 0 ? " (" + skipped + " skipped: no key)" : "");
                    }
                    resultIdentity.style.display = "block";
                });
            })
            .catch(function(err) {
                showError(err.message || "Something went wrong. Please try again.");
                resetBtn();
            });
    }

    function sendIdentityMode(plaintext) {
        var email = recipientInput.value.trim();
        if (!email) {
            showError("Please enter a recipient email or @team.");
            resetBtn();
            return;
        }

        if (email.charAt(0) === "@") {
            var teamName = email.substring(1);
            if (!teamName) {
                showError("Please enter a team name after @.");
                resetBtn();
                return;
            }
            sendTeamMode(plaintext, teamName);
            return;
        }

        var ttlSeconds = ttlSelect ? parseInt(ttlSelect.value, 10) : 0;

        sendBtn.textContent = "Looking up recipient...";

        fetch("/api/identity/pubkey/" + encodeURIComponent(email), {
            credentials: "same-origin"
        })
            .then(function (res) {
                if (res.status === 401) {
                    handle401();
                    return;
                }
                if (res.status === 404) {
                    throw new Error("Recipient not found or has no public key.");
                }
                if (!res.ok) {
                    return res.json().then(function (data) {
                        throw new Error(data.error || "Failed to look up recipient.");
                    });
                }
                return res.json();
            })
            .then(function (data) {
                if (!data) return; // 401 redirect case

                sendBtn.textContent = "Encrypting...";

                var encrypter = new age.Encrypter();
                encrypter.addRecipient(data.public_key);
                return encrypter.encrypt(new TextEncoder().encode(plaintext))
                    .then(function (ciphertext) {
                        var b64 = uint8ArrayToBase64url(ciphertext);

                        sendBtn.textContent = "Sending...";

                        var body = {
                            ciphertext: b64,
                            mode: "identity",
                            recipient_email: email
                        };
                        if (ttlSeconds > 0) {
                            body.ttl_seconds = ttlSeconds;
                        }

                        return fetch("/api/secrets", {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            credentials: "same-origin",
                            body: JSON.stringify(body)
                        });
                    });
            })
            .then(function (res) {
                if (!res) return; // 401 redirect case

                if (res.status === 401) {
                    handle401();
                    return;
                }
                if (!res.ok) {
                    return res.json().then(function (data) {
                        throw new Error(data.error || "Failed to send secret.");
                    });
                }
                return res.json();
            })
            .then(function (data) {
                if (!data) return; // 401 or earlier bail

                form.style.display = "none";
                document.querySelector(".mode-toggle").style.display = "none";
                resultIdentity.style.display = "block";
            })
            .catch(function (err) {
                showError(err.message || "Something went wrong. Please try again.");
                resetBtn();
            });
    }

    function handleSend(e) {
        e.preventDefault();
        hideError();

        var plaintext = textarea.value;
        if (!plaintext.trim()) {
            showError("Please enter a secret.");
            return;
        }

        sendBtn.disabled = true;
        sendBtn.textContent = "Encrypting...";

        var mode = getSelectedMode();
        if (mode === "identity") {
            sendIdentityMode(plaintext);
        } else {
            sendLinkMode(plaintext);
        }
    }

    if (recipientInput) {
        recipientInput.placeholder = "alice@example.com or @teamname";
    }

    form.addEventListener("submit", handleSend);

    // Copy button handler
    if (copyBtn) {
        copyBtn.addEventListener("click", function () {
            var url = resultUrl.value;
            if (!url) return;

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(url)
                    .then(function () {
                        copyBtn.textContent = "Copied!";
                        copyBtn.classList.add("btn-success");
                        setTimeout(function () {
                            copyBtn.textContent = "Copy Link";
                            copyBtn.classList.remove("btn-success");
                        }, 2000);
                    })
                    .catch(function () {
                        fallbackCopy();
                    });
            } else {
                fallbackCopy();
            }

            function fallbackCopy() {
                resultUrl.select();
                resultUrl.setSelectionRange(0, 99999);
                try {
                    document.execCommand("copy");
                    copyBtn.textContent = "Copied!";
                    copyBtn.classList.add("btn-success");
                    setTimeout(function () {
                        copyBtn.textContent = "Copy Link";
                        copyBtn.classList.remove("btn-success");
                    }, 2000);
                } catch (err) {
                    copyBtn.textContent = "Copy failed - select and copy manually";
                    setTimeout(function () {
                        copyBtn.textContent = "Copy Link";
                    }, 3000);
                }
            }
        });
    }
})();
