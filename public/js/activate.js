document.getElementById("activateForm").addEventListener("submit", async function (event) {
    event.preventDefault();

    const username = document.getElementById("username").value.trim();
    const token = document.getElementById("token").value.trim();
    const msg = document.getElementById("activateMsg");
    const linksDiv = document.getElementById("links");

    msg.textContent = "";
    msg.classList.remove("visible", "error", "success");
    linksDiv.classList.remove("visible");

    if (!username || !token) {
        msg.textContent = "Username and token are required.";
        msg.classList.add("visible", "error");
        return;
    }
	
	if (token.length < 20) {
	    msg.textContent = "Invalid token format. Please check your email.";
	    msg.classList.add("visible", "error");
	    return;
	}

	const tokenRegex = /^[A-Za-z0-9-_]+$/;
	if (!tokenRegex.test(token)) {
	    msg.textContent = "Invalid token format. Token contains invalid characters.";
	    msg.classList.add("visible", "error");
	    return;
	}

    try {
        const response = await fetch("/activate", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ username, token }),
        });

        const data = await response.json();

        if (data.success) {
            msg.textContent = "Email successfully activated! Redirecting to login page...";
            msg.classList.add("visible", "success");

            // Redirect to login page after a few seconds
            setTimeout(() => {
                window.location.href = "/login.html";
            }, 2000);
        } else {
            msg.textContent = data.message || "Activation failed.";
            msg.classList.add("visible", "error");

            // Display a link back to the register
            linksDiv.classList.add("visible");
        }
    } catch (error) {
        console.error("Activation error:", error);
        msg.textContent = "Server error. Please try again later.";
        msg.classList.add("visible", "error");
        linksDiv.classList.add("visible");
    }
});