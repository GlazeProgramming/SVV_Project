document.getElementById("activateForm").addEventListener("submit", async function (event) {
    event.preventDefault();

    const username = document.getElementById("username").value.trim();
    const token = document.getElementById("token").value.trim();
    const msg = document.getElementById("activateMsg");
    const linksDiv = document.getElementById("links");

    msg.textContent = "";
    linksDiv.style.display = "none";

    if (!username || !token) {
        msg.textContent = "Username and token are required.";
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
            msg.style.color = "green";
            msg.textContent = "Email successfully activated! Redirecting to login page...";

            // Redirect ke login setelah beberapa detik
            setTimeout(() => {
                window.location.href = "/login.html";
            }, 2000);
        } else {
            msg.style.color = "red";
            msg.textContent = data.message || "Activation failed.";

            // Tampilkan link balik ke register
            linksDiv.style.display = "block";
        }
    } catch (error) {
        console.error("Activation error:", error);
        msg.style.color = "red";
        msg.textContent = "Server error. Please try again later.";
        linksDiv.style.display = "block";
    }
});