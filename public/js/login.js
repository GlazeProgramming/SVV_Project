document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("signupForm"); // keep the same ID as your form
    const errorMsg = document.getElementById("errorMsg");

    const setMessage = (message, type = "error") => {
        if (!message) {
            errorMsg.textContent = "";
            errorMsg.classList.remove("visible", "error", "success");
            return;
        }

        errorMsg.textContent = message;
        errorMsg.classList.remove("error", "success");
        errorMsg.classList.add("visible", type === "success" ? "success" : "error");
    };

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        setMessage("");

        const data = {
            username: form.username.value.trim(),
            password: form.password.value.trim()
        };

        try {
            const res = await fetch("/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(data)
            });

            const result = await res.json();

            setMessage(result.message, result.success ? "success" : "error");

            if (result.success) {
                setTimeout(() => {
                    window.location.href = "dashboard.html"; // redirect after login
                }, 1000);
            }
        } catch (err) {
            console.error(err);
            setMessage("Server error occurred", "error");
        }
    });
});
