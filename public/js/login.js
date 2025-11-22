document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("signupForm"); // keep the same ID as your form
    const errorMsg = document.getElementById("errorMsg");

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

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

            errorMsg.textContent = result.message;
            errorMsg.style.color = result.success ? "green" : "red";

            if (result.success) {
                setTimeout(() => {
                    window.location.href = "dashboard.html"; // redirect after login
                }, 1000);
            }
        } catch (err) {
            console.error(err);
            errorMsg.textContent = "Server error occurred";
            errorMsg.style.color = "red";
        }
    });
});
