const form = document.getElementById("signupForm");
const errorMsg = document.getElementById("errorMsg");

form.addEventListener("submit", function (e) {

    const username = document.getElementById("username").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value.trim();
    const confirmPassword = document.getElementById("confirmPassword").value.trim();

    // Basic client-side validation
    if (!username || !email || !password || !confirmPassword) {
        e.preventDefault();
        errorMsg.textContent = "All fields are required";
        return;
    }

    // Email format check
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        e.preventDefault();
        errorMsg.textContent = "Invalid email format";
        return;
    }

    // Password match check
    if (password !== confirmPassword) {
        e.preventDefault();
        errorMsg.textContent = "Passwords do not match";
        return;
    }
});
