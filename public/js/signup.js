const form = document.getElementById("signupForm");
const errorMsg = document.getElementById("errorMsg");

form.addEventListener("submit", async function (e) { 
	
	e.preventDefault();
	
	errorMsg.textContent = "";
    
	const username = document.getElementById("username").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value.trim();
    const confirmPassword = document.getElementById("confirmPassword").value.trim();

    // Client-side Validation
    if (!username || !email || !password || !confirmPassword) {
        errorMsg.textContent = "All fields are required";
        return;
    }

	// Email Format Validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        errorMsg.textContent = "Invalid email format";
        return;
    }

	// Password Match check
    if (password !== confirmPassword) {
        errorMsg.textContent = "Passwords do not match";
        return;
    }
	
	// Password length check
    if (password.length < 6) {
        errorMsg.textContent = "Password must be at least 6 characters long";
        return;
    }

    // Requires: at least one lowercase, one uppercase, one digit, and one special character.
    const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{6,}$/;

    if (!complexityRegex.test(password)) {
        errorMsg.textContent = "Password must include an uppercase letter, a lowercase letter, a digit, and a special character.";
        return;
    }
	
	// Send data using fetch to the server
    try {
        const response = await fetch("/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json", 
            },
            body: JSON.stringify({
                username,
                email,
                password,
                confirmPassword,
            }),
        });

        const data = await response.json(); 

        if (response.ok && data.success) {
            alert(data.message);
            window.location.href = "/login.html"; 
            
        } else {
            errorMsg.textContent = data.message;
        }

    } catch (error) {
        console.error("Fetch Error:", error);
        errorMsg.textContent = "A network error occurred. Please try again.";
    }

});