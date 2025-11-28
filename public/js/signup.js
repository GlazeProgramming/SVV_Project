const form = document.getElementById("signupForm");
const errorMsg = document.getElementById("errorMsg");

const showError = (message) => {
    errorMsg.textContent = message;
    errorMsg.classList.add("visible", "error");
};

const clearError = () => {
    errorMsg.textContent = "";
    errorMsg.classList.remove("visible", "error");
};

// DOB input
const dobInput = document.getElementById("dob");

// Auto-open datepicker when clicking input wrapper
dobInput.parentElement.addEventListener("click", () => {
    dobInput.showPicker?.();
});

// Limit DOB to only 18–100 years old
const today = new Date();
const minAgeDate = new Date(today.getFullYear() - 18, today.getMonth(), today.getDate());
const maxAgeDate = new Date(today.getFullYear() - 100, today.getMonth(), today.getDate());

dobInput.max = minAgeDate.toISOString().split("T")[0]; // youngest allowed (18 y/o)
dobInput.min = maxAgeDate.toISOString().split("T")[0]; // oldest allowed (100 y/o)


document.querySelectorAll(".toggle-password").forEach((button) => {
    button.addEventListener("click", () => {
        const target = document.getElementById(button.dataset.target);
        if (!target) return;
        const isHidden = target.type === "password";
        target.type = isHidden ? "text" : "password";

        const icon = button.querySelector("ion-icon");
        icon?.setAttribute("name", isHidden ? "eye" : "eye-off");

        button.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
    });
});

const inputBoxes = document.querySelectorAll(".input-box input");

const syncLabelState = (input) => {
    const wrapper = input.closest(".input-box");
    if (!wrapper) return;
    const hasValue = input.type === "date" ? Boolean(input.value) : Boolean(input.value.trim());
    wrapper.classList.toggle("has-content", hasValue);
};

inputBoxes.forEach((input) => {
    syncLabelState(input);
    input.addEventListener("input", () => syncLabelState(input));
    input.addEventListener("blur", () => syncLabelState(input));
});

form.addEventListener("submit", async function (e) { 
	
	e.preventDefault();
	
	clearError();
    
    const firstname = document.getElementById("firstname").value.trim();
    const lastname = document.getElementById("lastname").value.trim();
    const dob = document.getElementById("dob").value.trim();
    const phonenumber = document.getElementById('phonenumber').value.trim();
	const username = document.getElementById("username").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value.trim();
    const confirmPassword = document.getElementById("confirmPassword").value.trim();

     // Firstname length check and only allow character 
    const nameRegex = /^[A-Za-z ]{3,}$/; 
    if (!nameRegex.test(firstname)) {
        showError("Firstname must be at least 3 letters (A-Z) only.");
        return;
    }

    // Phone number: must be '+' and only digits
    const phoneRegex = /^\+[0-9]{7,15}$/; 
    if (!phoneRegex.test(phonenumber)) {
        showError("Phone number must start with + and contain digits only (example: +60123456789).");
        return;
    }

    // Client-side Validation
    if (!firstname || !username || !email || !password || !confirmPassword ||
        !dob || !phonenumber) {
        showError("All fields are required except lastname");
        return;
    }

    // DOB check: user must be at least 18 years old
    const selectedDob = new Date(dob);
    const ageDiff = today.getFullYear() - selectedDob.getFullYear();
    const birthdayHasPassed = (today.getMonth() > selectedDob.getMonth()) ||
        (today.getMonth() === selectedDob.getMonth() && today.getDate() >= selectedDob.getDate());
    const age = birthdayHasPassed ? ageDiff : ageDiff - 1;
    if (age < 18) {
        errorMsg.textContent = "You must be at least 18 years old to register.";
        return;
    }
    // Maximum age (not older than 100)
    if (age > 100) {
        errorMsg.textContent = "Birth year too old. Please enter a valid date of birth.";
        return;
    }

	// Email Format Validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        showError("Invalid email format");
        return;
    }

	// Password length check
    if (password.length < 6) {
        showError("Password must be at least 6 characters long");
        return;
    }

	// Password Match check
    if (password !== confirmPassword) {
        showError("Passwords do not match");
        return;
    }

    // Requires: at least one lowercase, one uppercase, one digit, and one special character.
    const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{6,}$/;

    if (!complexityRegex.test(password)) {
        showError("Password must include an uppercase letter, a lowercase letter, a digit, and a special character.");
        return;
    }

    // Terms and Conditions checkbox validation
    const termsCheckbox = document.getElementById("terms");
    if (!termsCheckbox.checked) {
        showError("You must agree to the Terms & Conditions to register.");
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
                firstname,
                lastname,
                dob,
                phonenumber,
                username,
                email,
                password,
                confirmPassword,
                terms: document.getElementById("terms").checked,
            }),
        });

        const data = await response.json(); 

        if (response.ok && data.success) {
            alert(data.message);
            window.location.href = "/activate.html"; 
            
        } else {
            showError(data.message);
        }

    } catch (error) {
        console.error("Fetch Error:", error);
        showError("A network error occurred. Please try again.");
    }

});