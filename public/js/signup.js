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

// Hide country name after selection - show only the code
// But keep full names visible in the dropdown
const countryCodeSelect = document.getElementById("countryCode");
if (countryCodeSelect) {
    // Store original option texts
    Array.from(countryCodeSelect.options).forEach(option => {
        if (option.text) {
            option.setAttribute("data-full-text", option.text);
        }
    });
    
    // Function to restore all options to full text (for dropdown display)
    function restoreAllOptionTexts() {
        Array.from(countryCodeSelect.options).forEach(option => {
            const fullText = option.getAttribute("data-full-text");
            if (fullText && option.text !== fullText) {
                option.text = fullText;
            }
        });
    }
    
    // Function to show only code for selected option
    function showCodeOnly() {
        const selectedOption = countryCodeSelect.options[countryCodeSelect.selectedIndex];
        if (selectedOption && selectedOption.value) {
            const fullText = selectedOption.getAttribute("data-full-text") || selectedOption.text;
            const codeMatch = fullText.match(/^(\+\d+)/);
            if (codeMatch) {
                selectedOption.text = codeMatch[1];
            }
        }
    }
    
    // When dropdown opens (focus), restore all option texts so full names are visible
    countryCodeSelect.addEventListener("focus", function() {
        restoreAllOptionTexts();
    });
    
    // When dropdown opens (mousedown), restore all option texts
    countryCodeSelect.addEventListener("mousedown", function() {
        restoreAllOptionTexts();
    });
    
    // After selection is made, show only code
    countryCodeSelect.addEventListener("change", function() {
        // Small delay to ensure change event completes
        setTimeout(() => {
            showCodeOnly();
        }, 10);
    });
    
    // When dropdown closes (blur), show only code for selected
    countryCodeSelect.addEventListener("blur", function() {
        setTimeout(() => {
            showCodeOnly();
        }, 10);
    });
    
    // Initialize: if there's a pre-selected value, show only code
    if (countryCodeSelect.value) {
        showCodeOnly();
    }
}

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
	const countryCode = document.getElementById("countryCode").value;
	const localNumber = document.getElementById("localNumber").value.trim();
	const phonenumber = countryCode + localNumber;
	const username = document.getElementById("username").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value.trim();
    const confirmPassword = document.getElementById("confirmPassword").value.trim();
	
	const MAX_USERNAME_LEN = 100;
    const MAX_NAME_LEN = 30; 
	const MIN_PHONE_DIGITS = 7; 
    const MAX_PHONE_DIGITS = 15; 
    const MAX_PHONE_FULL_LEN = 30; 
    const MAX_EMAIL_LEN = 255; 
    const MAX_PASSWORD_LEN = 128;
	
	if (username.length > MAX_USERNAME_LEN) {
        showError(`Username cannot exceed ${MAX_USERNAME_LEN} characters.`);
        return;
    }

    if (firstname.length > MAX_NAME_LEN) {
        showError(`Firstname cannot exceed ${MAX_NAME_LEN} characters.`);
        return;
    }
    
    if (lastname.length > MAX_NAME_LEN) {
        showError(`Lastname cannot exceed ${MAX_NAME_LEN} characters.`);
        return;
    }
	
	if (!countryCode) {
	        showError("Please select a Country Code.");
	        return;
	    }
		
	if (phonenumber.length > MAX_PHONE_FULL_LEN) {
	        showError(`The phone number is too long. The total length (code + local) cannot exceed ${MAX_PHONE_FULL_LEN} characters.`);
	        return;
	    }    

    if (email.length > MAX_EMAIL_LEN) {
        showError(`Email cannot exceed ${MAX_EMAIL_LEN} characters.`);
        return;
    }
    
    if (password.length > MAX_PASSWORD_LEN) {
        showError(`Password cannot exceed ${MAX_PASSWORD_LEN} characters.`);
        return;
    }
	
    const generalNameRegex = /^[A-Za-z ]+$/;
	// 1. Firstname: Check minimum length (3) AND format
    if (firstname.length < 3 || !generalNameRegex.test(firstname)) {
        showError("Firstname must be at least 3 characters and can only contain letters and spaces.");
        return;
    }
    
    // 2. Lastname: Check format ONLY if provided (since it's optional)
    if (lastname && !generalNameRegex.test(lastname)) {
        showError("Lastname can only contain letters and spaces.");
        return;
    }

	// New Local Number Format and Length Check
	const localNumberRegex = /^[0-9]+$/; 
	    
	    if (!localNumberRegex.test(localNumber)) {
	        showError("The local phone number can only contain digits (0-9).");
	        return;
	    }
	    
	    if (localNumber.length < MIN_PHONE_DIGITS || localNumber.length > MAX_PHONE_DIGITS) {
	        showError(`The local phone number must be between ${MIN_PHONE_DIGITS} and ${MAX_PHONE_DIGITS} digits long.`);
	        return;
	    }

	    // Country Code Check
	    if (!countryCode.startsWith('+') || countryCode.length < 2) {
	        showError("Please select or enter a valid Country Code starting with '+'.");
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