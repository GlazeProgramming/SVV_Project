const { Builder, By, until } = require('selenium-webdriver');

async function runTest(testName, testFn) {
    console.log(`\n🔹 Running Test: ${testName}`);
    let driver = await new Builder().forBrowser('chrome').build();
    try {
        await testFn(driver);
        console.log(`✔ Test Passed: ${testName}`);
    } catch (error) {
        console.error(`❌ Test Failed: ${testName}\n`, error.message);
    } finally {
        await driver.quit();
    }
}

// 1. Valid signup
async function validSignup(driver) {
    await driver.get('http://localhost:3000/signup.html');
    await driver.wait(until.elementLocated(By.id('email')), 5000);

    await driver.findElement(By.id('firstname')).sendKeys('John');
    await driver.findElement(By.id('lastname')).sendKeys('Doe');
    await driver.findElement(By.id('dob')).sendKeys('2000-01-01');
    await driver.findElement(By.id('phonenumber')).sendKeys('+60123456789');
    await driver.findElement(By.id('username')).sendKeys('johndoe123');
    await driver.findElement(By.id('email')).sendKeys('johndoe123@example.com');
    await driver.findElement(By.id('password')).sendKeys('Password123!');
    await driver.findElement(By.id('confirmPassword')).sendKeys('Password123!');
    await driver.findElement(By.css('.custom-checkbox')).click();
    await driver.findElement(By.css('button[type="submit"]')).click();
}

// 2. Missing required field
async function missingField(driver) {
    await driver.get('http://localhost:3000/signup.html');
    await driver.wait(until.elementLocated(By.id('email')), 5000);

    await driver.findElement(By.id('firstname')).sendKeys('John');
    // skip lastname
    await driver.findElement(By.id('dob')).sendKeys('2000-01-01');
    await driver.findElement(By.id('phonenumber')).sendKeys('+60123456789');
    await driver.findElement(By.id('username')).sendKeys('missinglastname');
    await driver.findElement(By.id('email')).sendKeys('missinglastname@example.com');
    await driver.findElement(By.id('password')).sendKeys('Password123!');
    await driver.findElement(By.id('confirmPassword')).sendKeys('Password123!');
    await driver.findElement(By.css('.custom-checkbox')).click();
    await driver.findElement(By.css('button[type="submit"]')).click();
}

// 3. Invalid email format
async function invalidEmail(driver) {
    await driver.get('http://localhost:3000/signup.html');
    await driver.wait(until.elementLocated(By.id('email')), 5000);

    await driver.findElement(By.id('firstname')).sendKeys('Jane');
    await driver.findElement(By.id('lastname')).sendKeys('Doe');
    await driver.findElement(By.id('dob')).sendKeys('2000-01-01');
    await driver.findElement(By.id('phonenumber')).sendKeys('+60123456789');
    await driver.findElement(By.id('username')).sendKeys('invalidemail');
    await driver.findElement(By.id('email')).sendKeys('invalidemail'); // invalid
    await driver.findElement(By.id('password')).sendKeys('Password123!');
    await driver.findElement(By.id('confirmPassword')).sendKeys('Password123!');
    await driver.findElement(By.css('.custom-checkbox')).click();
    await driver.findElement(By.css('button[type="submit"]')).click();
}

// 4. Passwords do not match
async function passwordMismatch(driver) {
    await driver.get('http://localhost:3000/signup.html');
    await driver.wait(until.elementLocated(By.id('email')), 5000);

    await driver.findElement(By.id('firstname')).sendKeys('Alice');
    await driver.findElement(By.id('lastname')).sendKeys('Smith');
    await driver.findElement(By.id('dob')).sendKeys('2000-01-01');
    await driver.findElement(By.id('phonenumber')).sendKeys('+60123456789');
    await driver.findElement(By.id('username')).sendKeys('passmismatch');
    await driver.findElement(By.id('email')).sendKeys('passmismatch@example.com');
    await driver.findElement(By.id('password')).sendKeys('Password123!');
    await driver.findElement(By.id('confirmPassword')).sendKeys('Password321!'); // mismatch
    await driver.findElement(By.css('.custom-checkbox')).click();
    await driver.findElement(By.css('button[type="submit"]')).click();
}

// 5. Terms not accepted
async function termsNotAccepted(driver) {
    await driver.get('http://localhost:3000/signup.html');
    await driver.wait(until.elementLocated(By.id('email')), 5000);

    await driver.findElement(By.id('firstname')).sendKeys('Bob');
    await driver.findElement(By.id('lastname')).sendKeys('Brown');
    await driver.findElement(By.id('dob')).sendKeys('2000-01-01');
    await driver.findElement(By.id('phonenumber')).sendKeys('+60123456789');
    await driver.findElement(By.id('username')).sendKeys('noterms');
    await driver.findElement(By.id('email')).sendKeys('noterms@example.com');
    await driver.findElement(By.id('password')).sendKeys('Password123!');
    await driver.findElement(By.id('confirmPassword')).sendKeys('Password123!');
    // do NOT click terms checkbox
    await driver.findElement(By.css('button[type="submit"]')).click();
}

// Run all tests
(async function runAll() {
    await runTest("Valid Signup", validSignup);
    await runTest("Missing Field", missingField);
    await runTest("Invalid Email", invalidEmail);
    await runTest("Password Mismatch", passwordMismatch);
    await runTest("Terms Not Accepted", termsNotAccepted);
})();
