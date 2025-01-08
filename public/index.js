document.addEventListener("DOMContentLoaded", () => {
  // For Login Form
  const loginForm = document.querySelector("#loginForm");
  const emailInput = document.querySelector("input[name='email']");
  const passwordInput = document.querySelector("input[name='password']");
  const rememberCheckbox = document.getElementById("remember");

  // Load saved credentials if "Remember Me" is checked
  if (localStorage.getItem("remember") === "true") {
    rememberCheckbox.checked = true;
    emailInput.value = localStorage.getItem("email") || "";
    passwordInput.value = localStorage.getItem("password") || "";
  }

  // Save credentials when the form is submitted and "Remember Me" is checked
  loginForm.addEventListener("submit", (event) => {
    if (rememberCheckbox.checked) {
      localStorage.setItem("remember", "true");
      localStorage.setItem("email", emailInput.value);
      localStorage.setItem("password", passwordInput.value);
    } else {
      // Clear saved credentials if "Remember Me" is unchecked
      localStorage.removeItem("remember");
      localStorage.removeItem("email");
      localStorage.removeItem("password");
    }
  });

  // For "Agree to Terms" checkbox validation
  const loginAgreeCheckbox = document.getElementById("agree");
  if (loginAgreeCheckbox) {
    loginForm.addEventListener("submit", (event) => {
      if (!loginAgreeCheckbox.checked) {
        event.preventDefault();
        alert("You must agree to the terms of use and privacy policy to continue.");
      }
    });
  }

  // For Register Form
  const registerForm = document.querySelector("#registerForm");
  const registerAgreeCheckbox = document.getElementById("checksignup");

  if (registerForm && registerAgreeCheckbox) {
    registerForm.addEventListener("submit", (event) => {
      if (!registerAgreeCheckbox.checked) {
        event.preventDefault();
        alert("You must agree to the terms of use and privacy policy to continue.");
      }
    });
  }
});
