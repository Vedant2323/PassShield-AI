// Main JavaScript for Password Strength Evaluator

document.addEventListener("DOMContentLoaded", function () {
  // DOM elements
  const passwordForm = document.getElementById("password-form");
  const passwordInput = document.getElementById("password");
  const togglePasswordBtn = document.getElementById("toggle-password");
  const evaluateBtn = document.getElementById("evaluate-btn");
  const generateBtn = document.getElementById("generate-btn");
  const resultsContainer = document.getElementById("results-container");
  const securitySlider = document.getElementById("security-slider");
  const securityLevelBadge = document.getElementById("security-level-badge");
  const aiTransformMessage = document.getElementById("ai-transform-message");
  const barclaysModeToggle = document.getElementById("barclays-mode-toggle");

  // Security levels
  const securityLevels = [
    { label: "Very Low (Hours)", color: "#dc3545" },
    { label: "Low (Days)", color: "#fd7e14" },
    { label: "Medium (Months)", color: "#ffc107" },
    { label: "High (Years)", color: "#20c997" },
    { label: "Very High (Centuries)", color: "#198754" },
  ];

  // Barclays policies (mock)
  const barclaysPolicies = {
    min_entropy: 70,
    min_length: 12,
    banned_substrings: ["barclays", "password", "bank", "123"],
    allowed_special_chars: ["!", "@", "#", "$", "%", "&", "*"],
  };

  // Composition chart
  let compositionChart = null;

  // Toggle password visibility
  togglePasswordBtn.addEventListener("click", function () {
    const type =
      passwordInput.getAttribute("type") === "password" ? "text" : "password";
    passwordInput.setAttribute("type", type);

    // Toggle icon
    const icon = togglePasswordBtn.querySelector("i");
    if (type === "password") {
      icon.classList.remove("fa-eye-slash");
      icon.classList.add("fa-eye");
    } else {
      icon.classList.remove("fa-eye");
      icon.classList.add("fa-eye-slash");
    }
  });

  // Handle security slider changes
  securitySlider.addEventListener("input", function () {
    const level = parseInt(this.value) - 1;
    securityLevelBadge.textContent = securityLevels[level].label;
    securityLevelBadge.style.backgroundColor = securityLevels[level].color;

    // Update the transform message
    if (passwordInput.value.trim() !== "") {
      aiTransformMessage.textContent =
        "Moving the slider will regenerate password recommendations";
    }
  });

  // Handle generate button click
  generateBtn.addEventListener("click", function () {
    const securityLevel = parseInt(securitySlider.value);
    const isBarclaysMode = barclaysModeToggle.checked;

    generateStrongPassword(securityLevel, isBarclaysMode).then((password) => {
      passwordInput.value = password;
      updatePasswordCharts(password);
      passwordForm.dispatchEvent(new Event("submit"));
    });
  });

  // Handle Barclays mode toggle
  barclaysModeToggle.addEventListener("change", function () {
    const password = passwordInput.value.trim();

    if (
      password.trim() !== "" &&
      resultsContainer.classList.contains("d-none") === false
    ) {
      // Show loading state
      const strengthMeter = document.querySelector(".strength-meter");
      const timeElements = document.querySelectorAll(
        "#time-online-throttled, #time-online-unthrottled, #time-offline-slow, #time-offline-fast"
      );

      timeElements.forEach((el) => {
        el.innerHTML =
          '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
      });

      // Re-evaluate the password with Barclays mode
      passwordForm.dispatchEvent(new Event("submit"));
    }

    // Show info modal on first toggle
    if (this.checked && !hasShownBarcalysInfo) {
      const modal = new bootstrap.Modal(
        document.getElementById("barclaysInfoModal")
      );
      modal.show();
      hasShownBarcalysInfo = true;
    }

    // Update UI elements for Barclays Mode
    const strengthMeter = document.querySelector(".strength-meter");
    if (this.checked) {
      strengthMeter.classList.add("barclays-mode");
      passwordInput.classList.add("barclays-mode");
    } else {
      strengthMeter.classList.remove("barclays-mode");
      passwordInput.classList.remove("barclays-mode");
    }
  });

  // Handle form submission
  passwordForm.addEventListener("submit", function (e) {
    e.preventDefault();

    const password = passwordInput.value.trim();

    if (password === "") {
      alert("Please enter a password to evaluate");
      return;
    }

    // Show loading state
    evaluateBtn.innerHTML =
      '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Evaluating...';
    evaluateBtn.disabled = true;

    // Check if Barclays mode is enabled
    const barclaysMode = barclaysModeToggle.checked;

    // Evaluate the password
    evaluatePassword(password, barclaysMode)
      .then((response) => {
        // Check for breaches
        checkPasswordBreach(password).then((breachData) => {
          // Update the UI with the breach data
          updateBreachUI(breachData);

          // Update the UI with the results
          updateResultsUI(response);

          // Check Barclays policy if enabled
          if (barclaysMode) {
            const policyResults = checkBarclaysPolicy(
              password,
              response.graph_data.entropy_data
            );
            updateBarclaysPolicyUI(policyResults);
          } else {
            // Hide Barclays policy alert if disabled
            document
              .getElementById("barclays-policy-alert")
              .classList.add("d-none");
          }

          // Show the attack simulation
          simulateAttacks(password, response.graph_data.entropy_data);

          // Detect dictionary words in multiple languages
          detectMultiLanguage(password);

          // Show the results container
          resultsContainer.classList.remove("d-none");
          resultsContainer.classList.add("fade-in");

          // Scroll to results
          resultsContainer.scrollIntoView({ behavior: "smooth" });
        });
      })
      .catch((error) => {
        console.error("Error evaluating password:", error);
        alert(
          "An error occurred while evaluating the password. Please try again."
        );
      })
      .finally(() => {
        // Reset button state
        evaluateBtn.innerHTML = "Evaluate Password";
        evaluateBtn.disabled = false;
      });
  });

  // Function to evaluate password
  async function evaluatePassword(password, barclaysMode) {
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          password,
          barclays_mode: barclaysMode,
          security_level: parseInt(securitySlider.value),
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to evaluate password");
      }

      const result = await response.json();
      console.log(result);
      // Calculate more accurate crack times with Barclays mode consideration
      const entropyData = result.entropy;

      const crackTimes = calculateCrackTimes(
        password,
        entropyData,
        barclaysMode
      );
      result.graph_data.crack_time_data.crack_times = crackTimes;

      // Generate Barclays-compliant alternative passwords if needed
      if (barclaysMode) {
        // Replace the alternative passwords with Barclays-compliant ones
        result.suggestions.alternative_passwords =
          await generateBarclaysCompliantAlternatives();
      }

      return result;
    } catch (error) {
      console.error("API Error:", error);
      throw error;
    }
  }

  // Calculate accurate crack times based on real-world attack speeds
  function calculateCrackTimes(password, entropyData, isBarclaysMode = false) {
    const charsetSize = entropyData.charset_size;
    const passwordLength = entropyData.password_length;
    const totalCombinations = Math.pow(charsetSize, passwordLength);

    // Attack speeds (attempts per second)
    const speeds = {
      online_throttled: 100, // 100 attempts per second (rate-limited)
      online_unthrottled: 10000, // 10K attempts per second
      offline_slow_hash: 250000000, // 250M/s (bcrypt/pbkdf2)
      offline_fast_hash: 100000000000, // 100B/s (MD5/SHA1)
    };

    // Barclays mode adjusts speeds to account for additional security measures
    if (isBarclaysMode) {
      // Barclays applies additional rate limiting and security measures
      speeds.online_throttled = 50; // More strict rate limiting
      speeds.online_unthrottled = 5000; // Additional security layers
      speeds.offline_slow_hash = 100000000; // Stronger hashing algorithms
      speeds.offline_fast_hash = 50000000000; // More complex salting
    }

    // Effectiveness multipliers based on password composition
    let effectivenessMultiplier = 1;

    // Check for common patterns that make cracking easier
    if (/^[a-z]+$/.test(password)) {
      effectivenessMultiplier *= 0.3; // Only lowercase
    } else if (/^[A-Z]+$/.test(password)) {
      effectivenessMultiplier *= 0.3; // Only uppercase
    } else if (/^\d+$/.test(password)) {
      effectivenessMultiplier *= 0.2; // Only numbers
    }

    // Check for dictionary words
    const commonWords = [
      "password",
      "admin",
      "user",
      "login",
      "123456",
      "qwerty",
    ];
    if (commonWords.some((word) => password.toLowerCase().includes(word))) {
      effectivenessMultiplier *= 0.1;
    }

    // Check for keyboard patterns
    const keyboardPatterns = ["qwerty", "asdfgh", "123456"];
    if (
      keyboardPatterns.some((pattern) =>
        password.toLowerCase().includes(pattern)
      )
    ) {
      effectivenessMultiplier *= 0.15;
    }

    // In Barclays mode, additional password complexity requirements are enforced
    if (isBarclaysMode) {
      // Password length penalty is more severe
      if (password.length < 12) {
        effectivenessMultiplier *= 0.5; // Significantly easier to crack short passwords
      }

      // Missing character types are penalized
      if (!/[A-Z]/.test(password)) effectivenessMultiplier *= 0.6; // No uppercase
      if (!/[a-z]/.test(password)) effectivenessMultiplier *= 0.6; // No lowercase
      if (!/\d/.test(password)) effectivenessMultiplier *= 0.7; // No digits
      if (!/[^a-zA-Z0-9]/.test(password)) effectivenessMultiplier *= 0.5; // No special chars

      // Check for Barclays-specific banned terms
      const barclaysTerms = ["barclays", "bank", "password", "123"];
      if (barclaysTerms.some((term) => password.toLowerCase().includes(term))) {
        effectivenessMultiplier *= 0.05; // Extremely easy to crack if contains banned terms
      }
    }

    // Calculate times with adjustments
    const times = {};
    for (const [type, speed] of Object.entries(speeds)) {
      // Base calculation
      let seconds = totalCombinations / speed;

      // Apply effectiveness multiplier
      seconds *= effectivenessMultiplier;

      // Additional adjustments based on attack type
      switch (type) {
        case "online_throttled":
          seconds *= 1.5; // Account for network latency
          if (isBarclaysMode) seconds *= 2.0; // Additional security measures
          break;
        case "online_unthrottled":
          seconds *= 1.2; // Account for server processing
          if (isBarclaysMode) seconds *= 1.8; // Additional security layers
          break;
        case "offline_slow_hash":
          // Adjust for hardware variations
          if (
            entropyData.composition &&
            entropyData.composition.special &&
            entropyData.composition.special.count > 0
          ) {
            seconds *= 1.3; // Special characters increase complexity
          }
          if (isBarclaysMode) seconds *= 1.5; // Stronger hashing in Barclays mode
          break;
        case "offline_fast_hash":
          // Account for GPU optimization
          if (password.length > 12) {
            seconds *= 1.4; // Longer passwords are harder to parallelize
          }
          if (isBarclaysMode) seconds *= 1.2; // More complex salting in Barclays mode
          break;
      }

      times[type] = formatTime(seconds);
    }

    return {
      online_throttled: times.online_throttled,
      online_unthrottled: times.online_unthrottled,
      offline_slow_hash: times.offline_slow_hash,
      offline_fast_hash: times.offline_fast_hash,
    };
  }

  // Enhanced time formatting function
  function formatTime(seconds) {
    if (seconds < 1) {
      return "instant";
    } else if (seconds < 60) {
      return `${Math.round(seconds)} seconds`;
    } else if (seconds < 3600) {
      const minutes = seconds / 60;
      return minutes < 10
        ? `${minutes.toFixed(1)} minutes`
        : `${Math.round(minutes)} minutes`;
    } else if (seconds < 86400) {
      const hours = seconds / 3600;
      return hours < 10
        ? `${hours.toFixed(1)} hours`
        : `${Math.round(hours)} hours`;
    } else if (seconds < 2592000) {
      const days = seconds / 86400;
      return days < 10 ? `${days.toFixed(1)} days` : `${Math.round(days)} days`;
    } else if (seconds < 31536000) {
      const months = seconds / 2592000;
      return months < 10
        ? `${months.toFixed(1)} months`
        : `${Math.round(months)} months`;
    } else if (seconds < 3153600000) {
      const years = seconds / 31536000;
      return years < 10
        ? `${years.toFixed(1)} years`
        : `${Math.round(years)} years`;
    } else if (seconds < 315360000000) {
      const centuries = seconds / 3153600000;
      return centuries < 10
        ? `${centuries.toFixed(1)} centuries`
        : `${Math.round(centuries)} centuries`;
    } else {
      return "infinite";
    }
  }

  // Function to check if password has been breached
  async function checkPasswordBreach(password) {
    try {
      // For demo purposes, we'll use a simulated breach check
      // In production, use the Have I Been Pwned API with k-anonymity

      // Create a SHA-1 hash of the password
      const hashHex = await sha1(password);

      // Common leaked passwords for demo
      const commonLeaked = [
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", // password
        "cbfdac6008f9cab4083784cbd1874f76618d2a97", // password123
        "b1b3773a05c0ed0176787a4f1574ff0075f7521e", // qwerty
        "5cec175b165e3d5e62c9e13ce848ef6feac81bff", // 123456
        "f7c3bc1d808e04732adf679965ccc34ca7ae3441", // admin
        "c12e01f2a13ff5587e1e9e4aedb8242d472143c8", // test123
        "7c222fb2927d828af22f592134e8932480637c0d", // 12345678
        "b9c950640e1b3740e98acb93e669c65766f6670dd1609ba91ff41052ba48c6f3", // welcome
        "0b9c2625dc21ef05f6ad4ddf47c5f203837aa32c", // letmein
        "5d41402abc4b2a76b9719d911017c592", // hello
      ];

      // Check if the password hash is in the list of common leaked passwords
      const isBreached = commonLeaked.some((leak) =>
        leak.includes(hashHex.slice(0, 10).toLowerCase())
      );

      return {
        breached: isBreached,
        count: isBreached ? Math.floor(Math.random() * 20) + 1 : 0, // Random number for demo
      };
    } catch (error) {
      console.error("Breach check error:", error);
      return { breached: false, count: 0 };
    }
  }

  // SHA-1 hash function
  async function sha1(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest("SHA-1", msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return hashHex;
  }

  // Update breach UI
  function updateBreachUI(breachData) {
    const breachAlert = document.getElementById("breach-alert");
    const breachMessage = document.getElementById("breach-message");

    if (breachData.breached) {
      breachAlert.classList.remove("d-none");
      breachMessage.textContent = `This password has been found in ${
        breachData.count
      } known data breach${
        breachData.count > 1 ? "es" : ""
      } and should not be used!`;
    } else {
      breachAlert.classList.add("d-none");
    }
  }

  // Check Barclays policy
  function checkBarclaysPolicy(password, entropyData) {
    const failures = [];

    // Check minimum entropy
    if (
      entropyData.charset_size ** entropyData.password_length <
      2 ** barclaysPolicies.min_entropy
    ) {
      failures.push("Entropy is too low (min: 70 bits)");
    }

    // Check minimum length
    if (password.length < barclaysPolicies.min_length) {
      failures.push(
        `Password must be at least ${barclaysPolicies.min_length} characters long`
      );
    }

    // Check banned substrings
    for (const substring of barclaysPolicies.banned_substrings) {
      if (password.toLowerCase().includes(substring)) {
        failures.push(`Password contains banned substring: "${substring}"`);
        break;
      }
    }

    // Check for special characters
    const hasSpecialChar = barclaysPolicies.allowed_special_chars.some((char) =>
      password.includes(char)
    );
    if (!hasSpecialChar) {
      failures.push(
        "Password must contain at least one special character (!@#$%&*)"
      );
    }

    return {
      compliant: failures.length === 0,
      failures: failures,
    };
  }

  // Update Barclays policy UI
  function updateBarclaysPolicyUI(policyResults) {
    const policyAlert = document.getElementById("barclays-policy-alert");
    const policyFailures = document.getElementById("policy-failures");

    if (!policyResults.compliant) {
      policyAlert.classList.remove("d-none");
      policyFailures.innerHTML = "";

      policyResults.failures.forEach((failure) => {
        const listItem = document.createElement("li");
        listItem.textContent = failure;
        policyFailures.appendChild(listItem);
      });
    } else {
      policyAlert.classList.add("d-none");
    }
  }

  // Simulate different attack types
  function simulateAttacks(password, entropyData) {
    // Dictionary attack
    const dictionaryProgress = document.getElementById("dictionary-progress");
    const dictionaryTime = document.getElementById("dictionary-attack-time");

    // Brute force attack
    const bruteforceProgress = document.getElementById("bruteforce-progress");
    const bruteforceTime = document.getElementById("bruteforce-attack-time");

    // Rainbow table attack
    const rainbowProgress = document.getElementById("rainbow-progress");
    const rainbowTime = document.getElementById("rainbow-attack-time");

    // Reset progress bars
    dictionaryProgress.style.width = "0%";
    bruteforceProgress.style.width = "0%";
    rainbowProgress.style.width = "0%";

    // Calculate password complexity
    const charsetSize = entropyData.charset_size;
    const passwordLength = entropyData.password_length;
    const totalCombinations = Math.pow(charsetSize, passwordLength);

    // Calculate attack speeds and success rates
    // Dictionary attack (1 million attempts per second)
    const dictionarySpeed = 1000000; // 1M attempts/sec
    let dictionaryEffectiveness = 0;
    if (passwordLength < 8) {
      dictionaryEffectiveness = 90; // Very effective on short passwords
    } else if (passwordLength < 10) {
      dictionaryEffectiveness = 70; // Effective on medium passwords
    } else if (passwordLength < 12) {
      dictionaryEffectiveness = 40; // Less effective on longer passwords
    } else {
      dictionaryEffectiveness = 15; // Very ineffective on long passwords
    }

    // Brute force attack (100 billion attempts per second)
    const bruteforceSpeed = 100000000000; // 100B attempts/sec
    const bruteforceEffectiveness = Math.min(
      100,
      100 * (12 / Math.max(12, passwordLength))
    );

    // Rainbow table attack (10 trillion lookups per second)
    const rainbowSpeed = 10000000000000; // 10T lookups/sec
    let rainbowEffectiveness = 0;
    if (
      entropyData.composition &&
      entropyData.composition.special &&
      entropyData.composition.special.count === 0
    ) {
      rainbowEffectiveness = 95 - passwordLength * 5; // Very effective on simple passwords
    } else {
      rainbowEffectiveness = 40 - passwordLength * 3; // Less effective on complex passwords
    }
    rainbowEffectiveness = Math.max(5, Math.min(95, rainbowEffectiveness));

    // Calculate actual attack times
    const dictionaryTimeSeconds =
      (totalCombinations / dictionarySpeed) * (dictionaryEffectiveness / 100);
    const bruteforceTimeSeconds =
      (totalCombinations / bruteforceSpeed) * (bruteforceEffectiveness / 100);
    const rainbowTimeSeconds =
      (totalCombinations / rainbowSpeed) * (rainbowEffectiveness / 100);

    // Calculate progress bar widths based on how quickly the password can be cracked
    // Shorter times = more progress = less secure
    // We'll use a logarithmic scale to better visualize the differences
    const calculateProgressWidth = (timeSeconds) => {
      if (timeSeconds <= 0) return 100; // Instant crack = 100% progress
      if (timeSeconds >= 31536000000) return 1; // >1000 years = 1% progress (still visible)

      // Log scale to handle the wide range of possible times
      // 1 second = ~90%, 1 minute = ~70%, 1 hour = ~50%, 1 day = ~30%, 1 month = ~20%, 1 year = ~10%
      const logValue = Math.log10(timeSeconds);
      const maxLog = Math.log10(31536000000); // ~log10(1000 years in seconds)
      const progressPercent = 100 - (logValue / maxLog) * 99;

      return Math.max(1, Math.min(100, Math.round(progressPercent)));
    };

    // Format and display attack times
    const dictionaryTimeFormatted = formatTime(dictionaryTimeSeconds);
    const bruteforceTimeFormatted = formatTime(bruteforceTimeSeconds);
    const rainbowTimeFormatted = formatTime(rainbowTimeSeconds);

    // Calculate progress widths (inverse of time - shorter time = more progress = less secure)
    const dictionaryProgressWidth = calculateProgressWidth(
      dictionaryTimeSeconds
    );
    const bruteforceProgressWidth = calculateProgressWidth(
      bruteforceTimeSeconds
    );
    const rainbowProgressWidth = calculateProgressWidth(rainbowTimeSeconds);

    // Animate progress bars with realistic timing
    setTimeout(() => {
      // Update progress bars
      dictionaryProgress.style.width = `${dictionaryProgressWidth}%`;
      bruteforceProgress.style.width = `${bruteforceProgressWidth}%`;
      rainbowProgress.style.width = `${rainbowProgressWidth}%`;

      // Update time estimates
      document.getElementById("dictionary-attack-time").textContent =
        dictionaryTimeFormatted;
      document.getElementById("bruteforce-attack-time").textContent =
        bruteforceTimeFormatted;
      document.getElementById("rainbow-attack-time").textContent =
        rainbowTimeFormatted;
    }, 500);
  }

  // Detect dictionary words in multiple languages
  function detectMultiLanguage(password) {
    const languageContainer = document.getElementById(
      "language-detection-container"
    );
    const languageAlert = document.getElementById("language-detection-alert");

    // For demo purposes, we'll simulate language detection
    // In production, use proper NLP libraries or APIs

    // Common words in different languages
    const languageWords = {
      english: ["password", "welcome", "hello", "admin", "login", "user"],
      spanish: ["contraseña", "bienvenido", "hola", "administrador"],
      hindi: ["namaste", "swagat", "khushi"],
      french: ["bonjour", "bienvenue", "merci", "mot"],
      german: ["willkommen", "passwort", "hallo", "danke"],
    };

    const lowerPassword = password.toLowerCase();
    const detectedWords = [];

    for (const [language, words] of Object.entries(languageWords)) {
      for (const word of words) {
        if (lowerPassword.includes(word)) {
          detectedWords.push({ language, word });
        }
      }
    }

    if (detectedWords.length > 0) {
      languageContainer.classList.remove("d-none");

      let alertHtml = `<strong>Warning:</strong> We detected the following dictionary words in your password:`;
      alertHtml += `<ul class="mb-0 mt-2">`;

      for (const detection of detectedWords) {
        alertHtml += `<li>"${detection.word}" (${capitalizeFirst(
          detection.language
        )})</li>`;
      }

      alertHtml += `</ul>`;
      alertHtml += `<p class="mt-2 mb-0">Using dictionary words in any language makes passwords easier to crack.</p>`;

      languageAlert.innerHTML = alertHtml;
    } else {
      languageContainer.classList.add("d-none");
    }
  }

  // Generate strong password based on security level
  async function generateStrongPassword(securityLevel, isBarclaysMode = false) {
    // Adjust parameters based on security level (1-5)
    let length = 8 + securityLevel * 2; // 10-18 characters
    let useUppercase = securityLevel >= 1;
    let useDigits = securityLevel >= 1;
    let useSpecial = securityLevel >= 2;
    let specialCount = Math.max(1, Math.floor(securityLevel / 2));

    // In Barclays mode, enforce stricter requirements
    if (isBarclaysMode) {
      length = Math.max(12, length); // Enforce minimum 12 characters
      useUppercase = true; // Require uppercase
      useDigits = true; // Require digits
      useSpecial = true; // Require special chars
      specialCount = Math.max(2, specialCount); // At least 2 special chars
    }

    // Character sets
    const lowercase = "abcdefghijklmnopqrstuvwxyz";
    const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const digits = "0123456789";
    const special = isBarclaysMode ? "!@#$%&*" : "!@#$%^&*()-_=+[]{}|;:,.<>?";

    // Create character pool
    let charPool = lowercase;
    if (useUppercase) charPool += uppercase;
    if (useDigits) charPool += digits;
    if (useSpecial) charPool += special;

    // Generate base password
    let password = "";
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charPool.length);
      password += charPool[randomIndex];
    }

    // Ensure we have required character types
    let result = password;

    if (useUppercase && !/[A-Z]/.test(result)) {
      const pos = Math.floor(Math.random() * result.length);
      const uppercaseChar =
        uppercase[Math.floor(Math.random() * uppercase.length)];
      result =
        result.substring(0, pos) + uppercaseChar + result.substring(pos + 1);
    }

    if (useDigits && !/[0-9]/.test(result)) {
      const pos = Math.floor(Math.random() * result.length);
      const digitChar = digits[Math.floor(Math.random() * digits.length)];
      result = result.substring(0, pos) + digitChar + result.substring(pos + 1);
    }

    if (useSpecial && !/[^a-zA-Z0-9]/.test(result)) {
      for (let i = 0; i < specialCount; i++) {
        const pos = Math.floor(Math.random() * result.length);
        const specialChar = special[Math.floor(Math.random() * special.length)];
        result =
          result.substring(0, pos) + specialChar + result.substring(pos + 1);
      }
    }

    // In Barclays mode, validate that the password doesn't contain banned terms
    if (isBarclaysMode) {
      const barclaysTerms = ["barclays", "bank", "password", "123"];
      if (barclaysTerms.some((term) => result.toLowerCase().includes(term))) {
        // Regenerate if it contains banned terms
        return generateStrongPassword(securityLevel, isBarclaysMode);
      }
    }

    return result;
  }

  // Function to update the UI with results
  function updateResultsUI(response) {
    console.log("updateResultsUI called with:", response);

    // Check if Barclays mode is enabled
    const barclaysMode = barclaysModeToggle.checked;

    // Update strength meter
    updateStrengthMeter(response.graph_data.strength_meter);

    // Update time to crack
    updateCrackTimeDisplay(response.graph_data.crack_time_data.crack_times);

    // Update composition - handle both possible data structures
    let composition;
    if (
      response.graph_data.entropy_data &&
      response.graph_data.entropy_data.composition
    ) {
      composition = response.graph_data.entropy_data.composition;
    } else if (response.entropy && response.entropy.composition) {
      composition = response.entropy.composition;
    } else {
      console.error("Composition data not found in response:", response);
      return;
    }

    updateCompositionDisplay(composition);

    // Update AI suggestions with Barclays mode flag
    console.log("Calling updateSuggestions with:", response.suggestions);
    updateSuggestions(response.suggestions, barclaysMode);
  }

  // Update strength meter display
  function updateStrengthMeter(strengthMeter) {
    const strengthBar = document.getElementById("strength-meter-bar");
    const strengthCategory = document.getElementById("strength-category");
    const strengthScore = document.getElementById("strength-score");

    // Update progress bar
    strengthBar.style.width = `${strengthMeter.score}%`;
    strengthBar.style.backgroundColor = strengthMeter.color;

    // Update category text
    strengthCategory.textContent = capitalizeFirst(strengthMeter.category);
    strengthCategory.className = ""; // Remove any existing classes
    strengthCategory.classList.add(strengthMeter.category.replace(" ", "-"));

    // Update score text
    strengthScore.textContent = `Score: ${strengthMeter.score}/100`;
  }

  // Update crack time display
  function updateCrackTimeDisplay(crackTimes) {
    document.getElementById("time-online-throttled").textContent =
      crackTimes.online_throttled;
    document.getElementById("time-online-unthrottled").textContent =
      crackTimes.online_unthrottled;
    document.getElementById("time-offline-slow").textContent =
      crackTimes.offline_slow_hash;
    document.getElementById("time-offline-fast").textContent =
      crackTimes.offline_fast_hash;
  }

  // Update composition display
  function updateCompositionDisplay(composition) {
    // Update composition details
    const compositionDetails = document.getElementById("composition-details");
    compositionDetails.innerHTML = "";

    const categories = [
      { key: "lowercase", label: "Lowercase Letters", color: "#4e73df" },
      { key: "uppercase", label: "Uppercase Letters", color: "#1cc88a" },
      { key: "digits", label: "Digits", color: "#f6c23e" },
      { key: "special", label: "Special Characters", color: "#e74a3b" },
    ];

    categories.forEach((category) => {
      const item = document.createElement("li");
      item.className =
        "list-group-item d-flex justify-content-between align-items-center";
      item.innerHTML = `
                <span>
                    <span class="badge rounded-pill" style="background-color: ${
                      category.color
                    };">&nbsp;</span>
                    ${category.label}
                </span>
                <span>${composition[category.key].count} (${composition[
        category.key
      ].percentage.toFixed(1)}%)</span>
            `;
      compositionDetails.appendChild(item);
    });

    // Update patterns list
    const patternsContainer = document.getElementById("patterns-container");
    const patternsList = document.getElementById("patterns-list");
    patternsList.innerHTML = "";

    if (composition.patterns && composition.patterns.length > 0) {
      patternsContainer.classList.remove("d-none");

      composition.patterns.forEach((pattern) => {
        const item = document.createElement("li");
        item.className = "list-group-item text-danger";
        item.innerHTML = `<i class="fas fa-exclamation-triangle me-2"></i> ${pattern}`;
        patternsList.appendChild(item);
      });
    } else {
      patternsContainer.classList.add("d-none");
    }

    // Update composition chart
    updateCompositionChart([
      composition.lowercase.percentage,
      composition.uppercase.percentage,
      composition.digits.percentage,
      composition.special.percentage,
    ]);
  }

  // Update composition chart
  function updateCompositionChart(data) {
    const ctx = document.getElementById("composition-chart").getContext("2d");

    // Destroy existing chart if it exists
    if (compositionChart) {
      compositionChart.destroy();
    }

    // Create new chart
    compositionChart = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Lowercase", "Uppercase", "Digits", "Special"],
        datasets: [
          {
            data: data,
            backgroundColor: ["#4e73df", "#1cc88a", "#f6c23e", "#e74a3b"],
            hoverBackgroundColor: ["#2e59d9", "#17a673", "#f4b619", "#e02d1b"],
            borderWidth: 1,
          },
        ],
      },
      options: {
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false,
          },
        },
        cutout: "70%",
      },
    });
  }

  // Update suggestions display
  function updateSuggestions(suggestions, isBarclaysMode = false) {
    console.log("updateSuggestions called with:", suggestions);

    const aiSuggestions = document.getElementById("ai-suggestions");
    const alternativesList = document.getElementById("alternatives-list");

    console.log("aiSuggestions element:", aiSuggestions);
    console.log("alternativesList element:", alternativesList);

    // Clear previous content
    aiSuggestions.innerHTML = "";
    alternativesList.innerHTML = "";

    // Display AI suggestion if available
    if (suggestions.ai_suggestion) {
      console.log("Using AI suggestion");
      aiSuggestions.innerHTML = `<div class="alert alert-info">${formatAISuggestion(
        suggestions.ai_suggestion
      )}</div>`;
    } else if (suggestions.weaknesses && suggestions.improvements) {
      console.log("Using rule-based suggestions");
      // Display rule-based suggestions
      let html =
        '<div class="alert alert-warning"><h6>Detected Weaknesses:</h6><ul>';

      suggestions.weaknesses.forEach((weakness) => {
        html += `<li>${weakness}</li>`;
      });

      html += '</ul><h6 class="mt-3">Recommended Improvements:</h6><ul>';

      suggestions.improvements.forEach((improvement) => {
        html += `<li>${improvement}</li>`;
      });

      html += "</ul></div>";
      aiSuggestions.innerHTML = html;
    } else {
      console.log("No suggestions found in:", suggestions);
    }

    // Display alternative passwords
    const alternatives = suggestions.alternative_passwords || [];
    console.log("Alternative passwords:", alternatives);

    if (alternatives.length > 0) {
      // Add badge to show if these are Barclays-compliant alternatives
      const badgeHtml = isBarclaysMode
        ? `<div class="mb-3 text-center"><span class="badge bg-primary">Barclays-Compliant Alternatives</span></div>`
        : "";
      alternativesList.innerHTML = badgeHtml;

      alternatives.forEach((password) => {
        const item = document.createElement("li");
        item.className = "list-group-item";
        item.innerHTML = `
                    <span class="alternative-password">${password}</span>
                    <button class="copy-button" data-password="${password}">
                        <i class="fas fa-copy"></i> Copy
                    </button>
                `;
        alternativesList.appendChild(item);
      });

      // Add copy functionality
      document.querySelectorAll(".copy-button").forEach((button) => {
        button.addEventListener("click", function () {
          const password = this.getAttribute("data-password");
          copyToClipboard(password);

          // Show tooltip
          const originalText = this.innerHTML;
          this.innerHTML = '<i class="fas fa-check"></i> Copied!';

          setTimeout(() => {
            this.innerHTML = originalText;
          }, 2000);
        });
      });
    }
  }

  // Format AI suggestion text
  function formatAISuggestion(text) {
    // Replace line breaks with HTML breaks
    text = text.replace(/\n/g, "<br>");

    // Highlight key phrases
    text = text.replace(
      /('strong[a-z ]*')/gi,
      '<strong class="text-success">$1</strong>'
    );
    text = text.replace(
      /('weak[a-z ]*')/gi,
      '<strong class="text-danger">$1</strong>'
    );

    return text;
  }

  // Helper function to capitalize first letter
  function capitalizeFirst(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  // Helper function to copy text to clipboard
  function copyToClipboard(text) {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
  }

  // Initialize tooltips
  var tooltipTriggerList = [].slice.call(
    document.querySelectorAll('[data-bs-toggle="tooltip"]')
  );
  var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl);
  });

  // Initialize Barclays Mode toggle with tooltip
  barclaysModeToggle.setAttribute("data-bs-toggle", "tooltip");
  barclaysModeToggle.setAttribute("data-bs-placement", "right");
  barclaysModeToggle.setAttribute(
    "title",
    "Enable enterprise-grade password security"
  );

  // Show info modal on first toggle
  let hasShownBarcalysInfo = false;

  // Generate Barclays-compliant alternative passwords
  async function generateBarclaysCompliantAlternatives() {
    const alternatives = [];
    const securityLevel = parseInt(securitySlider.value);

    // Generate 3 alternative passwords
    for (let i = 0; i < 3; i++) {
      // Use at least security level 4 for Barclays mode to ensure strong passwords
      const level = Math.max(4, securityLevel);
      alternatives.push(await generateStrongPassword(level, true));
    }

    return alternatives;
  }

  // Update chart displays for generated password
  function updatePasswordCharts(password) {
    // Count character types
    const uppercase_count = (password.match(/[A-Z]/g) || []).length;
    const lowercase_count = (password.match(/[a-z]/g) || []).length;
    const number_count = (password.match(/[0-9]/g) || []).length;
    const special_count = (password.match(/[^a-zA-Z0-9]/g) || []).length;

    // Update character distribution chart
    const charDistCtx = document
      .getElementById("charDistChart")
      .getContext("2d");
    new Chart(charDistCtx, {
      type: "bar",
      data: {
        labels: ["Uppercase", "Lowercase", "Numbers", "Special"],
        datasets: [
          {
            data: [
              uppercase_count,
              lowercase_count,
              number_count,
              special_count,
            ],
            backgroundColor: [
              "rgba(99, 102, 241, 0.8)", // Indigo for uppercase
              "rgba(139, 92, 246, 0.8)", // Purple for lowercase
              "rgba(59, 130, 246, 0.8)", // Blue for numbers
              "rgba(236, 72, 153, 0.8)", // Pink for special
            ],
            borderColor: [
              "rgba(99, 102, 241, 1)",
              "rgba(139, 92, 246, 1)",
              "rgba(59, 130, 246, 1)",
              "rgba(236, 72, 153, 1)",
            ],
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              color: "#f8fafc",
              font: {
                family: "'Inter', sans-serif",
              },
            },
            grid: {
              color: "rgba(255, 255, 255, 0.1)",
            },
          },
          x: {
            ticks: {
              color: "#f8fafc",
              font: {
                family: "'Inter', sans-serif",
              },
            },
            grid: {
              color: "rgba(255, 255, 255, 0.1)",
            },
          },
        },
        plugins: {
          legend: {
            display: false,
          },
        },
      },
    });

    // Detect patterns for chart (mock implementation)
    const sequential_patterns = [];
    const repeated_patterns = [];
    const common_patterns = [];

    // Sequential patterns (123, abc)
    if (/123|234|345|456|567|678|789|abc|bcd|cde|def|efg/i.test(password)) {
      sequential_patterns.push("sequential");
    }

    // Repeated patterns (aa, 11)
    if (/(.)\1{1,}/i.test(password)) {
      repeated_patterns.push("repeated");
    }

    // Common patterns (qwerty, password)
    const commonWords = ["password", "admin", "login", "qwerty", "welcome"];
    if (commonWords.some((word) => password.toLowerCase().includes(word))) {
      common_patterns.push("common");
    }

    // Update pattern detection chart
    const patternCtx = document.getElementById("patternChart").getContext("2d");
    new Chart(patternCtx, {
      type: "doughnut",
      data: {
        labels: ["Sequential", "Repeated", "Common", "Safe"],
        datasets: [
          {
            data: [
              sequential_patterns.length,
              repeated_patterns.length,
              common_patterns.length,
              Math.max(
                0,
                4 -
                  (sequential_patterns.length +
                    repeated_patterns.length +
                    common_patterns.length)
              ),
            ],
            backgroundColor: [
              "rgba(239, 68, 68, 0.8)", // Red for sequential
              "rgba(245, 158, 11, 0.8)", // Yellow for repeated
              "rgba(59, 130, 246, 0.8)", // Blue for common
              "rgba(34, 197, 94, 0.8)", // Green for safe
            ],
            borderColor: [
              "rgba(239, 68, 68, 1)",
              "rgba(245, 158, 11, 1)",
              "rgba(59, 130, 246, 1)",
              "rgba(34, 197, 94, 1)",
            ],
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: "#f8fafc",
              font: {
                family: "'Inter', sans-serif",
              },
            },
          },
        },
      },
    });
  }
});
