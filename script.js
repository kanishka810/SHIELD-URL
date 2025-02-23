document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById("url-input");
    const checkBtn = document.getElementById("check-btn");
    const reportBtn = document.getElementById("report-btn");
    const resultElement = document.getElementById("result");
    const scoreElement = document.getElementById("securityScore");
    const loader = document.getElementById("loader");

    checkBtn.addEventListener("click", async () => {
        const url = urlInput.value.trim();

        if (!url) {
            displayMessage("Please enter a URL!", "red");
            return;
        }

        showLoader();
        clearResults();

        try {
            const response = await fetch('http://127.0.0.1:8000/check_url/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            if (!response.ok) {
                try {
                    const errorText = await response.text();
                    throw new Error(`HTTP error! status: ${response.status}, details: ${errorText}`);
                } catch (parseError) {
                    throw new Error(`HTTP error! status: ${response.status}, details: Could not parse error response`);
                }
            }

            const data = await response.json();
            hideLoader();
            displayResult(data);

        } catch (error) {
            hideLoader();
            console.error("Error checking URL:", error);
            displayMessage(error.message || "An error occurred checking the URL.", "red"); // Display error message or generic message
        }
    });

    reportBtn.addEventListener("click", async () => {
        const url = urlInput.value.trim();

        if (!url) {
            displayMessage("Please enter a URL to report!", "red");
            return;
        }

        showLoader();
        clearResults();

        try {
            const response = await fetch('http://127.0.0.1:8000/add_blacklist/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            if (!response.ok) {
                try {
                    const errorText = await response.text();
                    throw new Error(`HTTP error! status: ${response.status}, details: ${errorText}`);
                } catch (parseError) {
                    throw new Error(`HTTP error! status: ${response.status}, details: Could not parse error response`);
                }
            }

            const data = await response.json();
            hideLoader();
            displayMessage(data.message, "green");

        } catch (error) {
            hideLoader();
            console.error("Error reporting URL:", error);
            displayMessage(error.message || "An error occurred reporting the URL.", "red");  // Display error message or generic message
        }
    });


    function showLoader() {
        loader.style.display = "block";
    }

    function hideLoader() {
        loader.style.display = "none";
    }

    function displayMessage(message, color) {
        resultElement.textContent = message;
        resultElement.style.color = color;
    }

    function clearResults() {
        resultElement.textContent = "";
        scoreElement.textContent = "";
    }

    function displayResult(data) {
        resultElement.textContent = data.reason;

        let score = "Unknown";
        let color = "black";

        switch (data.status) {
            case "safe":
                score = "100";
                color = "green";
                break;
            case "suspicious":
                score = "50";
                color = "orange";
                break;
            case "phishing":
                score = "0";
                color = "red";
                break;
        }

        scoreElement.textContent = `Security Score: ${score}`;
        resultElement.style.color = color;
    }
});