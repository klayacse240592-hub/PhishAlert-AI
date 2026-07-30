const urlBox = document.getElementById("urlBox");
const scanBtn = document.getElementById("scanBtn");
const loader = document.getElementById("loader");
const resultCard = document.getElementById("resultCard");
const verdict = document.getElementById("verdict");
const confidence = document.getElementById("confidence");
const reason = document.getElementById("reason");

let currentURL = "";

chrome.tabs.query(
  { active: true, currentWindow: true },
  function (tabs) {
    currentURL = tabs[0].url;
    urlBox.innerText = currentURL;
  }
);

scanBtn.addEventListener("click", async () => {
  loader.classList.remove("hidden");
  resultCard.classList.add("hidden");

  try {
    const response = await fetch(
      "http://127.0.0.1:5000/api/extension/scan",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: currentURL,
        }),
      }
    );

    const data = await response.json();

    loader.classList.add("hidden");
    resultCard.classList.remove("hidden");

    verdict.className = "";

    let text = data.verdict || "UNKNOWN";
    let conf = data.confidence || 0;
    let desc = data.description || "";

    if (text.toLowerCase().includes("safe")) {
      verdict.classList.add("safe");
      reason.innerText =
        desc || "No suspicious phishing indicators detected.";
    } else if (text.toLowerCase().includes("suspicious")) {
      verdict.classList.add("warning");
      reason.innerText =
        desc || "Some suspicious patterns were detected.";
    } else {
      verdict.classList.add("danger");
      reason.innerText =
        desc || "High phishing probability detected.";
    }

    verdict.innerText = text;
    confidence.innerText = "Confidence : " + conf + "%";
  } catch (err) {
    loader.classList.add("hidden");
    resultCard.classList.remove("hidden");

    verdict.className = "danger";
    verdict.innerText = "Connection Error";
    confidence.innerText = "";
    reason.innerText = "Check backend and reload extension.";
  }
});