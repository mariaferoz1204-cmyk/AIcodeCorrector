function getSuggestions() {
  const code = document.getElementById("codeInput").value.trim();
  const language = document.getElementById("language").value;
  const outputBox = document.getElementById("suggestionsBox");
  const errorText = document.getElementById("errorText");

  outputBox.style.display = "block";

  if (code === "") {
    errorText.innerText = "⚠️ Please paste some code before clicking Get Suggestions.";
    return;
  }

  errorText.innerText = "⏳ Analyzing code...";

  fetch("http://127.0.0.1:5000/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      code: code,
      language: language
    })
  })
  .then(response => response.json())
  .then(data => {
    if (data.status === "error") {
      errorText.innerText =
        `❌ ${data.language} Error\n\nLine ${data.line}: ${data.message}\n\nExplanation:\n${data.explanation}`;
    } else {
      errorText.innerText =
        "✅ No syntax errors detected.\n\nSuggestion:\n" + data.explanation;
    }
  })
  .catch(() => {
    errorText.innerText = "❌ Backend connection failed.";
  });
}
