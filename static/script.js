// Wait for the DOM content to be fully loaded
document.addEventListener("DOMContentLoaded", function () {
  // JavaScript code for handling user interactions (e.g., submitting questions)

  // Retrieve question from input field
  function getQuestionAndApiKey() {
    return {
      question: document.getElementById("question-input").value.trim(),
      apiKey: document.getElementById("api-key").value.trim(),
    };
  }

  // Function to handle sending the question
  function sendQuestion() {
    var { question, apiKey } = getQuestionAndApiKey();

    // Check if the question and API key are not empty
    if (question !== "" && apiKey !== "") {
      // Construct the request body
      var requestBody = JSON.stringify({ question: question, api_key: apiKey });

      // Append the question to the response area (optional)
      var responseArea = document.getElementById("response-area");
      responseArea.innerHTML += "<p><strong>You:</strong> " + question + "</p>";

      // Send an HTTP POST request to the /ask endpoint
      fetch("/ask", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: requestBody,
      })
        .then((response) => {
          if (response.ok) {
            j = response.json();
            console.log(j);
            return j;
          } else {
            // Correctly logging the response
            console.error(response.statusText);
            return response.text().then((text) => {
              throw new Error(text);
            });
          }
        })
        .then((data) => {
          // Process the response data and add it to the response area
          console.log(data);
          // r = data.response;
          r = data;
          // r = "here's some more static text";
          // console.log(r);
          let html = marked.parse(
            "<p><strong>Response:</strong> " + data + "</p>"
          );
          responseArea.innerHTML += html;
        })
        .catch((error) => {
          // Handle errors
          responseArea.innerHTML += "<p>Error: " + error.message + "</p>";
          console.error("Error:", error);
        });

      // Clear the question input field
      document.getElementById("question-input").value = "";
    } else {
      // Display an alert or message indicating that the question field or API key is empty
      alert("Please enter a question and API key.");
    }
  }

  // Attach event listener for sending the question
  document.getElementById("ask-button").addEventListener("click", sendQuestion);

  // Clear button functionality to empty the response area
  document
    .getElementById("clear-button")
    .addEventListener("click", function () {
      document.getElementById("response-area").innerHTML = "";
    });
});
