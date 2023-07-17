// Get the form element and attach an event listener to the submit event
const form = document.querySelector('form');
form.addEventListener('submit', checkLink);

function checkLink(event) {
  event.preventDefault(); // Prevent form submission

  // Get the URL input value
  const urlInput = document.getElementById('url');
  const url = urlInput.value.trim();

  // Perform the link checking logic using the VirusTotal API
  checkSafety(url)
    .then((isSafe) => {
      // Display the result to the user
      const resultMessage = isSafe ? 'The link is safe to use.' : 'The link is potentially malicious.';
      showResult(resultMessage);
    })
    .catch((error) => {
      // Handle any errors that occurred during the link checking process
      showResult('An error occurred while checking the link. Please try again later.');
    });

  // Clear the input field
  urlInput.value = '';
}

function checkSafety(url) {
  return new Promise((resolve, reject) => {
    // Replace 'YOUR_API_KEY' with your actual VirusTotal API key
    const apiKey = '50e61a0af11c868bafd7cf8528bfc06304ef6eb695d6a024148fef3cd9ea0a1f';

    // Construct the API request URL
    const apiUrl = `https://www.virustotal.com/api/v3/urls/${encodeURIComponent(url)}`;

    // Make a request to the VirusTotal API
    fetch(apiUrl, {
      headers: {
        'x-apikey': "50e61a0af11c868bafd7cf8528bfc06304ef6eb695d6a024148fef3cd9ea0a1f"
      }
    })
      .then(response => response.json())
      .then(data => {
        // Extract the relevant information from the API response
        const isSafe = data.data.attributes.last_analysis_stats.malicious > 0 ? false : true;

        // Resolve the promise with the result (true if safe, false if potentially malicious)
        resolve(isSafe);
      })
      .catch(error => {
        // Reject the promise if an error occurred during the API request
        reject(error);
      });
  });
}

function showResult(message) {
  // Remove any existing result container
  const existingResultContainer = document.getElementById('result');
  if (existingResultContainer) {
    existingResultContainer.remove();
  }

  // Create a new result container and display the message
  const resultContainer = document.createElement('div');
  resultContainer.id = 'result';
  resultContainer.textContent = message;
  form.appendChild(resultContainer);
}