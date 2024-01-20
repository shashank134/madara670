// File: alertScript.js

alert(document.domain);
// File: script.js

// Example AJAX request to a PHP endpoint
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://shashank134.github.io/madara670/boom.html', true);

xhr.onload = function () {
    if (xhr.status == 200) {
        alert(xhr.responseText);
    }
};

xhr.send();
