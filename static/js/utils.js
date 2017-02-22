function base64UrlToUint8Array(base64UrlData) {
    const padding = '='.repeat((4 - base64UrlData.length % 4) % 4);
    const base64 = (base64UrlData + padding)
        .replace(/\-/g, '+')
        .replace(/_/g, '/');

    const rawData = window.atob(base64);
    const buffer = new Uint8Array(rawData.length);

    for (let i = 0; i < rawData.length; ++i) {
        buffer[i] = rawData.charCodeAt(i);
    }
    return buffer;
}
function enableUI(){
    let form = document.querySelector('#send-noti');
    let button = document.querySelector('#send');
    let textarea = document.querySelector('#message');
    form.addEventListener('submit', function(e){
        let request = new XMLHttpRequest();
        request.open('POST', '/send-notification');
        request.setRequestHeader('Content-Type', 'application/json');
        request.addEventListener('load', function(e){
            console.log(e);
            console.log(this);
        });
        if (textarea.value === ""){
            request.send(JSON.stringify({subscription: window.subscription}));
        } else {
            request.send(JSON.stringify({subscription: window.subscription, message: textarea.value}));
        }
        e.preventDefault();
    });
    button.removeAttribute('disabled');
    textarea.removeAttribute('disabled');
    console.log('Enabled UI');
}