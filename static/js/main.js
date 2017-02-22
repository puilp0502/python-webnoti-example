if ('serviceWorker' in navigator && 'PushManager' in window) {
    window.addEventListener('load', function(){
        function askPermission() {
            return new Promise(function(resolve, reject) {
                const permissionResult = Notification.requestPermission(function(result) {
                    resolve(result);
                });
                if (permissionResult) {
                    permissionResult.then(resolve, reject);
                }
            })
        }
        // Obtain applicationServerKey from server
        const serverKey = base64UrlToUint8Array(serverKeyBase64);
        // Ask for Notification permission
        let permRequest = askPermission();
        //register ServiceWorker
        let registrationRequest = navigator.serviceWorker.register('/service-worker.js');

        // Wait for two requests to complete
        Promise.all([permRequest, registrationRequest])
            .then(function(result){
                let permission = result[0];
                let registration = result[1];
                console.log('ServiceWorker registered @ ', registration.scope);
                if (permission === 'granted') {
                    registration.pushManager.subscribe({
                        userVisibleOnly: true, // Chrome requires this
                        applicationServerKey: serverKey,
                    }).then(
                        function (subscription) {
                            // Store subscription in global context
                            window.subscription = subscription;
                            console.log('subscription obtained: '+JSON.stringify(subscription));
                            // Enable UI
                            enableUI();
                        }, function (error) {
                            console.error(error);
                        }
                    );
                } else {
                    console.error('Permission is not granted')
                }
            })
            .catch(function(err){
                console.error('ServiceWorker registration failed: ', err);
            });
    })
} else {
    console.error('This browser does not support Push Notification. :(')
}
