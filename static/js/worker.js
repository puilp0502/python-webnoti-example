/**
 * Created by Frank Yang on 2017-02-14.
 * Web worker for python-web-push
 */
self.addEventListener('install', function(event){
    console.log(event);
});
self.addEventListener('push', function(event){
    console.log('Received push');
    let notificationTitle = 'Notification from server';
    let notificationOptions = {
        body: 'Server sent notification',
        tag: 'python-webnoti',
        // More options can be found at:
        // https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerRegistration/showNotification
    };

    if (event.data){
        // Server sent you a data!
        notificationOptions.body = event.data.text();
    }

    event.waitUntil(
        self.registration.showNotification(
            notificationTitle, notificationOptions)
    )
});