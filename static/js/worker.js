/**
 * Created by Frank Yang on 2017-02-14.
 * Web worker for python-web-push
 */
self.addEventListener('install', function(event){
    console.log(event);
});
self.addEventListener('message', function(event){
    console.log("Message: " + event.data);
    if (event.data.indexOf("notify") === 0){
        let pushData = JSON.parse(event.data.slice(7));
        let title = pushData.title;
        event.waitUntil(
            Promise.all([
                self.registration.showNotification(
                    title, pushData
                )
            ])
        )
    }
});
self.addEventListener('push', function(event){
    console.log('Received push');
    let notificationTitle = 'Notification from server';
    let notificationOptions = {
        body: 'Server sent notification',
        tag: 'python-webnoti',
    };

    if (event.data){
        notificationOptions.body = event.data.text();
    }

    event.waitUntil(
        self.registration.showNotification(
            notificationTitle, notificationOptions)
    )
});