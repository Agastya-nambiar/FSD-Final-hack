self.addEventListener('push', event => {
  let data = {};
  try { data = event.data.json(); } catch { data = { title: 'Sentinel alert', message: event.data?.text() || '' }; }
  event.waitUntil(self.registration.showNotification(data.title || 'Sentinel alert', {
    body: data.message || 'There is an incident response update.',
    icon: '/icon.svg', badge: '/icon.svg', tag: data.incidentId || 'sentinel-alert',
    data: { url: data.incidentId ? `/?incident=${encodeURIComponent(data.incidentId)}` : '/' }
  }));
});
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(clients.openWindow(event.notification.data?.url || '/'));
});
