package nids.app

/**
 * Compile-time target for the production notification PendingIntent in this
 * isolated helper. The helper does not include the app UI or register this
 * activity. Notification navigation is checked in the main application, not here.
 *
 * ObservationNotifications itself is copied unchanged from production so the
 * no-repost regression exercises the real notification implementation.
 */
class LearnedNetworkActivity : android.app.Activity()
