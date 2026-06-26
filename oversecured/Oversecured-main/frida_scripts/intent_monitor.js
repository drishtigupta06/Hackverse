
Java.perform(function() {
    var Intent = Java.use('android.content.Intent');
    var Activity = Java.use('android.app.Activity');
    Intent.putExtra.overload('java.lang.String', 'java.lang.String').implementation = function(name, value) {
        console.log('[Intent] putExtra(String,String): ' + name + ' = ' + value);
        return this.putExtra(name, value);
    };
    Intent.putExtra.overload('java.lang.String', 'int').implementation = function(name, value) {
        console.log('[Intent] putExtra(String,int): ' + name + ' = ' + value);
        return this.putExtra(name, value);
    };
    Intent.getStringExtra.implementation = function(name) {
        var val = this.getStringExtra(name);
        console.log('[Intent] getStringExtra: ' + name + ' => ' + val);
        return val;
    };
    Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
        console.log('[Intent] startActivity: ' + intent);
        console.log('[Intent] Action: ' + intent.getAction());
        console.log('[Intent] Data: ' + intent.getDataString());
        if (intent.getExtras()) {
            console.log('[Intent] Extras: ' + intent.getExtras().toString());
        }
        return this.startActivity(intent);
    };
    Activity.startActivityForResult.overload('android.content.Intent', 'int').implementation = function(intent, requestCode) {
        console.log('[Intent] startActivityForResult: ' + intent + ' code=' + requestCode);
        return this.startActivityForResult(intent, requestCode);
    };
    console.log('[Intent Monitor] Active');
});
