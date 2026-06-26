
Java.perform(function() {
    var SharedPreferences = Java.use('android.content.SharedPreferences');
    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
    SharedPreferencesImpl.getString.implementation = function(key, defValue) {
        var val = this.getString(key, defValue);
        console.log('[SharedPrefs] GET: ' + key + ' = ' + (val ? val.substring(0, 100) : 'null'));
        return val;
    };
    SharedPreferencesImpl.edit.implementation = function() {
        var editor = this.edit();
        var editorClass = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        editorClass.putString.implementation = function(key, value) {
            console.log('[SharedPrefs] SET: ' + key + ' = ' + (value ? value.substring(0, 100) : 'null'));
            return this.putString(key, value);
        };
        return editor;
    };
    console.log('[SharedPrefs Monitor] Active');
});
