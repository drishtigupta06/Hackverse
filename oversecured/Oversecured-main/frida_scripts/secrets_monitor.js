
Java.perform(function() {
    var StringBuilder = Java.use('java.lang.StringBuilder');
    var String = Java.use('java.lang.String');
    var patterns = [
        /api[_-]?key/i, /secret/i, /token/i, /password/i, /passwd/i,
        /credential/i, /auth.?token/i, /bearer/i, /jwt/i, /apikey/i,
        /access.?key/i, /secret.?key/i, /private.?key/i, /aws/i, /sk-[a-zA-Z0-9]/i
    ];
    StringBuilder.toString.implementation = function() {
        var str = this.toString();
        for (var i = 0; i < patterns.length; i++) {
            if (patterns[i].test(str) && str.length < 500) {
                console.log('[SECRETS] StringBuilder: ' + str.substring(0, 300));
                break;
            }
        }
        return str;
    };
    String.$init.overload('java.lang.String').implementation = function(s) {
        for (var i = 0; i < patterns.length; i++) {
            if (patterns[i].test(s) && s.length < 500) {
                console.log('[SECRETS] String: ' + s.substring(0, 300));
                break;
            }
        }
        return this.$init(s);
    };
    console.log('[Secrets Monitor] Active - scanning for API keys, tokens, passwords');
});
