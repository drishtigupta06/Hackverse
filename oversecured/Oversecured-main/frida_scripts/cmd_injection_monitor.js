
Java.perform(function() {
    var Runtime = Java.use('java.lang.Runtime');
    var Process = Java.use('java.lang.Process');
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
        var cmd = cmdArray.join(' ');
        console.log('[CMD_INJECT] exec: ' + cmd);
        if (cmd.indexOf('|') >= 0 || cmd.indexOf(';') >= 0 || cmd.indexOf('&&') >= 0 || cmd.indexOf('`') >= 0) {
            console.log('[CMD_INJECT] CHAINING DETECTED: ' + cmd);
        }
        return this.exec(cmdArray);
    };
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        console.log('[CMD_INJECT] exec(String): ' + cmd);
        return this.exec(cmd);
    };
    ProcessBuilder.start.implementation = function() {
        var command = this.command();
        console.log('[CMD_INJECT] ProcessBuilder: ' + command);
        return this.start();
    };
    console.log('[Command Injection Monitor] Active');
});
