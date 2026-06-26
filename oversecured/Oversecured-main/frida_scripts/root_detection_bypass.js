
Java.perform(function() {
    var RootDetection = {
        findClass: function(name) {
            try { Java.use(name); return true; } catch(e) { return false; }
        }
    };
    var classes = [
        'android.os.Build', 'java.lang.Runtime', 'java.lang.Process',
        'com.scottyab.rootbeer.RootBeer',
        'com.deviceinfohardware.RootDetection',
        'org.joor.Reflect',
        'com.jared.crummy.RootChecker',
        'com.saurik.substrate.MSB',
        'de.robv.android.xposed.XposedBridge',
        'com.topjohnwu.superuser.Shell'
    ];
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
        var cmd = cmdArray.join(' ');
        if (cmd.indexOf('su') >= 0 || cmd.indexOf('busybox') >= 0 ||
            cmd.indexOf('magisk') >= 0 || cmd.indexOf('superuser') >= 0 ||
            cmd.indexOf('test-keys') >= 0 || cmd.indexOf('ro.debuggable') >= 0 ||
            cmd.indexOf('ro.secure') >= 0) {
            console.log('[RootDetection] Blocked root check: ' + cmd);
            return Java.use('java.lang.Process').$new();
        }
        return this.exec(cmdArray);
    };
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ['/system/app/Superuser', '/system/bin/su', '/system/xbin/su',
                         '/data/local/xbin/su', '/data/local/bin/su', '/system/sd/xbin/su',
                         '/system/bin/failsafe/su', '/data/local/su', '/su/bin/su',
                         '/magisk', '/sbin/su'];
        if (rootPaths.indexOf(path) >= 0) {
            console.log('[RootDetection] Blocked root path check: ' + path);
            return false;
        }
        return this.exists();
    };
    console.log('[Root Detection Bypass] Active');
});
