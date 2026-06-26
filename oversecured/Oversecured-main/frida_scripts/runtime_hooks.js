
Java.perform(function() {
    var Runtime = Java.use('java.lang.Runtime');
    var System = Java.use('java.lang.System');
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    var PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
        console.log('[Runtime.exec] Command: ' + cmdArray.join(' '));
        return this.exec(cmdArray);
    };
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        console.log('[Runtime.exec] Command: ' + cmd);
        return this.exec(cmd);
    };
    DexClassLoader.$init.implementation = function(dexPath, optimizedDir, libPath, parent) {
        console.log('[DexLoader] Loading: ' + dexPath);
        return this.$init(dexPath, optimizedDir, libPath, parent);
    };
    PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(path, parent) {
        console.log('[PathLoader] Loading: ' + path);
        return this.$init(path, parent);
    };
    console.log('[Runtime Hooks] Active - monitoring exec, dex loading');
});
