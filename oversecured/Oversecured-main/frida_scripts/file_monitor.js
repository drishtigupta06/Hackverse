
Java.perform(function() {
    var File = Java.use('java.io.File');
    var FileOutputStream = Java.use('java.io.FileOutputStream');
    var FileInputStream = Java.use('java.io.FileInputStream');
    var RandomAccessFile = Java.use('java.io.RandomAccessFile');
    FileOutputStream.write.overload('[B').implementation = function(b) {
        var path = this.getFD() ? this.getFD().toString() : 'unknown';
        var preview = '';
        for (var i = 0; i < Math.min(b.length, 100); i++) preview += String.fromCharCode(b[i] & 0xff);
        console.log('[FileWrite] ' + path + ': ' + preview);
        return this.write(b);
    };
    FileInputStream.read.overload('[B').implementation = function(b) {
        var ret = this.read(b);
        if (ret > 0) {
            var preview = '';
            for (var i = 0; i < Math.min(ret, 100); i++) preview += String.fromCharCode(b[i] & 0xff);
            console.log('[FileRead] (' + this.getFD() + '): ' + preview);
        }
        return ret;
    };
    console.log('[File Monitor] Monitoring file I/O operations');
});
