from drozer.modules.common import loader
from drozer.android import Intent

class ServiceBinding(loader.ClassLoader):
    """
    Mixin' for binding to a service, and exchanging messages with it.
    """
    
    class ServiceBindingProxy(object):
        
        def __init__(self, context, package, component):
            self.context = context
            self.package = package
            self.component = component
            
            self.bundle = None
            self.binder = None
            self.objFormat = "setData"
        
        def getData(self):
            return self.binder.printData()

        def getMessage(self):
            return self.binder.getMessage()

        def add_extra(self, extra):
            if self.bundle == None:
                self.bundle = self.context.new("android.os.Bundle")
            
            Intent.add_extra_to(self, extra, self.bundle, self.context)

        def setBundle(self, bundle):
            self.bundle = bundle

        def obtain_binder(self):
            if self.binder == None:
                ServiceBinder = self.context.loadClass("common/ServiceBinder.apk", "ServiceBinder")
                
                self.binder = self.context.new(ServiceBinder)
                
            return self.binder
            
        def obtain_message(self, msg):
            return self.context.klass("android.os.Message").obtain(None, int(msg[0]), int(msg[1]), int(msg[2]))
        
        def setObjFormat(self, format):
            self.objFormat = format

        def send_message(self, msg, timeout):
            binder = self.obtain_binder()
            message = self.obtain_message(msg)
            
            if self.bundle != None:
                if self.objFormat.upper() == "SETDATA":
                    message.setData(self.bundle)
                
                if self.objFormat.upper() == "BUNDLEASOBJ":
                    message.obj = self.bundle
            
            return binder.execute(self.context.getContext(), self.package, self.component, message, int(timeout))
    
    def getBinding(self, package, component):
        return ServiceBinding.ServiceBindingProxy(self, package, component)
        
