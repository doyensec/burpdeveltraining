/*
 * This is an empty Burp Extension - Add here your file header
 */

package burp;

//Depending on the extension type, you'll add additional 'implements' interfaces here
public class BurpExtender implements IBurpExtender 
{
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Empty Burp Extension");
        
        //Your code goes here!
    }
}
