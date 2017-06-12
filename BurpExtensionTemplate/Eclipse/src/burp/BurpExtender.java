/*
 * BurpExtender - This is an empty Burp extension
 *
 * Copyright (c) 2017 Doyensec LLC. Made with love by Luca Carettoni.
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