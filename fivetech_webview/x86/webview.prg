// Please install https://developer.microsoft.com/en-us/microsoft-edge/webview2/ x86 version before using it

#include "FiveWin.ch"

function Main()

   local oWebView := TWebView():New()

   oWebView:Navigate( "http://www.google.com" )
   oWebView:SetTitle( "Microsoft Edge WebView working from FWH" )
   oWebView:SetSize( 1200, 800 )
   oWebView:SetUserAgent( "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Mobile Safari/537.36" )
   oWebView:OpenDevToolsWindow()
   sleep( 300 )
   oWebView:Run()
   oWebView:Destroy()

return nil