#include "hwgui.ch"
#include "webview.ch"

STATIC nWebView := 0

PROCEDURE Main()

   LOCAL oWindow

   INIT WINDOW oWindow TITLE "HWGUI + WebView" SIZE 800, 600 ;
      ON INIT {||Inicializa( oWindow )} ;
      ON SIZE {|o,nX,nY|iif( nWebView != 0, WebView_Set_Size( nWebView, nX, nY, WEBVIEW_HINT_NONE ), NIL )}

   ACTIVATE WINDOW oWindow

   WebView_Destroy( nWebView )

RETURN

STATIC FUNCTION Inicializa( oWindow )

   nWebView := WebView_Create( 0, oWindow:handle )

   //WebView_Set_Size( nWebView, 800, 600, WEBVIEW_HINT_NONE )

   WebView_Navigate( nWebView, "https://www.google.com" )

   //WebView_Run( nWebView )

RETURN NIL

#include "webview.prg"
