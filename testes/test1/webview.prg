#include "hbdll.ch"

/*
  WEBVIEW_API webview_t webview_create( int debug, void * window )
*/
DLL FUNCTION WEBVIEW_CREATE( nDebug AS INT, hWndParent AS LONG ) AS LONG PASCAL FROM "webview_create" LIB "webview.dll"

/*
  WEBVIEW_API void webview_destroy( webview_t w )
*/
DLL FUNCTION WEBVIEW_DESTROY( hWebView AS LONG ) AS VOID PASCAL FROM "webview_destroy" LIB "webview.dll"

/*
  WEBVIEW_API void webview_run( webview_t w )
*/
DLL FUNCTION WEBVIEW_RUN( hWebView AS LONG ) AS VOID PASCAL FROM "webview_run" LIB "webview.dll"

/*
  WEBVIEW_API void webview_terminate( webview_t w )
*/
DLL FUNCTION WEBVIEW_TERMINATE( hWebView AS LONG ) AS VOID PASCAL FROM "webview_terminate" LIB "webview.dll"

/*
  WEBVIEW_API void webview_dispatch( webview_t w, void (*fn)( webview_t w, void * arg ), void * arg )
*/

/*
  WEBVIEW_API void * webview_get_window( webview_t w )
*/
DLL FUNCTION WEBVIEW_GET_WINDOW( hWebView AS LONG ) AS LONG PASCAL FROM "webview_get_window" LIB "webview.dll"

/*
  WEBVIEW_API void webview_set_title( webview_t w, const char * title )
*/
DLL FUNCTION WEBVIEW_SET_TITLE( hWebView AS LONG, cTitle AS LPSTR ) AS VOID PASCAL FROM "webview_set_title" LIB "webview.dll"

/*
  WEBVIEW_API void webview_set_size( webview_t w, int width, int height, int hints )
*/
DLL FUNCTION WEBVIEW_SET_SIZE( hWebView AS LONG, nWidth AS INT, nHeight AS INT, nHints AS INT ) AS VOID PASCAL FROM "webview_set_size" LIB "webview.dll"

/*
  WEBVIEW_API void webview_navigate( webview_t w, const char * url )
*/
DLL FUNCTION WEBVIEW_NAVIGATE( hWebView AS LONG, cUrl AS LPSTR ) AS VOID PASCAL FROM "webview_navigate" LIB "webview.dll"

/*
  WEBVIEW_API void webview_init( webview_t w, const char * js )
*/
DLL FUNCTION WEBVIEW_INIT( hWebView AS LONG, cJs AS LPSTR ) AS VOID PASCAL FROM "webview_init" LIB "webview.dll"

/*
  WEBVIEW_API void webview_eval( webview_t w, const char * js )
*/
DLL FUNCTION WEBVIEW_EVAL( hWebView AS LONG, cJs AS LPSTR ) AS VOID PASCAL FROM "webview_eval" LIB "webview.dll"

/*
  WEBVIEW_API void webview_bind( webview_t w, const char * name, void (*fn)( const char * seq, const char * req, void * arg ), void * arg )
*/

/*
  WEBVIEW_API void webview_return( webview_t w, const char * seq, int status, const char * result )
*/
DLL FUNCTION WEBVIEW_RETURN( hWebView AS LONG, cSeq AS LPSTR, nStatus AS INT, cResult AS LPSTR ) AS VOID PASCAL FROM "webview_return" LIB "webview.dll"
