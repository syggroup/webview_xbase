/*
 * MIT License
 *
 * Copyright (c) 2017 Serge Zaitsev
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
  28/04/2022 16:19:59 marcosgambeta@outlook.com
  Código para Linux e Mac removido.
  Função adicionada:
  WEBVIEW_API int webview_get_result();

  11/12/2021 17:57:29 marcosgambeta@outlook.com
  Funções adicionadas:
  WEBVIEW_API void webview_set_userDataFolder(const char *folder);
  WEBVIEW_API void webview_set_browserExecutableFolder(const char *folder);
  Válidas apenas para WEBVIEW_EDGE
*/

#ifndef WEBVIEW_H
#define WEBVIEW_H

#ifndef WEBVIEW_API
#define WEBVIEW_API extern
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void *webview_t;

WEBVIEW_API void webview_set_userDataFolder(const char *folder);

WEBVIEW_API void webview_set_browserExecutableFolder(const char *folder);

// Creates a new webview instance. If debug is non-zero - developer tools will
// be enabled (if the platform supports them). Window parameter can be a
// pointer to the native window handle. If it's non-null - then child WebView
// is embedded into the given parent window. Otherwise a new window is created.
// Depending on the platform, a GtkWindow, NSWindow or HWND pointer can be
// passed here.
WEBVIEW_API webview_t webview_create(int debug, void *window);

// Destroys a webview and closes the native window.
WEBVIEW_API void webview_destroy(webview_t w);

// Runs the main loop until it's terminated. After this function exits - you
// must destroy the webview.
WEBVIEW_API void webview_run(webview_t w);

// Stops the main loop. It is safe to call this function from another other
// background thread.
WEBVIEW_API void webview_terminate(webview_t w);

// Posts a function to be executed on the main thread. You normally do not need
// to call this function, unless you want to tweak the native window.
WEBVIEW_API void webview_dispatch(webview_t w, void (*fn)(webview_t w, void *arg), void *arg);

// Returns a native window handle pointer. When using GTK backend the pointer
// is GtkWindow pointer, when using Cocoa backend the pointer is NSWindow
// pointer, when using Win32 backend the pointer is HWND pointer.
WEBVIEW_API void *webview_get_window(webview_t w);

// Updates the title of the native window. Must be called from the UI thread.
WEBVIEW_API void webview_set_title(webview_t w, const char *title);

// Window size hints
#define WEBVIEW_HINT_NONE 0  // Width and height are default size
#define WEBVIEW_HINT_MIN 1   // Width and height are minimum bounds
#define WEBVIEW_HINT_MAX 2   // Width and height are maximum bounds
#define WEBVIEW_HINT_FIXED 3 // Window size can not be changed by a user
// Updates native window size. See WEBVIEW_HINT constants.
WEBVIEW_API void webview_set_size(webview_t w, int width, int height, int hints);

// Navigates webview to the given URL. URL may be a data URI, i.e.
// "data:text/text,<html>...</html>". It is often ok not to url-encode it
// properly, webview will re-encode it for you.
WEBVIEW_API void webview_navigate(webview_t w, const char *url);

// Injects JavaScript code at the initialization of the new page. Every time
// the webview will open a the new page - this initialization code will be
// executed. It is guaranteed that code is executed before window.onload.
WEBVIEW_API void webview_init(webview_t w, const char *js);

// Evaluates arbitrary JavaScript code. Evaluation happens asynchronously, also
// the result of the expression is ignored. Use RPC bindings if you want to
// receive notifications about the results of the evaluation.
WEBVIEW_API void webview_eval(webview_t w, const char *js);

// Binds a native C callback so that it will appear under the given name as a
// global JavaScript function. Internally it uses webview_init(). Callback
// receives a request string and a user-provided argument pointer. Request
// string is a JSON array of all the arguments passed to the JavaScript
// function.
WEBVIEW_API void webview_bind(webview_t w, const char *name, void (*fn)(const char *seq, const char *req, void *arg), void *arg);

// Allows to return a value from the native binding. Original request pointer
// must be provided to help internal RPC engine match requests with responses.
// If status is zero - result is expected to be a valid JSON result value.
// If status is not zero - result is an error JSON object.
WEBVIEW_API void webview_return(webview_t w, const char *seq, int status, const char *result);

WEBVIEW_API int webview_get_result();

#ifdef __cplusplus
}
#endif

#ifndef WEBVIEW_HEADER

#if !defined(WEBVIEW_EDGE)
#if defined(_WIN32)
#define WEBVIEW_EDGE
#else
#error "please, specify webview backend"
#endif
#endif

#include <atomic>
#include <functional>
#include <future>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <cstring>

namespace webview {

std::wstring s_userDataFolder;
std::wstring s_browserExecutableFolder;
int s_result;

using dispatch_fn_t = std::function<void()>;

// Convert ASCII hex digit to a nibble (four bits, 0 - 15).
//
// Use unsigned to avoid signed overflow UB.
static inline unsigned char hex2nibble(unsigned char c)
{
  if( c >= '0' && c <= '9' )
  {
    return c - '0';
  }
  else if( c >= 'a' && c <= 'f' )
  {
    return 10 + (c - 'a');
  }
  else if( c >= 'A' && c <= 'F' )
  {
    return 10 + (c - 'A');
  }
  return 0;
}

// Convert ASCII hex string (two characters) to byte.
//
// E.g., "0B" => 0x0B, "af" => 0xAF.
static inline char hex2char(const char *p)
{
  return hex2nibble(p[0]) * 16 + hex2nibble(p[1]);
}

inline std::string url_encode(const std::string s)
{
  std::string encoded;
  for( unsigned int i = 0; i < s.length(); i++ )
  {
    auto c = s[i];
    if( isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' )
    {
      encoded = encoded + c;
    }
    else
    {
      char hex[4];
      snprintf(hex, sizeof(hex), "%%%02x", c);
      encoded = encoded + hex;
    }
  }
  return encoded;
}

inline std::string url_decode(const std::string st)
{
  std::string decoded;
  const char *s = st.c_str();
  size_t length = strlen(s);
  for( unsigned int i = 0; i < length; i++ )
  {
    if( s[i] == '%' )
    {
      decoded.push_back(hex2char(s + i + 1));
      i = i + 2;
    }
    else if( s[i] == '+' )
    {
      decoded.push_back(' ');
    }
    else
    {
      decoded.push_back(s[i]);
    }
  }
  return decoded;
}

inline std::string html_from_uri(const std::string s)
{
  if( s.substr(0, 15) == "data:text/html," )
  {
    return url_decode(s.substr(15));
  }
  return "";
}

inline int json_parse_c(const char *s, size_t sz, const char *key, size_t keysz, const char **value, size_t *valuesz)
{
  enum {
    JSON_STATE_VALUE,
    JSON_STATE_LITERAL,
    JSON_STATE_STRING,
    JSON_STATE_ESCAPE,
    JSON_STATE_UTF8
  } state = JSON_STATE_VALUE;
  const char *k = NULL;
  int index = 1;
  int depth = 0;
  int utf8_bytes = 0;

  if( key == NULL )
  {
    index = keysz;
    keysz = 0;
  }

  *value = NULL;
  *valuesz = 0;

  for( ; sz > 0; s++, sz-- )
  {
    enum {
      JSON_ACTION_NONE,
      JSON_ACTION_START,
      JSON_ACTION_END,
      JSON_ACTION_START_STRUCT,
      JSON_ACTION_END_STRUCT
    } action = JSON_ACTION_NONE;
    unsigned char c = *s;
    switch (state)
    {
    case JSON_STATE_VALUE:
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' ||
          c == ':') {
        continue;
      } else if (c == '"') {
        action = JSON_ACTION_START;
        state = JSON_STATE_STRING;
      } else if (c == '{' || c == '[') {
        action = JSON_ACTION_START_STRUCT;
      } else if (c == '}' || c == ']') {
        action = JSON_ACTION_END_STRUCT;
      } else if (c == 't' || c == 'f' || c == 'n' || c == '-' ||
                 (c >= '0' && c <= '9')) {
        action = JSON_ACTION_START;
        state = JSON_STATE_LITERAL;
      } else {
        return -1;
      }
      break;
    case JSON_STATE_LITERAL:
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' ||
          c == ']' || c == '}' || c == ':') {
        state = JSON_STATE_VALUE;
        s--;
        sz++;
        action = JSON_ACTION_END;
      } else if (c < 32 || c > 126) {
        return -1;
      } // fallthrough
    case JSON_STATE_STRING:
      if (c < 32 || (c > 126 && c < 192)) {
        return -1;
      } else if (c == '"') {
        action = JSON_ACTION_END;
        state = JSON_STATE_VALUE;
      } else if (c == '\\') {
        state = JSON_STATE_ESCAPE;
      } else if (c >= 192 && c < 224) {
        utf8_bytes = 1;
        state = JSON_STATE_UTF8;
      } else if (c >= 224 && c < 240) {
        utf8_bytes = 2;
        state = JSON_STATE_UTF8;
      } else if (c >= 240 && c < 247) {
        utf8_bytes = 3;
        state = JSON_STATE_UTF8;
      } else if (c >= 128 && c < 192) {
        return -1;
      }
      break;
    case JSON_STATE_ESCAPE:
      if (c == '"' || c == '\\' || c == '/' || c == 'b' || c == 'f' ||
          c == 'n' || c == 'r' || c == 't' || c == 'u') {
        state = JSON_STATE_STRING;
      } else {
        return -1;
      }
      break;
    case JSON_STATE_UTF8:
      if (c < 128 || c > 191) {
        return -1;
      }
      utf8_bytes--;
      if (utf8_bytes == 0) {
        state = JSON_STATE_STRING;
      }
      break;
    default:
      return -1;
    }

    if (action == JSON_ACTION_END_STRUCT) {
      depth--;
    }

    if (depth == 1) {
      if (action == JSON_ACTION_START || action == JSON_ACTION_START_STRUCT) {
        if (index == 0) {
          *value = s;
        } else if (keysz > 0 && index == 1) {
          k = s;
        } else {
          index--;
        }
      } else if (action == JSON_ACTION_END ||
                 action == JSON_ACTION_END_STRUCT) {
        if (*value != NULL && index == 0) {
          *valuesz = (size_t)(s + 1 - *value);
          return 0;
        } else if (keysz > 0 && k != NULL) {
          if (keysz == (size_t)(s - k - 1) && memcmp(key, k + 1, keysz) == 0) {
            index = 0;
          } else {
            index = 2;
          }
          k = NULL;
        }
      }
    }

    if (action == JSON_ACTION_START_STRUCT) {
      depth++;
    }
  }
  return -1;
}

inline std::string json_escape(std::string s) {
  // TODO: implement
  return '"' + s + '"';
}

inline int json_unescape(const char *s, size_t n, char *out) {
  int r = 0;
  if (*s++ != '"') {
    return -1;
  }
  while (n > 2) {
    char c = *s;
    if (c == '\\') {
      s++;
      n--;
      switch (*s) {
      case 'b':
        c = '\b';
        break;
      case 'f':
        c = '\f';
        break;
      case 'n':
        c = '\n';
        break;
      case 'r':
        c = '\r';
        break;
      case 't':
        c = '\t';
        break;
      case '\\':
        c = '\\';
        break;
      case '/':
        c = '/';
        break;
      case '\"':
        c = '\"';
        break;
      default: // TODO: support unicode decoding
        return -1;
      }
    }
    if (out != NULL) {
      *out++ = c;
    }
    s++;
    n--;
    r++;
  }
  if (*s != '"') {
    return -1;
  }
  if (out != NULL) {
    *out = '\0';
  }
  return r;
}

inline std::string json_parse(const std::string s, const std::string key,
                              const int index) {
  const char *value;
  size_t value_sz;
  if (key == "") {
    json_parse_c(s.c_str(), s.length(), nullptr, index, &value, &value_sz);
  } else {
    json_parse_c(s.c_str(), s.length(), key.c_str(), key.length(), &value,
                 &value_sz);
  }
  if (value != nullptr) {
    if (value[0] != '"') {
      return std::string(value, value_sz);
    }
    int n = json_unescape(value, value_sz, nullptr);
    if (n > 0) {
      char *decoded = new char[n + 1];
      json_unescape(value, value_sz, decoded);
      std::string result(decoded, n);
      delete[] decoded;
      return result;
    }
  }
  return "";
}

} // namespace webview

#if defined(WEBVIEW_EDGE)

//
// ====================================================================
//
// This implementation uses Win32 API to create a native window. It can
// use either EdgeHTML or Edge/Chromium backend as a browser engine.
//
// ====================================================================
//

#define WIN32_LEAN_AND_MEAN
#include <Shlwapi.h>
#include <codecvt>
#include <stdlib.h>
#include <windows.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "Shlwapi.lib")

// EdgeHTML headers and libs
#include <objbase.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Web.UI.Interop.h>
#pragma comment(lib, "windowsapp")

// Edge/Chromium headers and libs
#include "webview2.h"
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace webview {

using msg_cb_t = std::function<void(const std::string)>;

// Common interface for EdgeHTML and Edge/Chromium
class browser {
public:
  virtual ~browser() = default;
  virtual bool embed(HWND, bool, msg_cb_t) = 0;
  virtual void navigate(const std::string url) = 0;
  virtual void eval(const std::string js) = 0;
  virtual void init(const std::string js) = 0;
  virtual void resize(HWND) = 0;
};

//
// EdgeHTML browser engine
//
using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Web::UI;
using namespace Windows::Web::UI::Interop;

class edge_html : public browser {
public:
  bool embed(HWND wnd, bool debug, msg_cb_t cb) override
  {
    init_apartment(winrt::apartment_type::single_threaded);
    auto process = WebViewControlProcess();
    auto op = process.CreateWebViewControlAsync(reinterpret_cast<int64_t>(wnd), Rect());
    if( op.Status() != AsyncStatus::Completed )
    {
      handle h(CreateEvent(nullptr, false, false, nullptr));
      op.Completed([h = h.get()](auto, auto) { SetEvent(h); });
      HANDLE hs[] = {h.get()};
      DWORD i;
      CoWaitForMultipleHandles(COWAIT_DISPATCH_WINDOW_MESSAGES | COWAIT_DISPATCH_CALLS | COWAIT_INPUTAVAILABLE, INFINITE, 1, hs, &i);
    }
    m_webview = op.GetResults();
    m_webview.Settings().IsScriptNotifyAllowed(true);
    m_webview.IsVisible(true);
    m_webview.ScriptNotify([=](auto const &sender, auto const &args)
    {
      std::string s = winrt::to_string(args.Value());
      cb(s.c_str());
    });
    m_webview.NavigationStarting([=](auto const &sender, auto const &args)
    {
      m_webview.AddInitializeScript(winrt::to_hstring(init_js));
    });
    init("window.external.invoke = s => window.external.notify(s)");
    return true;
  }

  void navigate(const std::string url) override
  {
    std::string html = html_from_uri(url);
    if( html != "" )
    {
      m_webview.NavigateToString(winrt::to_hstring(html));
    }
    else
    {
      Uri uri(winrt::to_hstring(url));
      m_webview.Navigate(uri);
    }
  }

  void init(const std::string js) override
  {
    init_js = init_js + "(function(){" + js + "})();";
  }

  void eval(const std::string js) override
  {
    m_webview.InvokeScriptAsync(L"eval", single_threaded_vector<hstring>({winrt::to_hstring(js)}));
  }

  void resize(HWND wnd) override
  {
    if( m_webview == nullptr )
    {
      return;
    }
    RECT r;
    GetClientRect(wnd, &r);
    Rect bounds(r.left, r.top, r.right - r.left, r.bottom - r.top);
    m_webview.Bounds(bounds);
  }

private:
  WebViewControl m_webview = nullptr;
  std::string init_js = "";
};

//
// Edge/Chromium browser engine
//
class edge_chromium : public browser {
public:
  bool embed(HWND wnd, bool debug, msg_cb_t cb) override
  {
    CoInitializeEx(nullptr, 0);
    std::atomic_flag flag = ATOMIC_FLAG_INIT;
    flag.test_and_set();

    char currentExePath[MAX_PATH];
    GetModuleFileNameA(NULL, currentExePath, MAX_PATH);
    char *currentExeName = PathFindFileNameA(currentExePath);
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> wideCharConverter;
    std::wstring currentExeNameW = wideCharConverter.from_bytes(currentExeName);

    std::wstring browserExecutableFolder;
    if( s_browserExecutableFolder.empty() )
    {
      browserExecutableFolder = s_browserExecutableFolder;
    }

    std::wstring userDataFolder;
    if( s_userDataFolder.empty() )
    {
      userDataFolder = ( wideCharConverter.from_bytes(std::getenv("APPDATA")) + L"/" + currentExeNameW );
    }
    else
    {
      userDataFolder = s_userDataFolder;
    }

    HRESULT res = CreateCoreWebView2EnvironmentWithOptions(
      browserExecutableFolder.c_str(),
      userDataFolder.c_str(),
      nullptr,
      new webview2_com_handler(wnd, cb, [&](ICoreWebView2Controller *controller)
      {
        m_controller = controller;
        m_controller->get_CoreWebView2(&m_webview);
        m_webview->AddRef();
        flag.clear();
      }));
    s_result = res;
    if( res != S_OK )
    {
      CoUninitialize();
      return false;
    }
    MSG msg = {};
    while( flag.test_and_set() && GetMessage(&msg, NULL, 0, 0) )
    {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
    init("window.external={invoke:s=>window.chrome.webview.postMessage(s)}");
    return true;
  }

  void resize(HWND wnd) override
  {
    if( m_controller == nullptr )
    {
      return;
    }
    RECT bounds;
    GetClientRect(wnd, &bounds);
    m_controller->put_Bounds(bounds);
  }

  void navigate(const std::string url) override
  {
    auto wurl = to_lpwstr(url);
    m_webview->Navigate(wurl);
    delete[] wurl;
  }

  void init(const std::string js) override
  {
    LPCWSTR wjs = to_lpwstr(js);
    m_webview->AddScriptToExecuteOnDocumentCreated(wjs, nullptr);
    delete[] wjs;
  }

  void eval(const std::string js) override
  {
    LPCWSTR wjs = to_lpwstr(js);
    m_webview->ExecuteScript(wjs, nullptr);
    delete[] wjs;
  }

private:
  LPWSTR to_lpwstr(const std::string s)
  {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    wchar_t *ws = new wchar_t[n];
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws, n);
    return ws;
  }

  ICoreWebView2 *m_webview = nullptr;
  ICoreWebView2Controller *m_controller = nullptr;

  class webview2_com_handler : public ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler,
                               public ICoreWebView2CreateCoreWebView2ControllerCompletedHandler,
                               public ICoreWebView2WebMessageReceivedEventHandler,
                               public ICoreWebView2PermissionRequestedEventHandler {
    using webview2_com_handler_cb_t = std::function<void(ICoreWebView2Controller *)>;

  public:
    webview2_com_handler(HWND hwnd, msg_cb_t msgCb, webview2_com_handler_cb_t cb) : m_window(hwnd), m_msgCb(msgCb), m_cb(cb)
    {
    }
    ULONG STDMETHODCALLTYPE AddRef()
    {
      return 1;
    }
    ULONG STDMETHODCALLTYPE Release()
    {
      return 1;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, LPVOID *ppv)
    {
      return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Invoke(HRESULT res, ICoreWebView2Environment *env)
    {
      env->CreateCoreWebView2Controller(m_window, this);
      return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Invoke(HRESULT res, ICoreWebView2Controller *controller)
    {
      controller->AddRef();

      ICoreWebView2 *webview;
      ::EventRegistrationToken token;
      controller->get_CoreWebView2(&webview);
      webview->add_WebMessageReceived(this, &token);
      webview->add_PermissionRequested(this, &token);

      m_cb(controller);
      return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2 *sender, ICoreWebView2WebMessageReceivedEventArgs *args)
    {
      LPWSTR message;
      args->TryGetWebMessageAsString(&message);

      std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> wideCharConverter;
      m_msgCb(wideCharConverter.to_bytes(message));
      sender->PostWebMessageAsString(message);

      CoTaskMemFree(message);
      return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2 *sender, ICoreWebView2PermissionRequestedEventArgs *args)
    {
      COREWEBVIEW2_PERMISSION_KIND kind;
      args->get_PermissionKind(&kind);
      if( kind == COREWEBVIEW2_PERMISSION_KIND_CLIPBOARD_READ )
      {
        args->put_State(COREWEBVIEW2_PERMISSION_STATE_ALLOW);
      }
      return S_OK;
    }

  private:
    HWND m_window;
    msg_cb_t m_msgCb;
    webview2_com_handler_cb_t m_cb;
  };
};

class win32_edge_engine {
public:
  win32_edge_engine(bool debug, void *window)
  {
    if( window == nullptr )
    {
      HINSTANCE hInstance = GetModuleHandle(nullptr);
      HICON icon = (HICON)LoadImage(hInstance, IDI_APPLICATION, IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);

      WNDCLASSEX wc;
      ZeroMemory(&wc, sizeof(WNDCLASSEX));
      wc.cbSize = sizeof(WNDCLASSEX);
      wc.hInstance = hInstance;
      wc.lpszClassName = "webview";
      wc.hIcon = icon;
      wc.hIconSm = icon;
      wc.lpfnWndProc =
          (WNDPROC)(+[](HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) -> int {
            auto w = (win32_edge_engine *)GetWindowLongPtr(hwnd, GWLP_USERDATA);
            switch (msg)
            {
              case WM_SIZE:
                w->m_browser->resize(hwnd);
                break;
              case WM_CLOSE:
                DestroyWindow(hwnd);
                break;
              case WM_DESTROY:
                w->terminate();
                break;
              case WM_GETMINMAXINFO:
              {
                auto lpmmi = (LPMINMAXINFO)lp;
                if( w == nullptr )
                {
                  return 0;
                }
                if( w->m_maxsz.x > 0 && w->m_maxsz.y > 0 )
                {
                  lpmmi->ptMaxSize = w->m_maxsz;
                 lpmmi->ptMaxTrackSize = w->m_maxsz;
                }
                if( w->m_minsz.x > 0 && w->m_minsz.y > 0 )
                {
                  lpmmi->ptMinTrackSize = w->m_minsz;
                }
              }
              break;
              default:
                return DefWindowProc(hwnd, msg, wp, lp);
            }
            return 0;
          });
      RegisterClassEx(&wc);
      m_window = CreateWindow("webview", "", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 640, 480, nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
      SetWindowLongPtr(m_window, GWLP_USERDATA, (LONG_PTR)this);
    }
    else
    {
      m_window = static_cast<HWND>(window);
    }

    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE);
    ShowWindow(m_window, SW_SHOW);
    UpdateWindow(m_window);
    SetFocus(m_window);

    auto cb = std::bind(&win32_edge_engine::on_message, this, std::placeholders::_1);

    if (!m_browser->embed(m_window, debug, cb))
    {
      m_browser = std::make_unique<webview::edge_html>();
      m_browser->embed(m_window, debug, cb);
    }

    m_browser->resize(m_window);
  }

  void run()
  {
    MSG msg;
    BOOL res;
    while( (res = GetMessage(&msg, nullptr, 0, 0)) != -1 )
    {
      if( msg.hwnd )
      {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
        continue;
      }
      if( msg.message == WM_APP )
      {
        auto f = (dispatch_fn_t *)(msg.lParam);
        (*f)();
        delete f;
      }
      else if( msg.message == WM_QUIT )
      {
        return;
      }
    }
  }
  void *window()
  {
    return (void *)m_window;
  }
  void terminate()
  {
    PostQuitMessage(0);
  }
  void dispatch(dispatch_fn_t f)
  {
    PostThreadMessage(m_main_thread, WM_APP, 0, (LPARAM) new dispatch_fn_t(f));
  }

  void set_title(const std::string title)
  {
    SetWindowText(m_window, title.c_str());
  }

  void set_size(int width, int height, int hints)
  {
    auto style = GetWindowLong(m_window, GWL_STYLE);
    if( hints == WEBVIEW_HINT_FIXED )
    {
      style &= ~(WS_THICKFRAME | WS_MAXIMIZEBOX);
    }
    else
    {
      style |= (WS_THICKFRAME | WS_MAXIMIZEBOX);
    }
    SetWindowLong(m_window, GWL_STYLE, style);

    if( hints == WEBVIEW_HINT_MAX )
    {
      m_maxsz.x = width;
      m_maxsz.y = height;
    }
    else if( hints == WEBVIEW_HINT_MIN )
    {
      m_minsz.x = width;
      m_minsz.y = height;
    }
    else
    {
      RECT r;
      r.left = r.top = 0;
      r.right = width;
      r.bottom = height;
      AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, 0);
      SetWindowPos(m_window, NULL, r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOMOVE | SWP_FRAMECHANGED);
      m_browser->resize(m_window);
    }
  }

  void navigate(const std::string url)
  {
    m_browser->navigate(url);
  }
  void eval(const std::string js)
  {
    m_browser->eval(js);
  }
  void init(const std::string js)
  {
    m_browser->init(js);
  }

private:
  virtual void on_message(const std::string msg) = 0;

  HWND m_window;
  POINT m_minsz = POINT{0, 0};
  POINT m_maxsz = POINT{0, 0};
  DWORD m_main_thread = GetCurrentThreadId();
  std::unique_ptr<webview::browser> m_browser = std::make_unique<webview::edge_chromium>();
};

using browser_engine = win32_edge_engine;
} // namespace webview

#endif /* WEBVIEW_GTK, WEBVIEW_COCOA, WEBVIEW_EDGE */

namespace webview {

class webview : public browser_engine {
public:
  webview(bool debug = false, void *wnd = nullptr) : browser_engine(debug, wnd)
  {
  }

  void navigate(const std::string url)
  {
    if( url == "" )
    {
      browser_engine::navigate("data:text/html," + url_encode("<html><body>Hello</body></html>"));
      return;
    }
    std::string html = html_from_uri(url);
    if( html != "" )
    {
      browser_engine::navigate("data:text/html," + url_encode(html));
    }
    else
    {
      browser_engine::navigate(url);
    }
  }

  using binding_t = std::function<void(std::string, std::string, void *)>;
  using binding_ctx_t = std::pair<binding_t *, void *>;

  using sync_binding_t = std::function<std::string(std::string)>;
  using sync_binding_ctx_t = std::pair<webview *, sync_binding_t>;

  void bind(const std::string name, sync_binding_t fn)
  {
    bind(
        name,
        [](std::string seq, std::string req, void *arg) {
          auto pair = static_cast<sync_binding_ctx_t *>(arg);
          pair->first->resolve(seq, 0, pair->second(req));
        },
        new sync_binding_ctx_t(this, fn));
  }

  void bind(const std::string name, binding_t f, void *arg)
  {
    auto js = "(function() { var name = '" + name + "';" + R"(
      var RPC = window._rpc = (window._rpc || {nextSeq: 1});
      window[name] = function() {
        var seq = RPC.nextSeq++;
        var promise = new Promise(function(resolve, reject)
        {
          RPC[seq] =
          {
            resolve: resolve,
            reject: reject,
          };
        });
        window.external.invoke(JSON.stringify(
        {
          id: seq,
          method: name,
          params: Array.prototype.slice.call(arguments),
        }));
        return promise;
      }
    })())";
    init(js);
    bindings[name] = new binding_ctx_t(new binding_t(f), arg);
  }

  void resolve(const std::string seq, int status, const std::string result)
  {
    dispatch([=]()
    {
      if( status == 0 )
      {
        eval("window._rpc[" + seq + "].resolve(" + result + "); window._rpc[" + seq + "] = undefined");
      }
      else
      {
        eval("window._rpc[" + seq + "].reject(" + result + "); window._rpc[" + seq + "] = undefined");
      }
    });
  }

private:
  void on_message(const std::string msg)
  {
    auto seq = json_parse(msg, "id", 0);
    auto name = json_parse(msg, "method", 0);
    auto args = json_parse(msg, "params", 0);
    if( bindings.find(name) == bindings.end() )
    {
      return;
    }
    auto fn = bindings[name];
    (*fn->first)(seq, args, fn->second);
  }
  std::map<std::string, binding_ctx_t *> bindings;
};
} // namespace webview

WEBVIEW_API void webview_set_userDataFolder(const char *folder)
{
  std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> wideCharConverter;
  webview::s_userDataFolder = wideCharConverter.from_bytes(folder);
}

WEBVIEW_API void webview_set_browserExecutableFolder(const char *folder)
{
  std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> wideCharConverter;
  webview::s_browserExecutableFolder = wideCharConverter.from_bytes(folder);
}

WEBVIEW_API webview_t webview_create(int debug, void *wnd)
{
  return new webview::webview(debug, wnd);
}

WEBVIEW_API int webview_get_result()
{
  return webview::s_result;
}

WEBVIEW_API void webview_destroy(webview_t w)
{
  delete static_cast<webview::webview *>(w);
}

WEBVIEW_API void webview_run(webview_t w)
{
  static_cast<webview::webview *>(w)->run();
}

WEBVIEW_API void webview_terminate(webview_t w)
{
  static_cast<webview::webview *>(w)->terminate();
}

WEBVIEW_API void webview_dispatch(webview_t w, void (*fn)(webview_t, void *), void *arg)
{
  static_cast<webview::webview *>(w)->dispatch([=]() { fn(w, arg); });
}

WEBVIEW_API void *webview_get_window(webview_t w)
{
  return static_cast<webview::webview *>(w)->window();
}

WEBVIEW_API void webview_set_title(webview_t w, const char *title)
{
  static_cast<webview::webview *>(w)->set_title(title);
}

WEBVIEW_API void webview_set_size(webview_t w, int width, int height, int hints)
{
  static_cast<webview::webview *>(w)->set_size(width, height, hints);
}

WEBVIEW_API void webview_navigate(webview_t w, const char *url)
{
  static_cast<webview::webview *>(w)->navigate(url);
}

WEBVIEW_API void webview_init(webview_t w, const char *js)
{
  static_cast<webview::webview *>(w)->init(js);
}

WEBVIEW_API void webview_eval(webview_t w, const char *js)
{
  static_cast<webview::webview *>(w)->eval(js);
}

WEBVIEW_API void webview_bind(webview_t w, const char *name, void (*fn)(const char *seq, const char *req, void *arg), void *arg)
{
  static_cast<webview::webview *>(w)->bind(
    name,
    [=](std::string seq, std::string req, void *arg)
    {
      fn(seq.c_str(), req.c_str(), arg);
    },
    arg);
}

WEBVIEW_API void webview_return(webview_t w, const char *seq, int status, const char *result)
{
  static_cast<webview::webview *>(w)->resolve(seq, status, result);
}

#endif /* WEBVIEW_HEADER */

#endif /* WEBVIEW_H */
