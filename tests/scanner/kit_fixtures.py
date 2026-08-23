"""
Synthesized bundle fixtures for the kit analyzer tests.

The positive fixture is built the way javascript-obfuscator builds one: every
string lives in a base64 string table over a rotated alphabet, and the source
reaches them through a decoder function in member-access position
(c[b(0)][b(1)][b(2)]). That shape is the point. A fixture with plaintext
identifiers would pass the tests while proving nothing, because the whole
method exists to handle the case where grepping the raw source finds nothing.

Two shapes here are deliberately awkward because the real kit is awkward the
same way. Do not "simplify" either one; both were regressions that the old
fixture hid while the real bundle failed.

  1. Socket channels are registered through a `reg(name, callback)` wrapper
     that stores into a Map, and the raw socket sees only lifecycle events.
     The real kit never calls socket.on for its own channels.
  2. The transport key and IV are bound to variables and parsed from those,
     while the storage pair is parsed straight from literals. The real kit
     mixes both forms in one file.

The values carried are the confirmed Operation Paper Rabbit signature. They are
test data here; the analyzer never hardcodes them.
"""

import base64

STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
CUS_B64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="

_ENCODE = str.maketrans(STD_B64, CUS_B64)

# Decoded string table. Index order is what the call sites below reference.
TABLE = [
    "enc",                       # 0
    "Utf8",                      # 1
    "parse",                     # 2
    "AES",                       # 3
    "encrypt",                   # 4
    "NLFRWBHXVQJTCPYK",          # 5   storage key
    "DMAGSZEIOPQUNTVC",          # 6   storage iv
    "ZQMWLSPXJRDHKTNV",          # 7   transport key
    "YFBCUENAGPQLXJWR",          # 8   transport iv
    "CBC",                       # 9
    "Pkcs7",                     # 10
    "mode",                      # 11
    "padding",                   # 12
    "MD5",                       # 13
    "setItem",                   # 14
    "t_config",                  # 15
    "/console",                  # 16
    "websocket",                 # 17
    "polling",                   # 18
    "config",                    # 19
    "operation",                 # 20
    "/index",                    # 21
    "/phoneCode",                # 22
    "/emailCode",                # 23
    "/pinCode",                  # 24
    "/appCode",                  # 25
    "/tempCustomCode",           # 26
    "/expressCvv",               # 27
    "手机验证页",                      # 28 phone verification page
    "邮箱验证页",                      # 29 email verification page
    "APP验证页",                               # 30 app verification page
    "PIN验证页",                               # 31 PIN verification page
    "自定义验证码页",          # 32 custom code page
    "运通CVV验证页",                   # 33 Amex CVV page
    "加密失败:",                           # 34 encryption failed
    "加密异常!",                           # 35 encryption exception
    "解密结果为空",                # 36 decryption result empty
    "解密失败:",                           # 37 decryption failed
    "解密异常!",                           # 38 decryption exception
    "National Insurance Number",  # 39
    "Social Security number",     # 40
    "Postcode",                   # 41
    "Zip Code",                   # 42
    "DD/MM/YYYY",                 # 43
    "MM/DD/YYYY",                 # 44
    "Definitely Headless",        # 45
    "Likely Headless",            # 46
    "HeadlessDetectorModules",    # 47
    "Waiting for approval in your bank app",               # 48
    "unattendedCountdown",        # 49
    "Restoring verification state from localStorage",      # 50
    "never store your PIN",       # 51
    "Selenium",                   # 52
    "WebDriver",                  # 53
    "PhantomJS",                  # 54
    "Puppeteer",                  # 55
    "Playwright",                 # 56
    "CDP-based automation detected (Puppeteer, Playwright, Selenium 4+)",  # 57
    "Software renderer (SwiftShader, llvmpipe) - VM or headless",          # 58
    "on",                         # 59
    "path",                       # 60
    "transports",                 # 61
    "localStorage",               # 62
    "createWebHashHistory",       # 63
    "getItem",                    # 64
    "decrypt",                    # 65
    "navigator.plugins",          # 66
    "Province",                   # 67
]


def _enc(value: str) -> str:
    """Base64 over the rotated alphabet, matching the obfuscator's encoding."""
    return base64.b64encode(value.encode("utf-8")).decode("ascii").translate(_ENCODE)


def build_obfuscated_bundle() -> str:
    """A string-obfuscated bundle carrying the full signature.

    Every identifier sits behind the decoder, so a raw grep for AES,
    localStorage or socket config finds nothing here. That is deliberate.
    """
    array = ",".join('"%s"' % _enc(v) for v in TABLE)
    return """
var _0x3f2a=[%s];
function b(i){i-=0;return _0x3f2a[i];}
(function(){
  var c=window.CryptoJS;
  var storageKey=c[b(0)][b(1)][b(2)](b(5));
  var storageIv=c[b(0)][b(1)][b(2)](b(6));
  var tk=b(7),tv=b(8);
  var transportKey=c[b(0)][b(1)][b(2)](tk);
  var transportIv=c[b(0)][b(1)][b(2)](tv);
  function encStore(v){
    return c[b(3)][b(4)](v,storageKey,{iv:storageIv,mode:c.mode[b(9)],padding:c.pad[b(10)]});
  }
  function decStore(v){
    return c[b(3)][b(65)](v,storageKey,{iv:storageIv,mode:c.mode[b(9)],padding:c.pad[b(10)]});
  }
  function encWire(v){
    return c[b(3)][b(4)](v,transportKey,{iv:transportIv,mode:c.mode[b(9)],padding:c.pad[b(10)]});
  }
  function saveConfig(cfg){
    window[b(62)][b(14)](c[b(13)](b(15)),encStore(cfg));
  }
  function loadConfig(){
    return decStore(window[b(62)][b(64)](c[b(13)](b(15))));
  }
  var socket=io(origin,{[b(60)]:b(16),[b(61)]:[b(17),b(18)]});
  socket[b(59)]("connect",function(){ready()});
  socket[b(59)]("message",function(n){dispatch(n)});
  var H=new Map;
  function reg(n,m){n&&typeof m==="function"&&H.set(n,m)}
  reg(b(19),saveConfig);
  reg(b(20),function(cmd){route(cmd);});
  var router=%s({routes:[b(21),b(22),b(23),b(24),b(25),b(26),b(27)]});
  var pages=[b(28),b(29),b(30),b(31),b(32),b(33)];
  function fail(e){console.log(b(34),e);throw new Error(b(35));}
  function failDec(e){console.log(b(36));console.log(b(37),e);throw new Error(b(38));}
  var fields=[b(39),b(40),b(41),b(42),b(43),b(44),b(67)];
  var detector={tiers:[b(45),b(46)],mod:b(47),probes:[b(52),b(53),b(54),b(55),b(56),b(66)]};
  var copy=[b(48),b(49),b(50),b(51),b(57),b(58)];
})();
""" % (array, "createWebHashHistory")


def build_clean_bundle() -> str:
    """An ordinary WooCommerce/jQuery front-end bundle. Must score NO MATCH."""
    return """
/*! jQuery v3.6.0 | (c) OpenJS Foundation | jquery.org/license */
!function(e,t){"use strict";"object"==typeof module&&"object"==typeof module.exports
?module.exports=e.document?t(e,!0):function(e){return t(e)}:t(e)}
(typeof window!=="undefined"?window:this,function(window,noGlobal){
  var wc_add_to_cart_params={ajax_url:"/wp-admin/admin-ajax.php",
    wc_ajax_url:"/?wc-ajax=%%endpoint%%",cart_url:"/cart/",is_cart:"",cart_redirect_after_add:"no"};
  var checkoutFields=["billing_first_name","billing_last_name","billing_address_1",
    "billing_city","billing_postcode","billing_country","billing_email","billing_phone"];
  function addToCart(productId,quantity){
    return jQuery.ajax({type:"POST",url:wc_add_to_cart_params.wc_ajax_url,
      data:{product_id:productId,quantity:quantity},
      success:function(response){jQuery(document.body).trigger("added_to_cart");},
      error:function(xhr){console.error("add to cart failed",xhr.status);}});
  }
  function updateCartTotals(){
    jQuery(".woocommerce-cart-form").block({message:null});
    jQuery.get(wc_add_to_cart_params.cart_url,function(html){
      jQuery(".cart_totals").replaceWith(jQuery(html).find(".cart_totals"));
    });
  }
  window.localStorage.setItem("wc_cart_hash","a1b2c3");
  window.addEventListener("load",function(){updateCartTotals();});
  return {addToCart:addToCart,updateCartTotals:updateCartTotals};
});
"""


# A minimal HTML shell in the Vite shape: near-empty body, hashed assets, and
# the kit chunk referenced by a modulepreload href rather than a script src.
SPA_SHELL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Delivery</title>
<script type="module" crossorigin src="./assets/CS7qCa7O.js"></script>
<link rel="modulepreload" crossorigin href="./assets/D2c36igU.js">
<link rel="modulepreload" crossorigin href="./assets/B3_5Glc7.js">
<link rel="stylesheet" crossorigin href="./assets/X8NV_Jr5.css">
</head><body><div id="app"></div></body></html>
"""

SERVER_RENDERED_HTML = """<!doctype html>
<html><head><title>BPI Online Banking</title></head>
<body><h1>Welcome to online banking</h1>
<p>Please sign in with your username and password to access your accounts.
Our customer service team is available 24 hours a day, seven days a week, and
you can reach us on the numbers printed on the back of your card. Remember that
we will never ask you for your one time password over the telephone.</p>
<form method="post" action="/login"><input name="user"><input name="pass">
<button>Sign in</button></form></body></html>
"""
