// import $ from 'jquery';
import * as WWPass from 'wwpass-frontend';

let urlBase = window.location.href;
urlBase = `${urlBase.substring(0, urlBase.lastIndexOf('/'))}/`;

function supportsHtml5Storage() {
  try {
    return 'localStorage' in window && window.localStorage !== null;
  } catch (e) {
    return false;
  }
}

function compatibleBrowser() {
  if (!supportsHtml5Storage()) {
    return false;
  }
  if (window.msCrypto) {
    return false;
  }
  if (!window.crypto) {
    return false;
  }
  if (window.crypto.subtle || window.crypto.webkitSubtle) {
    return true;
  }
  return false;
}

const isIOS = navigator.userAgent.match(/iPhone|iPod|iPad/i)
  || (navigator.userAgent.match(/Intel Mac OS X/i) && navigator.maxTouchPoints > 1); // crazy ios13 on iPad..

const isAndroid = navigator.userAgent.match(/Android/i) ||
  (navigator.userAgent.match(/Samsung/i) && navigator.userAgent.match(/Linux/i));

const mobileDevice = isIOS || isAndroid;

function isSafariPrivateMode() {
  const isSafari = navigator.userAgent.match(/Version\/([0-9\._]+).*Safari/);

  if (!isSafari || !isIOS) {
    return false;
  }
  const version = parseInt(isSafari[1], 10);
  if (version >= 11) {
    try {
      window.openDatabase(null, null, null, null);
      return false;
    } catch (_) {
      return true;
    }
  } else if (version === 10) {
    if (localStorage.length) {
      return false;
    }
    try {
      localStorage.test = 1;
      localStorage.removeItem('test');
      return false;
    } catch (_) {
      return true;
    }
  }
  return false;
}

if (isSafariPrivateMode()) {
  if (window.location.href.includes("debug")) {
    alert('Safari private mode detected')
  } else {
    window.location.href = 'error_page.php?js=SafariPrivateMode';
  }
}

if (!navigator.userAgent.match(/electron/)) {
  if ((window.location.protocol !== 'https:')
    && (window.location.hostname !== 'localhost')
    && (window.location.hostname !== '127.0.0.1')
    && !window.location.hostname.endsWith('.localhost')) {
    window.location.href = 'notsupported.php?js=2';
  } else if (!compatibleBrowser()) {
    window.location.href = 'notsupported.php?js=1';
  }
}

function uiCallback(ev) {
  if (!ev) {
    return;
  }
  // only for legacy design, buth passhub.net and business  
  if (!document.querySelector("#qrtext")) { // new passhub.net design
    return;
  }

  // const event = JSON.stringify(ev);
  const heading_public = document.querySelector('.heading--margin-top-big');

  if (heading_public) { // passhub.net

    if ('button' in ev) {
      document.querySelector("#qrtext").style.display = "none";
      document.querySelector('.qrblock__code').classList.add('qrblock__codeExt');
      document.querySelector('.qrblock').classList.add('qrblockExt');
      document.querySelector('.heading--white-mobile').classList.add('heading--white-mobileExt');
      document.querySelector('.page-content__background').classList.remove('page-content__background--qrcode');

      /*      
            $('#qrtext').hide();
            $('.qrblock__code').addClass('qrblock__codeExt');
            $('.qrblock').addClass('qrblockExt');
            $('.heading--white-mobile').addClass('heading--white-mobileExt');
            $('.page-content__background').removeClass('page-content__background--qrcode');
      */
      document.querySelector('.heading--margin-top-big').style.marginTop = '0';
    } else if ('qrcode' in ev) {

      document.querySelector("#qrtext").style.display = "block";
      document.querySelector('.qrblock__code').classList.remove('qrblock__codeExt');
      document.querySelector('.qrblock').classList.remove('qrblockExt');
      document.querySelector('.heading--white-mobile').classList.remove('heading--white-mobileExt');
      document.querySelector('.page-content__background').classList.add('page-content__background--qrcode');

      /*      
            $('#qrtext').show();
            $('.qrblock__code').removeClass('qrblock__codeExt');
            $('.qrblock').removeClass('qrblockExt');
            $('.heading--white-mobile').removeClass('heading--white-mobileExt');
            $('.page-content__background').addClass('page-content__background--qrcode');
      */
      document.querySelector('.heading--margin-top-big').style.marginTop = '50px';
    }
  } else { // self-hosted
    if ('button' in ev) {
      document.querySelector("#qrtext").style.display = "none";
      document.querySelector(".landingContent__codeHeading").style.display = "none";
      document.querySelector(".landingContent__code-qr").classList.add('qrblockExt');
      document.querySelector(".landingContent__code-container").classList.add('landingContent__code-containerExt');
      document.querySelector(".landingContent__text").style.display = "none";
      document.querySelector('.landingContent__text').style.display = "none";


      /*
            $('#qrtext').hide();
            $(".landingContent__codeHeading").hide();
            $('.landingContent__code-qr').addClass('qrblockExt');
            $('.landingContent__code-container').addClass('landingContent__code-containerExt');
      
            $('.landingContent__text').hide();
      */
    } else if ('qrcode' in ev) {
      document.querySelector("#qrtext").style.display = "block";
      document.querySelector(".landingContent__codeHeading").style.display = "flex";
      document.querySelector(".landingContent__code-qr").classList.remove('qrblockExt');
      document.querySelector(".landingContent__code-container").classList.remove('landingContent__code-containerExt');
      document.querySelector(".landingContent__text").style.display = "block";

      /*
            $('#qrtext').show();
            $(".landingContent__codeHeading").show();
            $('.landingContent__code-container').removeClass('landingContent__code-containerExt');
            $('.landingContent__code-qr').removeClass('qrblockExt');
      
            $('.landingContent__text').show();
      */
    }
  }
}

if (mobileDevice) {
  // $('#qrcode').addClass('qrtap');
  // $('.qr_code_instruction').html('Touch the QR code or scan it with <b>WWPass&nbsp;PassKey&nbsp;app</b>');
  // document.querySelector('#qrcode').classList.add('qrtap');

  if (document.querySelector('.qr_code_instruction')) { // pre-2019
    document.querySelector('.qr_code_instruction').innerHTML = 'Tap the QR code or scan it with <b>WWPass&nbsp;Key&nbsp;app</b> to open your PAssHub vault';
  }
} else {
  //  $(document).ready(() => {
  function checkPlugin() {
    if (WWPass.pluginPresent()) {
      // pre-2019 login (legacy)
      let hardwarePassKeySet = document.querySelectorAll('.hardware');
      if (hardwarePassKeySet.length) {
        [].forEach.call(hardwarePassKeySet, (it) => {
          it.classList.remove('hardware');
        });
        const infoShare = document.querySelector('.landingContent__infoShare');
        infoShare.classList.add('landingContent__infoShare--hardToken');
        return;
      }
      // biz login
      hardwarePassKeySet = document.querySelectorAll('.landingContent__hardToken');
      if (hardwarePassKeySet.length) {
        [].forEach.call(hardwarePassKeySet, (it) => {
          it.classList.remove('landingContent__hardToken');
        });
        return;
      }
      // login 2019
      /*
      const loginBtn = document.querySelector('#button--login');
      loginBtn.classList.remove('embedded--hide');
      $('#button--login > button').hide();
      return;
      */
    }
    setTimeout(checkPlugin, 100);
  }
  setTimeout(checkPlugin, 100);
  //  });


}


// login 2019

document.addEventListener('DOMContentLoaded', () => {
  const qrtext = document.querySelector('#qrtext');
  if (qrtext) {
    if (mobileDevice) {
      // qrtext.innerText = 'Tap the QR code or ';
      qrtext.innerHTML = 'Download <b>WWPass&nbsp;Key&nbsp;App</b> and scan&nbsp;or&nbsp;tap the QR&nbsp;code';
    } else {
      qrtext.innerHTML = 'Scan the QR code with WWPass™ Key App';
      // qrtext.classList.add('text--qrcode');
    }
    qrtext.style.display = 'block';
  }

  WWPass.authInit({
    qrcode: '#qrcode',
    mobileLoginExtraButtons: document.querySelectorAll(".signin-mobile"),
    passkey: document.querySelector('#button--login'),
    ticketURL: `${urlBase}getticket.php`,
    callbackURL: `${urlBase}login.php`,
    uiCallback,
    forcePasskeyButton: false,
    universal: true,
    fastForward: true,
  });
});
