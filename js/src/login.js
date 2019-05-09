import $ from 'jquery';
import * as WWPass from 'wwpass-frontend';

let urlBase = window.location.href;
urlBase = urlBase.substring(0, urlBase.lastIndexOf("/")) + '/';

$('.passhub_url').text(urlBase);

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

function isSafariPrivateMode() {
  const isSafari = navigator.userAgent.match(/Version\/([0-9\._]+).*Safari/);

  if (!isSafari || !navigator.userAgent.match(/iPhone|iPod|iPad/i)) {
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
    const x = localStorage.length;
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
  window.location.href = 'error_page.php?js=SafariPrivateMode';
}

if ((window.location.protocol !== 'https:') && (window.location.hostname !== 'localhost') && !window.location.hostname.endsWith('.localhost')) {
  window.location.href = 'notsupported.php?js=2';
} else if (!compatibleBrowser()) {
  window.location.href = 'notsupported.php?js=1';
}

WWPass.authInit({
  qrcode: document.querySelector('#qrcode'),
  passkey: document.querySelector('#button--login'),
  ticketURL: `${urlBase}getticket.php`,
  callbackURL: `${urlBase}login.php`,
});

const mobileDevice = navigator.userAgent.match(/iPhone|iPod|iPad|Android/i);

if (mobileDevice) {
  $('#qrcode').addClass('qrtap');
  $('.qr_code_instruction').html('Touch the QR code or scan it with <b>WWPass&nbsp;PassKey&nbsp;app</b>');
} else {
  $(document).ready(() => {
    setTimeout(() => {
      if (WWPass.pluginPresent()) {
        const hardwarePassKeySet = document.querySelectorAll('.hardware');
        if (hardwarePassKeySet.length) {
          [].forEach.call(hardwarePassKeySet, (it) => {
            it.classList.remove('hardware');
          });
          const infoShare = document.querySelector('.landingContent__infoShare');
          infoShare.classList.add('landingContent__infoShare--hardToken');
        }
      }
    }, 100);
  });
}
