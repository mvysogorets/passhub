import $ from 'jquery';
import forge from 'node-forge';
import { modalAjaxError } from './utils';
import state from './state';
import passhub from './passhub';
import passhubCrypto from './crypto';
import 'jquery-contextmenu';

let safeUsersUpdatePageReq = false;

function showUsers(result) {
  $('#UserList').empty();
  if (result.status === 'Ok') {
    if (result.update_page_req) {
      safeUsersUpdatePageReq = true;
    }
    const ul = result.UserList;
    if (ul.length === 0) {
      $('#UserList').append($('<li>').append('Safe not shared'));
      // error actually
    } else {
      const myselfIdx = ul.findIndex(element => element.myself);
      if (myselfIdx < 0) {
        // error
      }
      let li;
      if (!ul[myselfIdx].name) {
        li = '<div style="margin:12px 0;"><span class="vault_user_name"><b>You (unnamed)</b></span>';
      } else {
        li = `<div style="margin:12px 0;"><span class="vault_user_name"><b>${ul[myselfIdx].name}</b> (you)</span>`;
      }
      const role = (ul[myselfIdx].role === 'administrator') ? 'owner' : ul[myselfIdx].role;
      if (role === 'owner') {
        $('#unsubscribe').hide();
      } else {
        $('#unsubscribe').show();
      }
      li += `<span style='float:right; width: 10em; text-align: right;'><b>${role}</b?</span></div>`;
      
      $('#UserList').append(li);
      for (let i = 0; i < ul.length; i++) {
        if (i === myselfIdx) {
          continue;
        }
        const role = (ul[i].role === 'administrator') ? 'owner' : ul[i].role;
        if (ul[myselfIdx].role === 'administrator') {
          li = `<div style="margin:12px 0;"><span class="vault_user_name">${ul[i].name}</span>`;
          li += '<div style="float:right">';
          if (ul[i].status == 0) {
//            li += '<button class="btn btn-default btn-sm confirm_vault_user">Confirm</button>';
            li += '<span class="confirm_vault_user">Confirm</span>';
          } else {
            li += "<span class = 'role_selector dropdown-toggle'>"
            + `${role}</span>`;
          }
          li += "<span class = 'del_user'>"
             + "Delete</span>";
          /*
          li += '<button class="btn btn-default btn-sm delete_vault_user" style="font-size:16px;">Delete</button>';
          */
          li += '</div>';

          li += '</div>';
        } else {
          li = `<div style="margin:12px 0;"><span class="vault_user_name">${ul[i].name}</span>`;
          li += `<span style='float:right; width: 10em; text-align: right;'>${role} </span></div>`;
        }
        $('#UserList').append(li);
      }
//      $.contextMenu(roleMenu);
    }
    return;
  }
  if (result.status === 'login') {
    window.location.href = 'expired.php';
    return;
  }
  $('#safe_users_alert').text(result.status).show();
}

function setRole(elm, role) {
  if (elm[0].classList.contains('add-user')) { // role_selector in Share_by_mail modal
    elm[0].innerText = (role === 'administrator') ? 'owner' : role;
    return;
  }
  $.ajax({
    url: 'safe_acl.php',
    method: 'POST',
    data: {
      verifier: state.csrf,
      vault: state.currentSafe.id,
      operation: 'role',
      name: elm.parent().parent().find('.vault_user_name')[0].innerText,
      role,
    },
    success: showUsers,
    error: (hdr, status, err) => {
      modalAjaxError($('#safe_users_alert'), hdr, status, err);
    },
  });
}

const roleMenu = {
  selector: '.role_selector',
  trigger: 'left',
  delay: 100,
  autoHide: true,
  items: {
    administrator: {
      name: 'owner',
      callback: function () {
        setRole($(this), 'administrator');
      },
    },
    readwrite: {
      name: 'editor',
      callback: function () {
        setRole($(this), 'editor');
      },
    },
    readonly: {
      name: 'readonly',
      callback: function () {
        setRole($(this), 'readonly');
      },
    },
  },
};

$.contextMenu(roleMenu);


function confirmUserFinalize(username, eAesKey) {
  $.ajax({
    url: 'safe_acl.php',
    method: 'POST',
    data: {
      verifier: state.csrf,
      vault: state.currentSafe.id,
      operation: 'confirm',
      name: username,
      key: eAesKey,
    },
    success: showUsers,
    error: (hdr, status, err) => {
      modalAjaxError($('#safe_users_alert'), hdr, status, err);
    },
  });
}

// 'confirm user' button functionality
$('#UserList').on('click', '.confirm_vault_user', function () {
  const x = $(this).parent().parent().find('span');
  const name = x[0].innerText;
  $.ajax({
    url: 'safe_acl.php',
    method: 'POST',
    data: {
      verifier: state.csrf,
      vault: state.currentSafe.id,
      operation: 'get_public_key',
      name,
    },
    error: (hdr, status, err) => {
      modalAjaxError($('#safe_users_alert'), hdr, status, err);
    },
    success: (result) => {
      if (result.status === 'Ok') {
        return passhubCrypto.decryptAesKey(result.my_encrypted_aes_key)
          .then((aesKey) => {
            const peerPublicKey = forge.pki.publicKeyFromPem(result.public_key);
            const peerEncryptedAesKey = peerPublicKey.encrypt(aesKey, 'RSA-OAEP');
            const hexPeerEncryptedAesKey = forge.util.bytesToHex(peerEncryptedAesKey);
            confirmUserFinalize(name, hexPeerEncryptedAesKey);
          });
      }
      if (result.status === 'login') {
        window.location.href = 'expired.php';
        return;
      }
      $('#safe_users_alert').text(result.status).show();
    },
  });
});

$('#safeUsers').on('show.bs.modal', () => {
  $('#safeUsersLabel').find('span').text(state.currentSafe.name);
  $('#UserList').empty();
  safeUsersUpdatePageReq = false;
  $.ajax({
    url: 'safe_acl.php',
    method: 'POST',
    data: {
      verifier: state.csrf,
      vault: state.currentSafe.id,
    },
    success: showUsers,
    error: (hdr, status, err) => {
      modalAjaxError($('#safe_users_alert'), hdr, status, err);
    },
  });
  $('#safe_users_alert').text('').hide();
});

$('#safeUsers').on('hidden.bs.modal', () => {
  if (safeUsersUpdatePageReq) {
    window.location.href = `index.php?vault=${state.currentSafe.id}`;
  }
});

// 'delete user' button functionality
$('#UserList').on('click', '.del_user', function () {
  const x = $(this).parent().parent().find('span');
  $.ajax({
    url: 'safe_acl.php',
    method: 'POST',
    data: {
      verifier: state.csrf,
      vault: state.currentSafe.id,
      operation: 'delete',
      name: x[0].innerText,
    },
    success: (result) => {
      showUsers(result);
      passhub.refreshUserData();
    },
    error: (hdr, status, err) => {
      modalAjaxError($('#safe_users_alert'), hdr, status, err);
    },
  });
});

$('#unsubscribe').click(function () {
  $.ajax({
    url: 'safe_acl.php',
    method: 'POST',
    data: {
      verifier: state.csrf,
      vault: state.currentSafe.id,
      operation: 'unsubscribe',
    },
    success: (result) => {
      $('SafeUsers').modal('toggle'); 
      passhub.refreshUserData();
    },
    error: (hdr, status, err) => {
      modalAjaxError($('#safe_users_alert'), hdr, status, err);
    },
  });
});
