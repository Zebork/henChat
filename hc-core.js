// 2018.03.02: Add support of big file (slice used)
// 2018.03.05: Cookie supported; Fix bug of slice
// 2018.03.15: Add support of progress in sending slice (HTML5 only)
// 2018.03.18: Add auto-gen mode; "control-enter" support
// 2018.04.05: End-to-end encryption realized (plain text only)

var CLIENT_VER = '180405 - ETE';

var DEFAULT_SERVER = 'wss://us2.srdmobile.tk';
var SLICE_THRESHOLD = 40960;						// Data whose length(base64) over this amount will be splited
var MAX_DATALENTH = SLICE_THRESHOLD*100;			// Max data length(base64)
var MAX_TXTLENGTH = 2048;							// Max character in message

var ws;												// Websocket
var sToken;											// To certificate users' validation
var msgBox = $('#box_msg');							// Session region
var addrMap = {};									// {nickname: SHA-1}

var sliceQueue = [];								// Queen of data slice
var sendingSlice = ''								// The sign of sending slice
var sliceCounter = [0, 0];							// [numSent, numTotal]
var dataSlices = [];

var buffer = {};									// Used to receive coming slices and combine them

var enabledFileExts = ['.jpg', '.gif', '.png'];		// Supported file formate

var encryptMode = false;
var publicKeyCache = '@';
var selfPrivateKey, selfPublicKey;



function rsaEncrypt(plaintext, key) {
	var plain = base64_encode(plaintext);
	return cryptico.encrypt(plain, key).cipher;
}

function rsaDecrypt(xtext, key) {
	var detext = cryptico.decrypt(xtext, selfPrivateKey).plaintext;
	return base64_decode(detext);
}


function getCookie(key) {
	var arr, reg = new RegExp("(^| )"+key+"=([^;]*)(;|$)");
	if (arr = document.cookie.match(reg)) {
		return unescape(arr[2]);
	} else {
		return null;
	}
}


function randomStr(length, symbol=true) {
	var gen = '';
	if (symbol) {
		var charLib = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`~!@#$%^&*()_-+=|';
	} else {
		var charLib = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	}
	
	for (var i=0; i<length; i++) {
		index = Math.round(Math.random() * (charLib.length - 1));
		gen += charLib[index];
	}
	return gen;
}


function newSession(server) {

	// Connect to Web Socket
	ws = new WebSocket(server);
	// ws = new WebSocket('ws://127.0.0.1:9001');

	// Set event handlers.
	ws.onopen = function() {
		showMsg(`Server opened. Client ver: ${CLIENT_VER}`);
		document.cookie = `server=${$('#s_server').val()}`;
		document.cookie = `pvk=${$('#s_pvk').val()}`;
		var now = new Date();
		loginInfo = {
			type: 'login',
			msg: $('#s_pvk').val(),
			time: now.getTime().toString()
		}
		ws.send(JSON.stringify(loginInfo));
	};
		
	ws.onmessage = function(e) {
		// e.data contains received string.
		var getMsg = JSON.parse(e.data);
		// console.log(getMsg);

		if (getMsg.type === 'login') {
			sToken = getMsg.msg;
			$('#s_pbk').val(getMsg.to);
			console.log(`Server ver: ${getMsg.ver}\nGet token: [${sToken}]`);
			$('#btn_send').prop('disabled', false);
			$('#btn_close').prop('disabled', false);
			$('#fileSelector').prop('disabled', false);
		}

		else if (getMsg.type === 'msg') {
			// Not a key-exchange request
			if (getMsg.key != 'true') {
				if (addrMap[getMsg.from] != undefined) {
					getMsg.from = addrMap[getMsg.from];
				}
				showMsg(getMsg, "blue");

			// Key-exchange request
			} else {
				if (publicKeyCache === '@') {
					showMsg(`Get public key from<br>${getMsg.from}.`, 'gray');
					publicKeyCache = getMsg.msg;
					var now = new Date();
					var keyExchangeRequest = {
						from: $('#s_pbk').val(),
						to: [getMsg.from],
						type: 'msg',
						msg: selfPublicKey,
						key: 'true',
						token: sToken,
						time: now.getTime().toString()
					}
					ws.send(JSON.stringify(keyExchangeRequest));
					encryptMode = true;
					$('#s_to').val(getMsg.from);
					$('#s_to').prop('disabled', true);
					$('#btn_encrypt').prop('disabled', true);
					$('#fileSelector').prop('disabled', true);
					// console.log(`PBK: ${publicKeyCache}\nSELFPVK: ${selfPrivateKey}`);
					showMsg('🔒You have entered encrypt mode.', 'red');
					document.title='🔒henChat';
				}
			}
		}

		else if (getMsg.type === 'info') {
			if (getMsg.msg != '0 reciver(s) offline.') {
				showMsg(`${getMsg.msg}`, 'gray');
			}
		}

		else if (getMsg.type === 'err') {
			alert(`ERROR from server: ${getMsg.msg}`);
			ws.close();
		}

		else if (getMsg.type === 'slice') {
			var nextSlice = sliceQueue.pop();
			$(`#${sendingSlice}`).val(++sliceCounter[0] / sliceCounter[1]);
			if (nextSlice != undefined) {
				ws.send(JSON.stringify(nextSlice));
			}
		}
	};

	ws.onclose = function() {
		showMsg("Server closed.");
		$('#btn_send').prop('disabled', true);
		$('#btn_close').prop('disabled', true);
		$('#btn_enter').prop('disabled', false);
		$('#fileSelector').prop('disabled', true);
	};

	ws.onerror = function(e) {
		showMsg("Server error.", "red");
	};
}

	
function showMsg(msg, color="black") {
	// msg here is the json

	function xssAvoid(rawStr){
		return rawStr.replace(/</g, '&lt').replace(/>/g, '&gt');
	}

	var log = $('#log');
	var notice = true;

	if (typeof(msg) === 'object') {
		var now = new Date(parseInt(msg.time));

		// Not in encrypt mode or the message is from the user
		if (encryptMode === false || color === 'green') {
			var strHead = `${now.toString()}<br>[${msg.from}]<br>`;
			showText = `${strHead}<font color="${color}">${xssAvoid(msg.msg).split('\n').join('<br>')}</font><br>`;
		
		} else {
			var strHead = `${now.toString()}<br>[🔒${msg.from}]<br>`;
			showText = `${strHead}<font color="${color}">${xssAvoid(rsaDecrypt(msg.msg, selfPrivateKey)).split('\n').join('<br>')}</font><br>`;
		}

		// Message with image
		if (msg['img'] != undefined) {

			// Whole file
			if (msg['rest'] === undefined) {

				showText += `<img src="${msg.img}"><br>`;
				showText += '<br>';
				log.prepend(showText);

			// Sliced file
			} else {

				if (buffer[msg.sign] == undefined) {
					showMsg(`Receiving an image from<br>${msg.from}<br><progress id="${msg.sign}" value="${msg.size[0]/msg.size[1]}">0%</progress>`, 'gray');
					buffer[msg.sign] = msg.img;
				} else {
					buffer[msg.sign] += msg.img;
					$(`#${msg.sign}`).val(msg.size[0]/msg.size[1]);
					notice = false;
				}

				// Transfer finished
				if (msg['rest'] <= 0) {
					showText += `<img src="${buffer[msg.sign]}" width="400"><br>`;
					showText += '<br>';
					log.prepend(showText);
					delete(buffer[msg.sign]);					// Clean buffer
				}
			}

		// Plain text
		} else {
			showText += '<br>';
			log.prepend(showText);
		}

		// Show the notification
		if(document.hidden && Notification.permission === "granted" && notice) {
			var notification = new Notification('henChat', {
			body: 'New message comes!',
			});

			notification.onclick = function() {
				window.focus();
			};
		}

	} else {
		log.prepend(`<font color="${color}">${msg}<br><br></font>`);
	}
}

function fileExtCheck(fileInputLable, extNames) {
			
	var fname = fileInputLable.value;
	if (!fname) {
		return false
	}
	var fext = fname.slice(-4).toLowerCase();
	if (extNames.indexOf(fext) != -1) {
		return true;
	} else {
		return false;
	}
}

// -------- init --------
$('#btn_send').prop('disabled', true);
$('#btn_close').prop('disabled', true);
$('#btn_encrypt').prop('disabled', true);
$('#fileSelector').prop('disabled', true);

$('#s_server').val(getCookie('server'));
$('#s_pvk').val(getCookie('pvk'));

var fileSelector = document.getElementById('fileSelector');
// -----------------------

// -------- Button Events --------

$('#btn_auto').click(function () {
	$('#s_server').val(DEFAULT_SERVER);
	$('#btn_keygen').click();
	$('#btn_enter').click();
});


$('#btn_keygen').click(function () {
	$('#s_pvk').val(randomStr(64));
	showMsg('A new key will be generated. Please save it by yourself.', 'gray');
});


$('#btn_enter').click(function () {
	if ($('#s_pvk').val().length === 64) {
		var server = $('#s_server').val();
		[selfPrivateKey, selfPublicKey] = (function() {
			var selfRSA = cryptico.generateRSAKey($('#s_pvk').val(), 1024);		// And it would also be used to decrypt
			return [selfRSA, cryptico.publicKeyString(selfRSA)];				// The later is used to encrypt plain text
		})();
		newSession(server);
		$('#btn_enter').prop('disabled', true);
		$('#btn_encrypt').prop('disabled', false);
		$('#btn_send').prop('disabled', false);
		$('#fileSelector').prop('disabled', false);
	} else {
		alert('Invalid key.');
	}
});


$('#btn_encrypt').click(function () {
	$('#s_to').prop('disabled', true);
	$('#fileSelector').prop('disabled', true);
	$('#btn_encrypt').prop('disabled', true);
	$('#btn_send').prop('disabled', true);
	$('#s_to').val($('#s_to').val().split('\n')[0]);

	var now = new Date();
	var keyExchangeRequest = {
		from: $('#s_pbk').val(),
		to: [$('#s_to').val()],
		type: 'msg',
		msg: selfPublicKey,
		key: 'true',
		token: sToken,
		time: now.getTime().toString()
	}

	ws.send(JSON.stringify(keyExchangeRequest));
	while (publicKeyCache != '@');
	$('#btn_send').prop('disabled', false);

	encryptMode = true;
});


$('#btn_send').click(function () {

	if ($('#s_send').val() === '' && !fileExtCheck(fileSelector, enabledFileExts)) {
		showMsg('Cannot send empty message!', 'red');

	} else {

		// Msg infomation
		var now = new Date();
		var sendLstWithName = $('#s_to').val().split('\n');
		var sendLst = [];
		for (c of sendLstWithName) {
			if (c.indexOf('#') != -1) {
				var [nickname, addr] = c.split('#');
				sendLst.push(addr);
				addrMap[addr] = nickname;
			} else {
				sendLst.push(c);
			}
		}

		// Attachment exist
		if (fileExtCheck(fileSelector, enabledFileExts)) {
					
			var reader = new FileReader();

			reader.onload = function(e) {
				var data = e.target.result;
				var fsize = fileSelector.files[0].size;

				if (data.length > MAX_DATALENTH) {
					showMsg('File size over limit!', 'red');
					return -1;
				}

				if (data.length > SLICE_THRESHOLD) {
					// Big file(size over slice threshold)

					var cut = function (dataStr, maxSlice) {
						var sliceNum = parseInt(dataStr.length / maxSlice);
						var slices = [];
						var p = 0;
						for (var i=0; i<sliceNum+1; i++) {
							slices.push(dataStr.substring(p, p+maxSlice));
							p += maxSlice;
						}
						return slices;
					}

					dataSlices = cut(data, SLICE_THRESHOLD);
					sendingSlice = randomStr(8, false);
					sliceCounter[0] = 0;
					sliceCounter[1] = dataSlices.length
					var sentLen = 0;
					var dataLen = data.length;

					showMsg(`File sending... (${dataLen})<br><progress id="${sendingSlice}" value="0">0%</progress>`, 'gray');
					console.log(`Data has been splited into ${dataSlices.length} parts.`);

					for (var i=0; i<dataSlices.length; i++) {

						sentLen += SLICE_THRESHOLD;
						var contentWithImg = {
							from: $('#s_pbk').val(),
							to: sendLst,
							type: 'msg',
							sign: sendingSlice,
							size: [i+1, dataSlices.length],		// [sent slice, total slice number]
							rest: dataLen - sentLen,
							msg: $('#s_send').val(),
							img: dataSlices[i],
							token: sToken,
							time: now.getTime().toString()
						}
						sliceQueue.push(contentWithImg);
					}
					sliceQueue = sliceQueue.reverse();

					// Here the client just send the 1st slice and wait the response of server.
					// (Otherwise the sever would crash.)
					// Once get the response, the next slice would be able to be sent.
					// That part is written in function "ws.onmessage()"
					ws.send(JSON.stringify(sliceQueue.pop()));

				// Send small file without splitting
				} else {

					var contentWithImg = {
						from: $('#s_pbk').val(),
						to: sendLst,
						type: 'msg',
						msg: $('#s_send').val(),
						img: data,
						token: sToken,
						time: now.getTime().toString()
					}
					showMsg(contentWithImg, 'green');

					ws.send(JSON.stringify(contentWithImg));
					$('#s_send').val('');
				}

				fileSelector.value = '';
			}
			reader.readAsDataURL(fileSelector.files[0]);

		// Plain text
		} else {

			if ($('#s_send').val().length <= MAX_TXTLENGTH) {

				if (encryptMode === true) {
					var content = {
						from: $('#s_pbk').val(),
						to: sendLst,
						type: 'msg',
						// msg: cryptico.encrypt($('#s_send').val(), publicKeyCache).cipher,
						msg: rsaEncrypt($('#s_send').val(), publicKeyCache),
						token: sToken,
						time: now.getTime().toString()
					}
					var content_plain = {
						from: '🔒' + $('#s_pbk').val(),
						to: sendLst,
						type: 'msg',
						msg: $('#s_send').val(),
						token: sToken,
						time: now.getTime().toString()
					}
					showMsg(content_plain, 'green');

				} else {

					var content = {
						from: $('#s_pbk').val(),
						to: sendLst,
						type: 'msg',
						msg: $('#s_send').val(),
						token: sToken,
						time: now.getTime().toString()
					}
					showMsg(content, 'green');

				}

				ws.send(JSON.stringify(content));
				$('#s_send').val('');
			} else {
			showMsg(`Too many characters!(over ${MAX_TXTLENGTH})`, 'red');
			}
		}
	}
});
			 

$('#btn_close').click(function () {
	ws.close();
	// $('#btn_enter').prop('disabled', false);
});


// -------- Key Events --------

prevKey = '';
document.onkeydown = function (e) {
	if (e.key === 'Enter' && prevKey === 'Control') {
		$('#btn_send').click();
	}
	if (e.key != prevKey) {
		prevKey = e.key;
	}
}