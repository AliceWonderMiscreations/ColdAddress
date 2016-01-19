<?php
// requires php-bcmath php-gmp and php-xml modules

// salt.inc.php is a configuration file
require_once('salt.inc.php');

/*
 * NOTHING BELOW SHOULD BE MODIFIED
 *
 */
 
$donation = '1DREo6Ctfep7Ao7stDuaH9xbemdd5bG7mK';
$github = 'https://github.com/AliceWonderMiscreations/ColdAddress';
 
$dom = new DOMDocument("1.0", "UTF-8");
$dom->formatOutput = TRUE;
$docstring = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE html><html><head><title>Smart Cold Address Generator</title></head><body /></html>';
$dom->loadXML($docstring);
$body = $dom->getElementsByTagName('body')->item(0);

$footer = $dom->createElement('footer');
$footer->setAttribute('id', 'footer');
$footer->setAttribute('style', 'background-color: black; color: white; text-align: center; padding: 1em;');
$p = $dom->createElement('p', 'The author of this software and documentation is not a trained or licensed financial advisor.');
$footer->appendChild($p);
$p = $dom->createElement('p', 'Use of Bitcoin and this software are at your own risk.');
$footer->appendChild($p);
$p = $dom->createElement('p', 'If you find this useful, bitcoin donations of any amount are appreciated:');
$br = $dom->createElement('br');
$a = $dom->createElement('a', $donation);
$a->setAttribute('href', 'bitcoin:1KutggwB8VLGKTx7mgxrfiJusWCx2CWtFW');
$p->appendChild($br);
$p->appendChild($a);
$footer->appendChild($p);
$p = $dom->createElement('p', 'If you use this instead of a Trezor, I just saved you $99.00 USD.');
$br = $dom->createElement('br');
$p->appendChild($br);
$text = $dom->createTextNode('5 mBTC (.005 BTC) is the suggested gratitude. But only if you really find this useful.');
$p->appendChild($text);
$footer->appendChild($p);


if(! isset($salt)) {
  $salt='';
}
if(strlen($salt) == 0) {
  $salt='7mgxrfiJTFfV9rfJCecczX18MGV1Wyfd6FJ761eAHfDFqAZSFubtkNzpuNqk2X23FzvSk7mKtdTxxbeUA8cdR26ugkSKfbPhHV5VbNW8AnqKR';
}

if(! isset($showdoc)) {
  $showdoc = TRUE;
}

$TEST = TRUE; // we do not yet have valid passphrase, trigger test mode
// Do not change ECDSA below, it verifies functions work when page first loads
$ECDSA = '18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725';
$ERROR = '';

// https://github.com/phpecc/phpecc - my copies of files below are from an older release than current
require_once('gmp_Utils.php');
require_once('CurveFpInterface.php');
require_once('CurveFp.php');
require_once('NumberTheory.php');
require_once('PointInterface.php');
require_once('Point.php');
require_once('PublicKeyInterface.php');
require_once('PublicKey.php');
define('USE_EXT', 'GMP');
define('MAX_BASE', 256);

$secp256k1 = new CurveFp(
    '115792089237316195423570985008687907853269984665640564039457584007908834671663',
    '0', '7');
$secp256k1_G = new Point($secp256k1,
    '55066263022277343669578718895168534326250603453777594175500187360389116729240',
    '32670510020758816978083085130507043184471273380659243275938904335757337482424',
    '115792089237316195423570985008687907852837564279074904382605163141518161494337');

if(isset($_POST['passphrase'])) {
  $passphrase = trim($_POST['passphrase']);
  $passphrase = preg_replace('/\s+/', ' ', $passphrase);
}

if(strlen($salt) < 96) {
  print('The salt must be at least 96 characters.');
  exit;
}

$test = array_unique(str_split($salt));
if(count($test) < 28) {
  print('The salt must have at least 28 unique characters in it.');
  exit;
}

// hash the salt twice to enlarge it
$salt .= strtoupper(hash('sha256', $salt));
$salt = strtoupper(hash('ripemd320', $salt)) . $salt;

$scheck = strtoupper(md5($salt));

if(isset($passphrase)) {
  $found = FALSE;
  $ntest = count(explode(' ', $passphrase));
  if($ntest < 6) {
    $ERROR = 'Pass phrase should contain at least six words.';
  } else {
    $TEST = FALSE; // we have a valid passphrase, this is not a test
    while(! $found) {
      $string = $salt . $passphrase;
      $salt2 = strtoupper(hash('ripemd320', $string));
      $string .= $salt2;
      $ECDSA = strtoupper(hash('sha256', $string));
      // must be <= $max to be valid ECDSA secp256k1
      $max = 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551';
      if(strcmp($ECDSA, $max) <= 0) {
        $found = TRUE;
      } else {
        $passphrase .= $ECDSA;
      }
    }
  }
}

function privkey2pubkey($ECDSA, $secp256k1_G) {
  // this is function that needs the phpecc stuff - rewrite when binary module available
  $privKey = gmp_Utils::gmp_hexdec($ECDSA);
  $pubKey = new PublicKey($secp256k1_G, Point::mul($privKey, $secp256k1_G));
  $xcoord = strtoupper(gmp_Utils::gmp_dechex($pubKey->getPoint()->getX()));
  $xcoord = str_pad($xcoord, 64, '0', STR_PAD_LEFT);
  $ycoord = strtoupper(gmp_Utils::gmp_dechex($pubKey->getPoint()->getY()));
  $ycoord = str_pad($ycoord, 64, '0', STR_PAD_LEFT);
  return('04' . $xcoord . $ycoord);
}

function pubkeyTo25byte($string) {
  $PUBKEY = hex2bin(strtoupper($string));
  $STEP1 = hash('sha256', $PUBKEY, true);
  $return = '00' . strtoupper(hash('ripemd160', $STEP1));
  $STEP2 = hex2bin($return);
  $STEP3 = hash('sha256', $STEP2, true);
  $STEP4 = substr(strtoupper(hash('sha256', $STEP3)), 0, 8);
  $return .= $STEP4;
  return $return;
}

function decodeHex($hex) {
  $hex=strtoupper($hex);
  $chars="0123456789ABCDEF";
  $return="0";
  for($i=0;$i<strlen($hex);$i++) {
    $current=(string)strpos($chars,$hex[$i]);
    $return=(string)bcmul($return,"16",0);
    $return=(string)bcadd($return,$current,0);
  }
  return $return;
}

function encodeBase58($hex) {
  $orighex=$hex;
  $chars="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  $hex=decodeHex($hex);
  $return="";
  while (bccomp($hex,0)==1) {
    $dv=(string)bcdiv($hex,"58",0);
    $rem=(integer)bcmod($hex,"58");
    $hex=$dv;
    $return=$return.$chars[$rem];
  }
  $return=strrev($return);
  //leading zeros
  for($i=0;$i<strlen($orighex)&&substr($orighex,$i,2)=="00";$i+=2) {
    $return="1".$return;
    }
  return $return;
}

function WIF($ECDSA) {
  $KEY = '80' . $ECDSA;
  $hash = hash('sha256', hex2bin($KEY), true);
  $CHK = substr(strtoupper(hash('sha256', $hash)), 0, 8);
  $KEY .= $CHK;
  return encodeBase58($KEY);
}

$PUBKEY = privkey2pubkey($ECDSA, $secp256k1_G);

$WIF = WIF($ECDSA);

$ADDRESS = pubkeyTo25byte($PUBKEY);

$BASE58 = encodeBase58($ADDRESS);

if($TEST) {
  // Do not change tstring below, it verifies functions work when page first loads
  $tstring = '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM';
  if(strcmp($tstring, $BASE58) != 0) {
    $ERROR = 'Address generation is broken';
    $BROKEN = TRUE;
  }
}



$article = $dom->createElement('article');
$article->setAttribute('style', 'max-width: 80%; margin: auto;');
$body->appendChild($article);
if(strlen($ERROR) > 0) {
  $h = $dom->createElement('h1', $ERROR);
  $article->appendChild($h);
  $hr = $dom->createElement('hr');
  $article->appendChild($hr);
}
if(! isset($BROKEN)) {
  $h = $dom->createElement('h1', 'Generate Salted Cold Private ECDSA Key and Public Address');
  $article->appendChild($h);
  if(strcmp($scheck, '8E7892895367F84DB7A8B2668EC60CC3') == 0) {
    $showdoc = TRUE;
    $section = $dom->createElement('section');
    $article->appendChild($section);
    $h = $dom->createElement('h2', 'Warning');
    $h->setAttribute('style', 'color: red;');
    $section->appendChild($h);
    $p = $dom->createElement('p', 'The salt value currently being used is not secret. This is a demonstration. Do not use addresses generated by this demonstration, they may not be secure. Please see the ');
    $a = $dom->createElement('a', 'documentation');
    $a->setAttribute('href', '#documentation');
    $p->appendChild($a);
    $text = $dom->createTextNode(' at the bottom of this page.');
    $p->appendChild($text);
    $p->setAttribute('style', 'color: red; font-size: 1.3em;');
    $section->appendChild($p);
  }
  $section = $dom->createElement('section');
  $article->appendChild($section);
  $form = $dom->createElement('form');
  $section->appendChild($form);
  $form->setAttribute('method', 'post');
  $label = $dom->createElement('label', 'Passphrase:');
  $label->setAttribute('for', 'passphrase');
  $form->appendChild($label);
  $br = $dom->createElement('br');
  $form->appendChild($br);
  $input = $dom->createElement('input');
  $input->setAttribute('type', 'text');
  $input->setAttribute('id', 'passphrase');
  $input->setAttribute('name', 'passphrase');
  $input->setAttribute('autocomplete', 'off');
  $input->setAttribute('autofocus', 'autofocus');
  $input->setAttribute('style', 'width: 95%;');
  $form->appendChild($input);
  $br = $dom->createElement('br');
  $form->appendChild($br);
  $input = $dom->createElement('input');
  $input->setAttribute('type', 'submit');
  $input->setAttribute('value', 'Submit');
  $form->appendChild($input);
  
  if(! $TEST) {
    $passphrase = preg_replace('/&/', '&amp;', $passphrase);
    $section = $dom->createElement('section');
    $article->appendChild($section);
    $h = $dom->createElement('h2', 'Crypto Values for: ');
    $section->appendChild($h);
    $span = $dom->createElement('span', $passphrase);
    $span->setAttribute('style', 'font-family: monospace; font-size: 2em; background-color: MistyRose;');
    $h->appendChild($span);
    
    $dl = $dom->createElement('dl');
    $dl->setAttribute('style', 'font-size: 1.6em;');
    $section->appendChild($dl);
    
    $dt = $dom->createElement('dt', '32-byte Hexadecimal ECDSA Private Key:');
    $dl->appendChild($dt);
    $dd = $dom->createElement('dd');
    $dd->setAttribute('style', 'font-size: 1.6em; padding: 0.1em 0 0.4em 0;');
    $dl->appendChild($dd);
    $code = $dom->createElement('code', $ECDSA);
    $dd->appendChild($code);
    
    $dt = $dom->createElement('dt', 'ECDSA Private Key in Wallet Import Format:');
    $dl->appendChild($dt);
    $dd = $dom->createElement('dd');
    $dd->setAttribute('style', 'background-color: LightGoldenRodYellow; font-size: 1.6em; padding: 0.1em 0 0.4em 0;');
    $dl->appendChild($dd);
    $code = $dom->createElement('code', $WIF);
    $dd->appendChild($code);
    
    $dt = $dom->createElement('dt', '25-byte Hexadecimal Bitcoin Address:');
    $dl->appendChild($dt);
    $dd = $dom->createElement('dd');
    $dd->setAttribute('style', 'font-size: 1.6em; padding: 0.1em 0 0.4em 0;');
    $dl->appendChild($dd);
    $code = $dom->createElement('code', $ADDRESS);
    $dd->appendChild($code);
    
    $dt = $dom->createElement('dt', 'Base58 Check Encoding Address:');
    $dl->appendChild($dt);
    $dd = $dom->createElement('dd');
    $dd->setAttribute('style', 'background-color: yellow; font-size: 1.6em; padding: 0.1em 0 0.4em 0;');
    $dl->appendChild($dd);
    $code = $dom->createElement('code', $BASE58);
    $dd->appendChild($code);
  }
}

// Documentation

if($showdoc) {

$hr = $dom->createElement('hr');
$article->appendChild($hr);

$section = $dom->createElement('section');
$section->setAttribute('id', 'documentation');
$section->setAttribute('style', 'max-width: 70%; font-size: 1.4em; text-align: justify;');
$article->appendChild($section);
$h = $dom->createElement('h2', 'Documentation');
$section->appendChild($h);

$p = $dom->createElement('p', 'Ignorance is bliss. It is also dangerous.');
$section->appendChild($p);

$details = $dom->createElement('details');
$section->appendChild($details);
$summary = $dom->createElement('summary', 'Table of Contents');
$details->appendChild($summary);
$toc = $dom->createElement('ol');
$details->appendChild($toc);

$subsection = $dom->createElement('section');
$subsection->setAttribute('id', 'basics');
$section->appendChild($subsection);
$h = $dom->createElement('h3', 'Basic Concepts of Bitcoin');
$subsection->appendChild($h);

$li = $dom->createElement('li');
$a = $dom->createElement('a', 'Basic Concepts of Bitcoin');
$a->setAttribute('href', '#basics');
$li->appendChild($a);
$toc->appendChild($li);

$p = $dom->createElement('p', 'Bitcoin is a new novel type of currency based upon public / private key cryptography. This is why it is often referred to as a crypto-currency.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Traditional currency is based upon cash, physical tokens that represent value. Cash has value because only the government is allowed to create it, and the government only creates a limited supply of it. Typically governments want a small amount of inflation in order to encourage spending, but sometimes governments mint too much cash resulting in hyper-inflation.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'With cash, each token has a fixed value. The spending power of that value changes over time but the cash value does not. A U.S. quarter minted in 1969 represented 25 cents USD when it was minted. It represents 25 cents USD today.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'With cash, possession of the physical tokens itself is proof that you have the right to spend it. Holding lots of cash is dangerous because if someone steals it, you no longer have the right to spend it. If you can find out who stole it, you may be able to use law enforcement to get it back, but the right to spend it belongs with whoever has possession of it.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'This is why we put money in the bank. The bank keeps the money safe for us, and gives us the ability to spend the value we have in the bank without actually needing to handle the cash itself.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'The bank keeps track of how much value we have, and when we want to spend value, our identity is used to prove we have the right to spend it. This is why so-called identity theft is so rampant. If I am able to get enough information about you, I may be able to convince the bank that I am you and spend the value that belongs to you.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Bitcoin does not have the equivalent of cash. I sometimes like to refer to Bitcoin as ‘Cash for the Internet’ and the anonymous inventor of Bitcoin referred to it as ‘digital cash’ but it actually is a very different concept. With Bitcoin, when we spend it what we are actually spending is previous transactions. Cryptography is used to prove we have the right to spend value from a previous transaction and cryptography is used to specify who has the right to spend value from the transaction we are creating.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Bitcoin itself also does not have the concept of banks. There are web-wallet companies that to some extent perform a similar concept, but they too are really quite different. One big difference is that these web-wallet companies do not have any kind of FDIC or similar insurance that protects the depositor from loss of value if the web-wallet company is compromised and value stolen.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Bitcoin operates completely on the concept of balanced transactions in a public ledger called the ');
$a = $dom->createElement('a', 'block chain');
$a->setAttribute('href', 'https://en.bitcoin.it/wiki/Block_chain');
$a->setAttribute('target', '_blank');
$a->setAttribute('title', '[Opens new window]');
$p->appendChild($a);
$text = $dom->createTextNode(' that is maintained by a peer-to-peer network.');
$p->appendChild($text);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'A Bitcoin ‘address’ only has value when there are transactions in that block chain that sent value to that address. There are no bank accounts associated with an address. There is no identity associated with an address.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'To spend the value associated with a particular Bitcoin address, you must know the cryptographic private key that is associated with that address.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Bitcoin does not give a damn about your identity. It does not give a damn who the value is being sent to. It really only cares about three things:');
$subsection->appendChild($p);

$list = $dom->createElement('ol');
$subsection->appendChild($list);
$item = $dom->createElement('li', 'The transaction is balanced. The value of all inputs is equal to the value of all outputs plus the transaction fee.');
$list->appendChild($item);
$item = $dom->createElement('li', 'None of the transaction value used as inputs have already been used as inputs in any other transaction.');
$list->appendChild($item);
$item = $dom->createElement('li', 'The transaction is signed using the private ECDSA key(s) associated with all the transaction value used as inputs.');
$list->appendChild($item);

$p = $dom->createElement('p', 'If those requirements are met, the transaction will end up in the block chain and once it is in the block chain, it can not be reversed.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'The security of your Bitcoin value is completely dependent upon keeping the private ECDSA keys associated with your value private.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Just like the possession of cash gives you the right to spend it, the possession of a private ECDSA key gives you the right spend any transactions sent to the address associated with that key.');
$subsection->appendChild($p);

$subsection = $dom->createElement('section');
$subsection->setAttribute('id', 'webwallet');
$section->appendChild($subsection);
$h = $dom->createElement('h3', 'Web Wallets');
$subsection->appendChild($h);

$li = $dom->createElement('li');
$a = $dom->createElement('a', 'Web Wallets');
$a->setAttribute('href', '#webwallet');
$li->appendChild($a);
$toc->appendChild($li);

$p = $dom->createElement('p', 'Web Wallets function in a similar way to banks in the respect that you deposit Bitcoin value with them. They also frequently act as an exchange where you can purchase Bitcoin value with another currency.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'It is very important to note that with a web wallet, you have no control over the actual Bitcoin value. You have to trust that the company actually has enough value to cover all the Bitcoin value that has been deposited with them.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Unfortunately, there have been many cases where web wallet companies have either been scams or have had weak security resulting in hackers stealing much of the Bitcoin value they have. Ultimately it is the customers that lose when they no longer have the Bitcoin value needed to cover what has been deposited with them.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'It is difficult to use Bitcoin without a web wallet account. Generally when you purchase Bitcoins, they are initially in a web wallet account. When you sell Bitcoins, generally you first need to deposit the coins in a web wallet account. You can however limit your risk by not keeping very much in a web wallet.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Transfer Bitcoin value out of a web wallet account after a purchase to an address where you control the private ECDSA key, and when you sell Bitcoins, do not transfer them into the web wallet until shortly before you are ready to sell them.');
$subsection->appendChild($p);

$subsection = $dom->createElement('section');
$subsection->setAttribute('id', 'softwarewallet');
$section->appendChild($subsection);
$h = $dom->createElement('h3', 'Software Wallets');
$subsection->appendChild($h);

$li = $dom->createElement('li');
$a = $dom->createElement('a', 'Software Wallets');
$a->setAttribute('href', '#softwarewallet');
$li->appendChild($a);
$toc->appendChild($li);

$p = $dom->createElement('p', 'With a software wallet, your private ECDSA keys are stored in a database on your local computing device and are managed by the software application.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'This gives you control over your Bitcoin value, but it also brings some dangers with it.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'If malware or a hacker gains access to your computing device, it is possible for them to gain access to your private ECDSA keys. You can (and should) get some protection by encrypting the wallet, but there is still a risk. The wallet has to decrypted when it is used, which can result in the reading of your private keys from memory or the recording of the keystrokes needed to decrypt the wallet.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'A software wallet should be viewed in a similar manner as a checking account. Keep enough value in it to comfortably meet your spending needs, but do not keep large amounts you are not intending to sell or spend in your software wallet. Private ECDSA keys that are not in your software wallet are not vulnerable to compromise if the contents of your software wallet are stolen.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'You also should have a ‘Cold Address’ (described below) that you can send all your value to in the event that you believe your computing device may have been compromised by malware or a hacker. That will allow you to restore your operating system, re-install your wallet software, and then import the private key associated with the cold address restoring your value to your software client.');
$subsection->appendChild($p);

$subsection = $dom->createElement('section');
$subsection->setAttribute('id', 'hardwarewallet');
$section->appendChild($subsection);
$h = $dom->createElement('h3', 'Hardware Wallets');
$subsection->appendChild($h);

$li = $dom->createElement('li');
$a = $dom->createElement('a', 'Hardware Wallets');
$a->setAttribute('href', '#hardwarewallet');
$li->appendChild($a);
$toc->appendChild($li);

$p = $dom->createElement('p', 'With a hardware wallet, your private ECDSA keys are stored on a hardware device.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'When you want to spend value associated with the keys on the hardware wallet, the hardware wallet must be connected to your computing device and you need to enter an authentication code onto the hardware wallet itself.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'The intended bitcoin transaction is created on your computing device and then passed to the hardware wallet to be signed. The signed transaction is returned so it can be sent out to the Bitcoin network. The private ECDSA key itself thus is never exposed.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'If the design is good and implemented correctly, they are extremely secure.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'If you are not technically inclined and have no desire to become so, a hardware wallet is the solution I recommend for the long term storage of Bitcoin value. That being said, I will not use them.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Using a hardware wallet is quite cumbersome. Every single transaction has to be approved on the device itself, entering your authentication code onto a very small screen with only a couple buttons available. This makes them unsuitable for normal Bitcoin spending.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Where they have value is in storing Bitcoin value that you will not likely need to access for some time. They should be viewed as serving a similar function to a savings account.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'I personally do not like them for several reasons.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'First of all, the interface is really small and difficult to use. To enter your authentication code, you have to use arrow keys to navigate a really small screen to select numbers on the screen. The order of the numbers on the screen constantly changes. Some people may be fine with that, but I find it extremely difficult. My eyes are not very good and I rely upon muscle memory to compensate. This results in frequent mis-entry of the authentication code and then for security reasons, the device makes you wait before you are allowed to try again. If you make a mistake more than once, the wait is even longer.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Secondly, you are required to use software compatible with the hardware wallet. This software is not packaged in a software repository for my operating system. This means that if I install it, it will not be updated through the normal mechanism I use to update my operating system.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'That is not a big deal for people who use Windows, they are use to needing to update many of their application individually. But for me, well, I have been spoiled by over a decade of Linux use where I can run a single command and update both the operating system and all applications at once. It is really nice, I really do not want to go back to the dark ages for anything and I especially do not want financial related software to be outside this update process.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Both of those issues are really just minor inconveniences. The biggest issue for me actually is recovery in the event of hardware failure.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'In the event of hardware failure or the device becomes lost, I have to use a ');
$a = $dom->createElement('a', 'BIP 0039');
$a->setAttribute('href', 'https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki');
$a->setAttribute('target', '_blank');
$a->setAttribute('title', '[Opens new window]');
$p->appendChild($a);
$text = $dom->createTextNode(' capable software wallet to recover the private ECDSA keys needed to spend the value on the device.');
$p->appendChild($text);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'It is absolutely fantastic that this is possible, but once it happens, it means all value that was stored on the hardware wallet is now exposed in the software wallet until I am able to acquire a replacement hardware wallet. That is too risky for me, I am not a very wealthy person and simply can not afford to potentially lose that value to a hacker or malware who compromises my system during the period of time while I am waiting for a replacement device to arrive.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'That risk can be reduced by waiting for the replacement to arrive before recovering, but if I need the value I need the value, and I may need the value just to be able to afford the replacement device.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Finally these devices are powered by USB and use a ');
$abbr = $dom->createElement('abbr', 'pRNG');
$abbr->setAttribute('title', 'pseudo Random Number Generator');
$p->appendChild($abbr);
$text = $dom->createTextNode(' as part of the process in generating the seed ECDSA key that is then itself used to generate all the private ECDSA keys the device will use.');
$p->appendChild($text);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'It is possible their ');
$abbr = $dom->createElement('abbr', 'pRNG');
$p->appendChild($abbr);
$text = $dom->createTextNode(' is fine, but there have just been way too many cases where low powered devices did not have enough entropy to properly generate random numbers, resulting in predictability of the results. That is extremely risky when generating a key for a deterministic wallet as you could lose everything with no recourse to get it back.');
$p->appendChild($text);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'It is easy to create a flawed ');
$abbr = $dom->createElement('abbr', 'pRNG');
$p->appendChild($abbr);
$text = $dom->createTextNode(', even ');
$p->appendChild($text);
$a = $dom->createElement('a', 'Google');
$a->setAttribute('href', 'http://www.securitytracker.com/id/1028916');
$a->setAttribute('target', '_blank');
$a->setAttribute('title', '[Opens new window]');
$p->appendChild($a);
$text = $dom->createTextNode(' got it wrong, resulting in some stolen value from Bitcoin wallets for Android.');
$p->appendChild($text);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'I can not speak for every hardware wallet, but I do think it is unlikely that the ');
$abbr = $dom->createElement('abbr', 'pRNG');
$p->appendChild($abbr);
$text = $dom->createTextNode(' in the Trezor is flawed. My guess is that it is safe.');
$p->appendChild($text);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Still, since I have the technical aptitude to program and use a salted pass phrase based cold address where a ');
$abbr = $dom->createElement('abbr', 'pRNG');
$p->appendChild($abbr);
$text = $dom->createTextNode(' does not even enter into the equation, for me that is the safer approach. That is the approach I am sharing here.');
$p->appendChild($text);
$subsection->appendChild($p);



$subsection = $dom->createElement('section');
$subsection->setAttribute('id', 'cold');
$section->appendChild($subsection);
$h = $dom->createElement('h3', 'Cold Address');
$subsection->appendChild($h);

$li = $dom->createElement('li');
$a = $dom->createElement('a', 'Cold Address');
$a->setAttribute('href', '#cold');
$li->appendChild($a);
$toc->appendChild($li);

$p = $dom->createElement('p', 'A cold address is a Bitcoin address where the private ECDSA key needed to spend any value associated with the address is not stored in a digital wallet.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'The private key can not be stolen by a hacker or by malware if it does not exist as digital data to be stolen.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'When you want to spend value associated with a cold address, you need to import the private ECDSA key into a proper wallet so that it can be used to sign the transaction. At that point it ceases to be a cold address.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Like a hardware wallet, a Cold Address should be used in a similar fashion as a savings account. They are used to safely store value that you do not intend to spend for some time.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'There are two types of cold addresses that are commonly in use:');
$subsection->appendChild($p);

$list = $dom->createElement('ul');
$subsection->appendChild($list);

$item = $dom->createElement('li', 'Paper Wallet');
$list->appendChild($item);
$item = $dom->createElement('li', 'Pass Phrase');
$list->appendChild($item);

$ctoc = $dom->createElement('ul');
$toc->appendChild($ctoc);

$csubsection = $dom->createElement('section');
$csubsection->setAttribute('id', 'paper');
$csubsection->setAttribute('style', 'margin-left: 1em;');
$subsection->appendChild($csubsection);
$h = $dom->createElement('h4', 'Paper Wallet');
$csubsection->appendChild($h);

$li = $dom->createElement('li');
$a = $dom->createElement('a', 'Paper Wallet');
$a->setAttribute('href', '#paper');
$li->appendChild($a);
$ctoc->appendChild($li);

$p = $dom->createElement('p', 'With a paper wallet, the private ECDSA key is printed on a piece of paper.');
$csubsection->appendChild($p);

$p = $dom->createElement('p', 'This makes it very easy to import the cold address into any software wallet when you do want to use the value associated with the address.');
$csubsection->appendChild($p);

$p = $dom->createElement('p', 'It also makes it very easy for anyone who has physical access to the paper wallet to use the value associated with the address.');
$csubsection->appendChild($p);

$csubsection = $dom->createElement('section');
$csubsection->setAttribute('id', 'phrase');
$csubsection->setAttribute('style', 'margin-left: 1em;');
$subsection->appendChild($csubsection);
$h = $dom->createElement('h4', 'Pass Phrase');
$csubsection->appendChild($h);

$li = $dom->createElement('li');
$a = $dom->createElement('a', 'Pass Phrase');
$a->setAttribute('href', '#phrase');
$li->appendChild($a);
$ctoc->appendChild($li);

$p = $dom->createElement('p', 'With a pass phrase cold address, the private ECDSA key is ');
$em = $dom->createElement('em', 'not');
$p->appendChild($em);
$text = $dom->createTextNode(' stored on a piece of paper. Instead, a pass phrase that can be used to generate the private ECDSA key is stored on a piece of paper.');
$p->appendChild($text);
$csubsection->appendChild($p);

$p = $dom->createElement('p', 'To generate the actual private ECDSA key, one must know both the algorithm and the salt used to generate the key from the pass phrase.');
$csubsection->appendChild($p);

$p = $dom->createElement('p', 'This makes it a ');
$em = $dom->createElement('em', 'little');
$p->appendChild($em);
$text = $dom->createTextNode(' more difficult to import the private ECDSA key into a software wallet when you are ready to spend the funds, but it also means if someone gains access to the paper the pass phrase is stored on, they will not be able to determine the private ECDSA key unless they also have access to the salt and know what algorithm is used to generate the private ECDSA key from the pass phrase.');
$p->appendChild($text);
$csubsection->appendChild($p);

$p = $dom->createElement('p', 'This solution should only be used by people who either are technically inclined or have a genuine interest in learning.');

$subsection = $dom->createElement('section');
$subsection->setAttribute('id', 'install');
$section->appendChild($subsection);
$h = $dom->createElement('h3', 'Installation');
$subsection->appendChild($h);

$li = $dom->createElement('li');
$a = $dom->createElement('a', 'Installation');
$a->setAttribute('href', '#install');
$li->appendChild($a);
$toc->appendChild($li);

$p = $dom->createElement('p', 'This PHP script and all the include files needed to run it can be downloaded from the github project page at ');
$a = $dom->createElement('a', $github);
$a->setAttribute('href', $github);
$a->setAttribute('target', '_blank');
$a->setAttribute('title', '[Opens new window]');
$p->appendChild($a);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Basic instructions for the Apache web server can be found in the ');
$code = $dom->createElement('code', 'README.md');
$p->appendChild($code);
$text = $dom->createTextNode(' file at the project page.');
$p->appendChild($text);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'This PHP script is intended to be run on the local host and not accessed over a network. If you do run it from a web server that is not your local host, make damn sure you password protect the directory and use TLS with only modern secure ciphers. I am not kidding about this. You do not want the private ECDSA keys this script generates to be sent over a network without proper TLS protection. I would limit it to TLS 1.2.');
$subsection->appendChild($p);

$subsection = $dom->createElement('section');
$subsection->setAttribute('id', 'salt');
$section->appendChild($subsection);
$h = $dom->createElement('h3', 'Salt Generation');
$subsection->appendChild($h);

$li = $dom->createElement('li');
$a = $dom->createElement('a', 'Salt Generation');
$a->setAttribute('href', '#salt');
$li->appendChild($a);
$toc->appendChild($li);

$p = $dom->createElement('p', 'The primary purpose of a salt in this application is not one of security. Rather it has to do with the way the human brain works.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'It is not uncommon for two completely different people to independently think up a pass phrase that they both believe no one else would have thought of yet are identical to each other.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'By using a salt that is unique to you, then it does not matter how many people happened to think up the same pass phrase you thought up, the generated private ECDSA key will be unique to you.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'The salt is defined in the file ');
$code = $dom->createElement('code', 'salt.inc.php');
$p->appendChild($code);
$text = $dom->createTextNode(' and is empty by default. The custom salt you create needs to be at least 96 characters in length and should have at least 28 unique characters in in. This is what the contents of that file looks like as distributed:');
$p->appendChild($text);
$subsection->appendChild($p);

$string  = '<?php' . "\n\n";
$string .= '// The salt needs to be at least 96 characters in length with at least 28 unique characters.' . "\n";
$string .= '$salt  = \'\';' . "\n\n";
$string .= '// change this to FALSE if you do not want to display the documentation' . "\n";
$string .= '$showdoc = TRUE;' . "\n\n";
$string .= '?>';

$pre = $dom->createElement('pre', $string);
$pre->setAttribute('style', 'font-size: 0.8em; color: blue;');
$subsection->appendChild($pre);

$p = $dom->createElement('p', 'When generating a salt, I recommend using the same base58 encoding character set that Bitcoin uses for Bitcoin addresses. This is because you will need to make a printed backup of your salt. It is critical that you have a printed backup of your salt. If the hardware on the PC you are running this on ever fails, you will need to re-create the same salt to be able to generate the private ECDSA keys associated with your stored value.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'The characters in the base58 encoding that Bitcoin uses were chosen so that no two characters would be visually similar.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'One way to generate a good salt that will be unique to you is to just type random junk strings into the form on this page and submit them for generation of a cold address. Then copy ');
$em = $dom->createElement('em', 'part');
$p->appendChild($em);
$text = $dom->createTextNode(' of the resulting address into the salt. Repeat with different random junk strings until your salt is at least 96 characters long.');
$p->appendChild($text);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'To make it easier on yourself when restoring the salt if your hardware fails, you can break it up into multiple lines. For example:');
$subsection->appendChild($p);

$string  = '<?php' . "\n\n";
$string .= '// The salt needs to be at least 96 characters in length with at least 28 unique characters.' . "\n";
$string .= '$salt  = \'611T5q8PxmJWFSXWdvPD\';' . "\n";
$string .= '$salt .= \'NdHMgv1kADHJotjV527K\';' . "\n";
$string .= '$salt .= \'SsQ5qw2tctRJzxpMK2GZ\';' . "\n";
$string .= '$salt .= \'UY6EVa29Vrox28TdYw68\';' . "\n";
$string .= '$salt .= \'kH53qJmUg1WmZmJGcqEQ\';' . "\n";
$string .= '$salt .= \'7pfBuHD5EChnYTMB4vsk\';' . "\n\n";
$string .= '// change this to FALSE if you do not want to display the documentation' . "\n";
$string .= '$showdoc = TRUE;' . "\n\n";
$string .= '?>';

$pre = $dom->createElement('pre', $string);
$pre->setAttribute('style', 'font-size: 0.8em; color: blue;');
$subsection->appendChild($pre);

$p = $dom->createElement('p', 'In that example, the salt is 120 characters long and because I made use of the ');
$code = $dom->createElement('code', '.=');
$code->setAttribute('style', 'color: blue;');
$p->appendChild($code);
$text = $dom->createTextNode(' assignment operator to split it into 6 lines of 20 characters, it is easy to recreate from a printout without losing my place in the string.');
$p->appendChild($text);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'When you have created a valid salt, you can test the web application in your web server. If the salt is valid, warning at the top of the page will go away.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'It is very important that you print out backup copies of the salt. I would recommend two. Put the printout into a security envelope and store them in a safe location. I would recommend one of those locations should be your Safe Deposit Box.');
$subsection->appendChild($p);

$subsection = $dom->createElement('section');
$subsection->setAttribute('id', 'pphrase');
$section->appendChild($subsection);
$h = $dom->createElement('h3', 'Pass Phrase Selection');
$subsection->appendChild($h);

$li = $dom->createElement('li');
$a = $dom->createElement('a', 'Pass Phrase Selection');
$a->setAttribute('href', '#pphrase');
$li->appendChild($a);
$toc->appendChild($li);

$p = $dom->createElement('p', 'Once you have your salt properly set up and backed up, you can start generating cold addresses. You do this by creating a pass phrase to enter into the form at the top of this page.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'A good pass phrase is at ');
$em = $dom->createElement('em', 'least');
$p->appendChild($em);
$text = $dom->createTextNode(' six words in length using words that have no logical relationship to each other. For example:');
$p->appendChild($text);
$subsection->appendChild($p);

$blockquote = $dom->createElement('blockquote');
$code = $dom->createElement('code', 'A long time ago in a galaxy far far away');
$blockquote->appendChild($code);
$subsection->appendChild($blockquote);

$p = $dom->createElement('p', 'That makes a very poor pass phrase because it a common string. If an attacker was to discover what your salt it, that phrase (and variations of it) very well may be tried to see if they can discover a private ECDSA key that has value associated with it.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'On the other hand the phrase');
$subsection->appendChild($p);

$blockquote = $dom->createElement('blockquote');
$code = $dom->createElement('code', 'festival mundos astonishing although suppose is cultured north');
$blockquote->appendChild($code);
$subsection->appendChild($blockquote);

$p = $dom->createElement('p', 'Those words have no logical reason to be together or in that order. If an attacker managed to discover what your salt is, the chances of the attacker trying that particular string are so ridiculously small it is considered mathematically impossible.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'I personally like to further reduce the odds that my mind unconsciously chose words that do have a relation to each other by inserting a garbage word:');
$subsection->appendChild($p);

$blockquote = $dom->createElement('blockquote');
$code = $dom->createElement('code', 'festival mundos astonishing although 77&amp;@sDq2 suppose is cultured north');
$blockquote->appendChild($code);
$subsection->appendChild($blockquote);

$p = $dom->createElement('p', 'Other than the fact that it has now been published in a public document, that would make an extremely strong pass phrase that I can confidently state would never ever be tried even if the attacker knew my salt. Bitcoins deposited in a cold address generated using that pass phrase would be safe.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'The point that I am trying to make, even though we should try to keep our salt from being discovered by an attacker, we should generate our pass phrases under the assumption that the salt might at some point be discovered by an attacker.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'The salt gives ');
$em = $dom->createElement('em', 'some');
$p->appendChild($em);
$text = $dom->createTextNode(' protection in case a very poor pass phrase is used, but it should ');
$p->appendChild($text);
$strong = $dom->createElement('strong');
$em = $dom->createElement('em', 'not');
$strong->appendChild($em);
$p->appendChild($strong);
$text = $dom->createTextNode(' be seen as license to use a poor pass phrase.');
$p->appendChild($text);
$subsection->appendChild($p);

$subsection = $dom->createElement('section');
$subsection->setAttribute('id', 'usage');
$section->appendChild($subsection);
$h = $dom->createElement('h3', 'Suggested Usage');
$subsection->appendChild($h);

$li = $dom->createElement('li');
$a = $dom->createElement('a', 'Suggested Usage');
$a->setAttribute('href', '#usage');
$li->appendChild($a);
$toc->appendChild($li);

$p = $dom->createElement('p', 'This section assumes you properly set up your salt and no longer have a warning message at the top of the page.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'This section assumes that your salt is properly backed up so that you can restore with the same salt if a meteorite strikes your house and destroys your existing computer.');
$subsection->appendChild($p);

$details = $dom->createElement('details');
$subsection->appendChild($details);
$summary = $dom->createElement('summary', 'Test Run');
$details->appendChild($summary);

$p = $dom->createElement('p', 'The first thing you should do is a low-value test run to make sure everything is working properly and that you understand how to import the private ECDSA key into your software wallet. To do this, I like to use the very weak pass phrase');
$details->appendChild($p);

$blockquote = $dom->createElement('blockquote');
$code = $dom->createElement('code', 'test test test test test test');
$blockquote->appendChild($code);
$details->appendChild($blockquote);

$p = $dom->createElement('p', 'Send a very small amount of Bitcoin value (e.g. 0.005 BTC) to the Base58 Check Encoding Address that is generated from that pass phrase. Give it some time for the transaction to hit the block chain with confirmations. It should be in the block chain within 20 minutes but waiting an hour doesn’t hurt. Then ');
$a = $dom->createElement('a', 'import the private ECDSA key into your software wallet');
$a->setAttribute('href', '#import');
$p->appendChild($a);
$text = $dom->createTextNode('. If everything is working you should see the transaction.');
$p->appendChild($text);
$details->appendChild($p);

$p = $dom->createElement('p', 'It is my opinion that for the typical user, ten cold addresses should be created ahead of time. To create a cold address:');
$subsection->appendChild($p);

$list = $dom->createElement('ol');
$subsection->appendChild($list);

$item = $dom->createElement('li', 'Write a pass phrase down on a 3x5 card. I like to use a thin point Sharpie. Write the same pass phrase down on a second 3x5 card. Remember the pass phrase must have at least six words separated by spaces and are case sensitive.');
$list->appendChild($item);

$item = $dom->createElement('li', 'Scrutinize the two 3x5 cards to make sure the pass phrases are identical and easy to read.');
$list->appendChild($item);

$item = $dom->createElement('li', 'Enter the pass phrase into the form for generating the addresses and click submit.');
$list->appendChild($item);

$item = $dom->createElement('li', 'Scrutinize the entered pass phrase to make sure it matches what is on the cards. The entered pass phrase as the address generator saw it will have a ');
$span = $dom->createElement('span', 'MistyRose');
$span->setAttribute('style', 'background-color: MistyRose;');
$item->appendChild($span);
$text = $dom->createTextNode(' colored background.');
$item->appendChild($text);
$list->appendChild($item);

$item = $dom->createElement('li', 'Assuming everything matches, put each of the 3x5 cards into a security envelope. I use Mead brand No. 6¾ Security Envelopes. They are a good size for 3x5 cards.');
$list->appendChild($item);

$item = $dom->createElement('li', 'On a third 3x5 card, write down the generated Base58 Check Encoding Address. It will have a ');
$span = $dom->createElement('span', 'Yellow');
$span->setAttribute('style', 'background-color: Yellow;');
$item->appendChild($span);
$text = $dom->createTextNode(' colored background.');
$item->appendChild($text);
$list->appendChild($item);

$item = $dom->createElement('p', 'Scrutinize the address you wrote down to make sure it matches what is on the screen.');
$list->appendChild($item);

$item = $dom->createElement('p', 'Write the same Base58 Check Encoding Address on the outside of the two envelopes.');
$list->appendChild($item);

$p = $dom->createElement('p', 'Repeat the above process for each cold address you want to create. When you are finished, you should have two envelopes for each cold address and a 3x5 card with just the Base58 address for each cold address.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'One set of envelopes should be placed in your Safe Deposit Box. If you are paranoid, it will be a different Safe Deposit Box than where the backup of your salt is located. The second set of envelopes should be in a separate location, perhaps at a relatives house.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'The 3x5 cards that are not in envelopes, it is not a bad idea to put your signature on them so you know without a doubt that you created them. Then put them in your desk drawer.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'When you want to deposit value into a cold address, simply make a payment to one of the addresses on one of the 3x5 cards. I personally like to only make payments of 0.5 BTC at a time, putting a mark on the 3x5 each time I do so that I always know a payment has been made to that address.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'My personal plan is to rotate through each card until I have made a 0.5 BTC payments to the cold address on each card. Then I will rotate through the cards again. If I ever am prosperous enough that each cold address has 10 BTC of value associated with it, I will probably create a new set to start making payments to. That time is a long ways away, I am not wealthy enough for that to be a concern anytime soon.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Limiting the payments to 0.5 BTC means that when I do import the private ECDSA key for a particular cold address, the transactions associated with that address are not so huge that spending from them results in the a bulk of their value being tied up in a change address that needs to wait for confirmations before it can be spent.');
$subsection->appendChild($p);

$csubsection = $dom->createElement('section');
$csubsection->setAttribute('style', 'margin-left: 1em;');
$subsection->appendChild($csubsection);
$h = $dom->createElement('h4', 'Important Note');
$h->setAttribute('style', 'color: red;');
$csubsection->appendChild($h);

$p = $dom->createElement('p', 'The private ECDSA key is never written down. When you want to use the value in a cold address, retrieve an envelope and open it. Then enter the pass phrase into the form to generate the private ECDSA key for import into your software wallet.');
$csubsection->appendChild($p);


















$subsection = $dom->createElement('section');
$subsection->setAttribute('id', 'import');
$section->appendChild($subsection);
$h = $dom->createElement('h3', 'Private Key Import');
$subsection->appendChild($h);

$li = $dom->createElement('li');
$a = $dom->createElement('a', 'Private Key Import');
$a->setAttribute('href', '#import');
$li->appendChild($a);
$toc->appendChild($li);

$p = $dom->createElement('p', 'These private key instructions are applicable to the standard Bitcoin-Qt client and were tested with version 0.11.2. If you use a different software wallet, please reference the documentation for your wallet.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'First, make sure you have a current backup of your wallet. In the File menu there is an option called ');
$code = $dom->createElement('code', 'Backup Wallet...');
$p->appendChild($code);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'I have never seen import of an address cause a problem, but it is hypothetically possible a bug in the Bitcoin-Qt software could corrupt the wallet when attempting to import an address the software did not create.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'After you have backed up your wallet, from the Help menu, select ');
$code = $dom->createElement('code', 'Debug window');
$p->appendChild($code);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Within the Debug window, select the ');
$code = $dom->createElement('code', 'Console');
$p->appendChild($code);
$text = $dom->createTextNode(' tab.');
$p->appendChild($text);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Assuming you encrypt your wallet (you really should) you will need to unlock your wallet by typing the following command into the console:');
$subsection->appendChild($p);

$string = 'walletpassphrase "The pass phrase for your Bitcoin-Qt Wallet" 600';
$pre = $dom->createElement('pre', $string);
$pre->setAttribute('style', 'color: green;');
$subsection->appendChild($pre);

$p = $dom->createElement('p', 'That will decrypt your wallet for 10 minutes (600 seconds) assuming that you entered the correct wallet pass phrase. It will give you an error message if you did not.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Next, import the private ECDSA with the following command:');
$subsection->appendChild($p);

$string = 'importprivkey privateKeyInWalletImportFormat';
$pre = $dom->createElement('pre', $string);
$pre->setAttribute('style', 'color: green;');
$subsection->appendChild($pre);

$p = $dom->createElement('p', 'Replace ');
$code = $dom->createElement('code', 'privateKeyInWalletImportFormat');
$p->appendChild($code);
$text = $dom->createTextNode(' with the actual private ECDSA key in the Wallet Import Format.');
$p->appendChild($text);
$subsection->appendChild($p);

$p = $dom->createElement('p', 'This will trigger the client to re-scan the block chain, so it will take a few minutes. When it is done, any value associated with that key should now be available in the client.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Now lock the wallet again with the following command:');
$subsection->appendChild($p);

$string = 'walletlock';
$pre = $dom->createElement('pre', $string);
$pre->setAttribute('style', 'color: green;');
$subsection->appendChild($pre);

$p = $dom->createElement('p', 'Clear the console by clicking on the circle in the bottom right hand corner of the Console. It is very important to do this, the console shows your pass phrase is in plain text and does not clear itself when you close the debug window.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'Finally, make another backup of the wallet now that it has the new address imported into it.');
$subsection->appendChild($p);

$p = $dom->createElement('p', 'It is important to note that the address you just imported is no longer a cold address. Any value sent to that address will show up in your software wallet.');
$subsection->appendChild($p);






} //end if showdoc

// send the page
$body->appendChild($footer);
$html = $dom->getElementsByTagName('html')->item(0);
$html->setAttribute('xmlns', 'http://www.w3.org/1999/xhtml');
$html->setAttributeNS('http://www.w3.org/XML/1998/namespace', 'xml:lang', 'en');
header('Content-Type: application/xhtml+xml; charset=utf-8');
print $dom->saveXML();

exit;
?>