(function(){
  'use strict';
  const $=id=>document.getElementById(id),base=new URL('.',location.href),encoder=new TextEncoder();
  const AAD='TSCK-PRIVATE/v1/';
  let activeKey=null,assets=null,frame=null,frameURL=null,urls=new Set(),busy=false,generation=0;
  function status(message,error=false){$('access-status').textContent=message;$('access-status').dataset.error=String(error);}
  function fromBase64(value){return Uint8Array.from(atob(value),char=>char.charCodeAt(0));}
  async function derive(password,manifest){
    const material=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2',salt:fromBase64(manifest.salt),iterations:manifest.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
  }
  async function decrypt(key,bytes,id){
    if(bytes.byteLength<29)throw Error('Invalid encrypted file');
    return crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.slice(0,12),additionalData:encoder.encode(AAD+id),tagLength:128},key,bytes.slice(12));
  }
  async function getBytes(path){
    const url=new URL(path,base);
    if(url.origin!==location.origin||!url.pathname.startsWith(base.pathname))throw Error('Invalid asset origin');
    const response=await fetch(url,{cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});
    if(!response.ok)throw Error('Unable to load encrypted file');
    return new Uint8Array(await response.arrayBuffer());
  }
  function lock(){
    generation++;
    if(frame)frame.remove();frame=null;
    if(frameURL)URL.revokeObjectURL(frameURL);frameURL=null;
    for(const url of urls)URL.revokeObjectURL(url);urls.clear();
    activeKey=null;assets=null;$('review-shell').hidden=true;$('entrance').hidden=false;
    $('password').value='';$('password').type='password';$('show-password').textContent='Show';$('show-password').setAttribute('aria-pressed','false');
    status('Presentation locked.');$('password').focus();
  }
  async function openFile(id,fragment='',asDownload=true){
    if(!activeKey||!assets||!Object.prototype.hasOwnProperty.call(assets,id))throw Error('Unlock the presentation again.');
    const key=activeKey,asset=assets[id],safeFragment=/^#page=[1-9][0-9]{0,3}$/.test(fragment)?fragment:'';
    const popup=!asDownload?window.open('about:blank','_blank'):null;if(popup)popup.opener=null;
    try{
      const plain=await decrypt(key,await getBytes(asset.file),id);
      if(activeKey!==key)throw Error('The presentation has been locked.');
      const url=URL.createObjectURL(new Blob([plain],{type:asset.mime}));urls.add(url);
      if(popup){popup.location.replace(url+safeFragment);return;}
      const link=document.createElement('a');link.href=url;link.download=asset.name;link.hidden=true;document.body.appendChild(link);link.click();link.remove();
      setTimeout(()=>{URL.revokeObjectURL(url);urls.delete(url);},60000);
    }catch(error){if(popup)popup.close();throw error;}
  }
  Object.defineProperty(window,'tsckVault',{value:Object.freeze({openFile,download:id=>openFile(id,'',true),lock}),writable:false,configurable:false});
  $('show-password').addEventListener('click',()=>{const show=$('password').type==='password';$('password').type=show?'text':'password';$('show-password').textContent=show?'Hide':'Show';$('show-password').setAttribute('aria-pressed',String(show));});
  $('lock').addEventListener('click',lock);
  $('unlock-form').addEventListener('submit',async event=>{
    event.preventDefault();if(busy)return;
    if(!window.crypto||!crypto.subtle){status('Please open this link in a current browser using HTTPS.',true);return;}
    busy=true;const attempt=++generation;$('unlock').disabled=true;status('Opening the presentation…');
    let key=null;
    try{
      const response=await fetch(new URL('vault.json',base),{cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});
      if(attempt!==generation)return;
      if(!response.ok)throw Error('Manifest unavailable');
      const manifest=await response.json();
      if(attempt!==generation)return;
      if(manifest.version!==1||manifest.iterations<600000||manifest.iterations>2000000||fromBase64(manifest.salt).length!==16)throw Error('Invalid manifest');
      key=await derive($('password').value,manifest);$('password').value='';
      if(attempt!==generation)return;
      const bytes=await decrypt(key,await getBytes(manifest.payload),'presentation');
      if(attempt!==generation)return;
      const payload=JSON.parse(new TextDecoder().decode(bytes));
      if(typeof payload.html!=='string'||!payload.assets||typeof payload.assets!=='object')throw Error('Invalid presentation');
      activeKey=key;assets=payload.assets;
      frame=document.createElement('iframe');frame.title='TSCK private concept review';frame.setAttribute('sandbox','allow-scripts allow-same-origin allow-downloads allow-popups');frame.referrerPolicy='no-referrer';frame.srcdoc=payload.html;
      $('frame-host').replaceChildren(frame);$('entrance').hidden=true;$('review-shell').hidden=false;status('');
    }catch(_){if(attempt===generation){activeKey=null;assets=null;status('The presentation could not be opened. Check the password and try again.',true);$('password').focus();}}
    finally{key=null;busy=false;$('unlock').disabled=false;}
  });
})();
