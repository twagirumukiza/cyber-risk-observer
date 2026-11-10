const {chromium}=require('playwright');
(async()=>{const b=await chromium.launch(),errs=[];const e=await b.newPage({viewport:{width:1100,height:800}});e.on('pageerror',x=>errs.push(x.message));
let ans=['3'];e.on('dialog',async d=>{console.log('prompt:',d.message().slice(0,60));await d.accept(ans.shift()||'')});
await e.goto('http://localhost:8765/redaction/index.html');await e.waitForTimeout(500);
await e.evaluate(()=>{items.unshift(norm({titre:'Art test',section:2,statut:'valide',date:today()}));save();drawList()});await e.waitForTimeout(300);
await e.click('button[data-a=un]');await e.waitForTimeout(300);
console.log('item:',await e.evaluate(()=>{var x=items[0];return x.une+'|'+x.uneJ+'|'+x.uneD}),'badge:',await e.$$eval('.b',l=>l.map(x=>x.textContent).filter(t=>/Accueil/.test(t))));
console.log('has Durée button:',await e.$$eval('button[data-a=uj]',l=>l.length));
await e.evaluate(()=>{$('vm').textContent='Rédaction en cours par l’IA…'});await e.waitForTimeout(300);console.log('ind:',await e.$eval('#ind',n=>n.className+' | '+n.textContent));
await e.evaluate(()=>{$('vm').textContent='Brouillon détaillé prêt : « X »'});await e.waitForTimeout(300);console.log('ind:',await e.$eval('#ind',n=>n.className+' | '+n.textContent));
await e.evaluate(()=>{localStorage.setItem('cro-vlp',JSON.stringify({abc:{t:Date.now()},def:{t:Date.now()}}));$('vm').textContent=''});await e.waitForTimeout(4500);console.log('ind pending:',await e.$eval('#ind',n=>n.className+' | '+n.textContent));
console.log(errs);await b.close()})()
