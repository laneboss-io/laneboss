const messageTable=/* MESSAGE_TABLE */;
Object.values(messageTable).forEach(row=>Object.freeze(row));Object.freeze(messageTable);
const messageValues=new Map(),messageNodes=new WeakMap(),messageAttrs=new WeakMap();
function readPreference(key){try{return localStorage.getItem(key);}catch(error){return null;}}
function writePreference(key,value){try{localStorage.setItem(key,value);}catch(error){}}
function browserLocale(language){return /^(zh-tw|zh-hk|zh-hant)(-|$)/i.test(language||'')?'zh-TW':'en';}
let locale=readPreference('lb.locale');if(!['en','zh-TW'].includes(locale))locale=browserLocale(navigator.language);
let themeChoice=readPreference('lb.theme');if(!['system','light','dark'].includes(themeChoice))themeChoice='system';
const systemTheme=matchMedia('(prefers-color-scheme: dark)');
function applyTheme(){document.documentElement.dataset.theme=themeChoice==='system'?(systemTheme.matches?'dark':'light'):themeChoice;document.documentElement.dataset.themeChoice=themeChoice;}
systemTheme.addEventListener('change',()=>{if(themeChoice==='system')applyTheme();});applyTheme();
document.documentElement.lang=locale;
function formatMessage(key,args={},language=locale){const row=messageTable[key];if(!row||typeof row[language]!=='string')throw new Error('Missing dashboard message: '+key);return row[language].replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g,(_,name)=>{if(!(name in args))throw new Error('Missing message argument: '+name);return String(args[name]);});}
function tr(key,args={}){const value=formatMessage(key,args);messageValues.set(value,{key,args});if(messageValues.size>4096)messageValues.delete(messageValues.keys().next().value);return value;}
function localized(value){const text=String(value),stored=messageValues.get(text);if(stored)return stored;if(messageTable[text])return {key:text,args:{}};const trimmed=text.trim();if(messageTable[trimmed])return {key:trimmed,args:{}};return null;}
function setText(element,text){delete element.dataset.recorded;const message=localized(text),value=message?tr(message.key,message.args):String(text);if(element.textContent!==value||element.children.length)element.textContent=value;if(message){if(element.firstChild)messageNodes.set(element.firstChild,message);element.dataset.msg=message.key;}else delete element.dataset.msg;}
function setData(element,text){delete element.dataset.msg;element.dataset.recorded='';element.textContent=text===null||text===undefined?'—':String(text);}
function recordNode(tag,text,cls){const el=document.createElement(tag);if(cls)el.className=cls;setData(el,text);return el;}
function nf(value,digits=12){return new Intl.NumberFormat(locale,{maximumFractionDigits:digits}).format(value);}
function pct(value,digits=1){return new Intl.NumberFormat(locale,{style:'percent',maximumFractionDigits:digits}).format(value);}
function clockText(value){return new Intl.DateTimeFormat(locale,{hour:'2-digit',minute:'2-digit',timeZoneName:'short'}).format(new Date(value));}
function stateText(value){const states={running:'Running',verifying:'Verifying',idle:'Idle',failed:'Failed',ended:'Ended',success:'Success',stopped:'Stopped',stopped_at_budget:'Stopped at budget',hook_config_failure:'Hook configuration failure',refused:'Refused',pending:'Pending',answered:'Answered',timeout:'Timed out',exit:'Program exited',output:'Invalid answer','not-found':'Program unavailable',ok:'OK',warn:'Warning',stop:'Stopped',error:'Error',unknown:'No state recorded'};return states[value]?tr(states[value]):String(value||'—');}
function kindText(value){return ['lane','instance','supervisor'].includes(value)?tr({lane:'Lane',instance:'Instance',supervisor:'Supervisor'}[value]):String(value);}
function levelText(level){return typeof level==='number'?tr('L{level}',{level:nf(level)}):tr('Level not recorded');}
function serverError(value,fallback){const known=localized(value||'');return known?tr(known.key,known.args):tr(fallback||'Request refused. Check the records for details.');}
function retainedMessage(previous,current){if(previous&&['en','zh-TW'].some(language=>formatMessage(previous.key,previous.args,language)===current))return previous;return localized(current);}
function matchingElements(root,selector){const elements=[...root.querySelectorAll(selector)];if(root.nodeType===Node.ELEMENT_NODE&&root.matches(selector))elements.unshift(root);return elements;}
function localizeTree(root){
 matchingElements(root,'[data-msg]').forEach(el=>{if(!el.children.length){const message=retainedMessage(messageNodes.get(el.firstChild),el.textContent);if(message)setText(el,tr(message.key,message.args));else if(!el.textContent)setText(el,tr(el.dataset.msg));else delete el.dataset.msg;}});
 const walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);let text;
 while(text=walker.nextNode()){
  const parent=text.parentElement;if(!parent||parent.closest('script,style,[data-recorded]'))continue;
  const message=retainedMessage(messageNodes.get(text),text.nodeValue);if(!message)continue;
  const value=formatMessage(message.key,message.args);if(text.nodeValue!==value)text.nodeValue=value;messageNodes.set(text,message);
 }
 matchingElements(root,'[aria-label],[placeholder],[title]').forEach(el=>{
  if(el.closest('[data-recorded]'))return;
  let stored=messageAttrs.get(el);if(!stored){stored={};messageAttrs.set(el,stored);}
  ['aria-label','placeholder','title'].forEach(attr=>{const current=el.getAttribute(attr);if(!current)return;const message=retainedMessage(stored[attr],current);if(message){stored[attr]=message;const value=tr(message.key,message.args);if(current!==value)el.setAttribute(attr,value);}else delete stored[attr];});
 });
}
localizeTree(document);
const localeObserver=new MutationObserver(changes=>{const roots=new Set();changes.forEach(change=>{if(change.type==='characterData'){const parent=change.target.parentElement;if(parent)roots.add(parent);}else roots.add(change.target);});roots.forEach(root=>{if(root.nodeType===Node.ELEMENT_NODE)localizeTree(root);});});
localeObserver.observe(document.body,{subtree:true,childList:true,characterData:true,attributes:true,attributeFilter:['aria-label','placeholder','title']});
function translationAudit(){
 const missing=[];const walker=document.createTreeWalker(document,NodeFilter.SHOW_TEXT);let text;
 while(text=walker.nextNode()){
  const parent=text.parentElement;if(!parent||parent.closest('script,style,noscript,[data-recorded]')||!text.nodeValue.trim()||(!parent.getClientRects().length&&parent.tagName.toLowerCase()!=='title'))continue;
  const message=messageNodes.get(text);
  if(!message||text.nodeValue.trim()!==formatMessage(message.key,message.args).trim())missing.push({kind:'text',text:text.nodeValue.trim(),element:parent.id||parent.tagName});
 }
 document.querySelectorAll('[aria-label],[placeholder],[title]').forEach(el=>{if(el.closest('[data-recorded]'))return;const attributes=messageAttrs.get(el)||{};['aria-label','placeholder','title'].forEach(attr=>{const value=el.getAttribute(attr),message=attributes[attr];if(value&&(!message||value!==formatMessage(message.key,message.args)))missing.push({kind:attr,text:value,element:el.id||el.tagName});});});
 return missing;
}
function preferenceControls(){
 const theme=document.getElementById('theme-choice'),language=document.getElementById('language-choice');theme.value=themeChoice;language.value=locale;
 theme.addEventListener('change',()=>{themeChoice=theme.value;writePreference('lb.theme',themeChoice);applyTheme();});
 language.addEventListener('change',()=>{locale=language.value;writePreference('lb.locale',locale);document.documentElement.lang=locale;localizeTree(document);if(typeof repaintLocale==='function')repaintLocale();});
}
// Read-only presentation inspection exposes no token or configuration data.
window.dashboardPresentation=Object.freeze({audit:translationAudit,messages:messageTable,format:(key,args)=>formatMessage(key,args),number:value=>nf(value),time:value=>new Intl.DateTimeFormat(locale,{year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZoneName:'short'}).format(new Date(value))});
