const API_HTTPS=`https://${window.location.hostname}`,API_HTTP=`http://${window.location.hostname}`,SCRIPT_VERSION_RAW="v-0f320bd3",SCRIPT_VERSION=SCRIPT_VERSION_RAW.replace(/^(?:fluxdrop-)?(?:v-)?/,"");let API_BASE_URL=window.location.protocol==="https:"?API_HTTPS:API_HTTP;function encodePath(e){return e==="/"?"/":e.split("/").map(encodeURIComponent).join("/")}function escapeHtmlAttr(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;")}function safeJs(e){return JSON.stringify(e).replace(/'/g,"\\'")}async function fetchWithFallback(e,n){let i=null;n&&n.body instanceof ArrayBuffer&&(i=n.body.slice(0));try{return await fetch(e,n)}catch(o){if(console.warn("Fetch failed:",o),window.location.protocol==="http:")try{API_BASE_URL=API_HTTP;const p=e.replace(API_HTTPS,API_HTTP),l=i?{...n,body:i}:n;return await fetch(p,l)}catch(p){throw p}throw o}}"serviceWorker"in navigator&&navigator.serviceWorker.addEventListener("message",e=>{e.data&&e.data.type==="SW_UPDATED"&&_showUpdateBanner()});function _showUpdateBanner(){if(document.getElementById("fd-update-banner"))return;const e=document.createElement("div");e.id="fd-update-banner",e.style.cssText=["position:fixed","bottom:1rem","left:50%","transform:translateX(-50%)","background:#1e40af","color:#fff","padding:0.6rem 1.2rem","border-radius:0.75rem","font-size:0.9rem","z-index:99999","display:flex","align-items:center","gap:0.75rem","box-shadow:0 4px 12px rgba(0,0,0,0.25)"].join(";"),e.innerHTML=`
        <span>🔄 A new version of FluxDrop is available.</span>
        <button onclick="_fdHardReload()" style="
            background:#fff;color:#1e40af;border:none;border-radius:0.5rem;
            padding:0.3rem 0.8rem;font-weight:600;cursor:pointer;">
            Reload
        </button>
        <button onclick="this.parentElement.remove()" style="
            background:none;border:none;color:#fff;cursor:pointer;font-size:1.1rem;">
            ✕
        </button>`,document.body.appendChild(e)}async function _fdHardReload(){try{"serviceWorker"in navigator&&navigator.serviceWorker.controller&&await new Promise(e=>{const n=new MessageChannel;n.port1.onmessage=e,navigator.serviceWorker.controller.postMessage({type:"SKIP_AND_CLEAR"},[n.port2]),setTimeout(e,5e3)})}catch{}try{sessionStorage.setItem("fd_just_updated","1")}catch{}location.reload()}const appRoot=document.getElementById("app-root"),authControls=document.getElementById("auth-controls");let authToken=localStorage.getItem("fluxdrop_token"),currentUsername=localStorage.getItem("fluxdrop_username"),isAdmin=localStorage.getItem("fluxdrop_is_admin")==="1",currentPath="/",_lastKnownRetentionDays=30,_lastUploadBatchCount=0,_pausedQueueDrain=null,_mobileUploadPending=!1;const _APP_BASE=(()=>{let e=window.location.pathname.replace(/\/index\.html$/,"").replace(/\/files(\/.*)?$/,"");return e.endsWith("/")?e.slice(0,-1):e})();function navigateTo(e){if(e===currentPath)return;window._fdKeepSelectionOnNav||(_selectedPaths.clear(),_lastClickedPath=null,_updateSelBar()),currentPath=e;const n=_APP_BASE+"/files"+(e==="/"?"":encodePath(e));history.pushState({fdPath:e},"",n),loadDirectory(e)}function _syncUrlToPath(e){const n=_APP_BASE+"/files"+(e==="/"?"":encodePath(e));history.replaceState({fdPath:e},"",n)}window.addEventListener("popstate",e=>{const n=e.state&&e.state.fdPath?e.state.fdPath:"/";n!==currentPath&&!window._fdKeepSelectionOnNav&&(_selectedPaths.clear(),_lastClickedPath=null,_updateSelBar()),currentPath=n,loadDirectory(n)});let currentSort=(()=>{try{return JSON.parse(localStorage.getItem("fluxdrop_sort"))||{key:"name",dir:"asc"}}catch{return{key:"name",dir:"asc"}}})(),sortFoldersMixed=(()=>{try{return JSON.parse(localStorage.getItem("fluxdrop_sort_mixed"))||!1}catch{return!1}})();function withMinDelay(e,n=1e3){const i=Date.now();return e.then(o=>{const p=Date.now()-i,l=Math.max(0,n-p);return l===0?o:new Promise(r=>setTimeout(()=>r(o),l))},o=>{const p=Date.now()-i,l=Math.max(0,n-p);if(l===0)throw o;return new Promise((r,s)=>setTimeout(()=>s(o),l))})}function _loadingHtml(e="24px"){if(!document.getElementById("fd-spin-style")){const n=document.createElement("style");n.id="fd-spin-style",n.textContent="@keyframes fd-spin{to{transform:rotate(360deg)}}",document.head.appendChild(n)}return`<div style="display:flex;align-items:center;justify-content:center;gap:10px;padding:${e};color:#94a3b8;font-size:14px"><span style="width:18px;height:18px;border:2px solid #cbd5e1;border-top-color:#3b82f6;border-radius:50%;animation:fd-spin .7s linear infinite;flex-shrink:0"></span>${escapeHtml(t("loading"))}</div>`}function showSpinnerOverlay(e="Loading…",n={}){const i=n.minMs!=null?n.minMs:1e3,o=n.id||"fd-spinner-"+Date.now(),p=document.createElement("div");if(p.id=o,p.style.cssText=["position:fixed;top:0;left:0;width:100%;height:100%;z-index:10400","background:rgba(15,23,42,.55);display:flex;align-items:center;justify-content:center","animation:fd-fade-in .15s ease"].join(";"),p.innerHTML='<div class="fd-modal-panel-in" style="background:#1e293b;border-radius:1rem;padding:2rem 2.5rem;display:flex;flex-direction:column;align-items:center;gap:1rem;box-shadow:0 16px 48px rgba(0,0,0,.5);min-width:180px;text-align:center"><div style="width:44px;height:44px;border-radius:50%;border:4px solid #334155;border-top-color:#3b82f6;animation:fd-spin .7s linear infinite"></div><div style="color:#e2e8f0;font-size:.93rem;font-weight:500">'+escapeHtml(e)+"</div></div>",!document.getElementById("fd-spin-style")){const r=document.createElement("style");r.id="fd-spin-style",r.textContent="@keyframes fd-spin{to{transform:rotate(360deg)}}",document.head.appendChild(r)}document.body.appendChild(p);const l=Date.now();return function(){const s=Math.max(0,i-(Date.now()-l)),a=function(){const d=document.getElementById(o);d&&window.fdCloseOverlay(d)};s<=0?a():setTimeout(a,s)}}function showModal(e){const n=document.getElementById(e);n.classList.remove("hidden","fd-overlay-closing"),delete n.dataset.fdClosing;const i=n.querySelector(".modal-content");i&&i.classList.remove("fd-panel-closing")}function hideModal(e){const n=document.getElementById(e);if(!n||n.classList.contains("hidden")||n.dataset.fdClosing){_detachModalKeys();return}_detachModalKeys(),n.dataset.fdClosing="1",n.classList.add("fd-overlay-closing");const i=n.querySelector(".modal-content");i&&i.classList.add("fd-panel-closing");let o=!1;const p=()=>{o||(o=!0,n.classList.remove("fd-overlay-closing"),i&&i.classList.remove("fd-panel-closing"),delete n.dataset.fdClosing,n.classList.add("hidden"))};n.addEventListener("animationend",p,{once:!0}),setTimeout(p,200)}let _modalKeyHandler=null;function _attachModalKeys(e,n){_detachModalKeys(),_modalKeyHandler=i=>{i.key==="Enter"?(i.preventDefault(),i.stopPropagation(),_detachModalKeys(),e&&e()):i.key==="Escape"&&(i.preventDefault(),i.stopPropagation(),_detachModalKeys(),n&&n())},document.addEventListener("keydown",_modalKeyHandler,!0)}function _detachModalKeys(){_modalKeyHandler&&(document.removeEventListener("keydown",_modalKeyHandler,!0),_modalKeyHandler=null)}function stripInternalPrefix(e){return e.replace(/^\/FluxDrop\/\d+\//,"/")}const _AVATAR_VERSION_KEY="fd-avatar-v";function _avatarUrl(e){const n=e||localStorage.getItem("fluxdrop_user_id")||"0",i=localStorage.getItem(_AVATAR_VERSION_KEY)||"0";return`${API_BASE_URL}/api/v1/avatar/${encodeURIComponent(n)}?v=${i}`}function _bumpAvatarVersion(){localStorage.setItem(_AVATAR_VERSION_KEY,String(Date.now()))}function escapeHtml(e){return String(e).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}function showMessage(e,n,i=!1){document.getElementById("message-modal-title").textContent=e;const o=document.getElementById("message-modal-content");i?o.innerHTML=n:o.textContent=n,showModal("message-modal"),_attachModalKeys(()=>hideModal("message-modal"),()=>hideModal("message-modal"))}function _getToastStack(){let e=document.getElementById("fd-toast-stack");return e||(e=document.createElement("div"),e.id="fd-toast-stack",e.className="fd-toast-stack",document.body.appendChild(e)),e}function showToast(e,n={}){const{type:i="success",duration:o=3200,sticky:p=!1,actions:l=[]}=n,r=_getToastStack(),s=document.createElement("div");s.className=`fd-toast fd-toast-${i} fd-tray-in`;const a=i==="progress"?'<span class="fd-toast-spinner"></span>':`<span class="fd-toast-icon">${i==="error"?"⚠":i==="info"?"ℹ":"✓"}</span>`,d=l.length?`<span class="fd-toast-actions">${l.map((m,u)=>`<button type="button" class="fd-toast-action" data-fd-action-idx="${u}">${m.label}</button>`).join("")}</span>`:"";s.innerHTML=`${a}<span class="fd-toast-msg"></span>${d}`,s.querySelector(".fd-toast-msg").textContent=e,r.appendChild(s);let f=!1;const c=()=>{f||!s.isConnected||(f=!0,s.classList.remove("fd-tray-in"),s.classList.add("fd-tray-closing"),s.addEventListener("animationend",()=>s.remove(),{once:!0}))};return l.forEach((m,u)=>{const g=s.querySelector(`[data-fd-action-idx="${u}"]`);g&&g.addEventListener("click",h=>{h.stopPropagation(),m.onClick(c)})}),s.addEventListener("click",c),p||setTimeout(c,o),{dismiss:c,setMessage(m){const u=s.querySelector(".fd-toast-msg");u&&(u.textContent=m)}}}function showPromptModal({title:e,label:n="",placeholder:i="",defaultValue:o="",confirmLabel:p=t("ok"),cancelLabel:l=t("cancel")}={}){return new Promise(r=>{const s=document.createElement("div");s.className="modal-overlay",s.innerHTML=`
            <div class="modal-content" style="max-width:380px">
                <h3 style="font-size:1.15rem;font-weight:700;margin-bottom:.75rem;color:#1e293b"></h3>
                ${n?'<label style="display:block;font-size:13px;color:#64748b;margin-bottom:6px"></label>':""}
                <input type="text" id="fd-prompt-input"
                       style="width:100%;padding:9px 12px;border:1px solid #cbd5e1;border-radius:8px;
                              font-size:14px;margin-bottom:1.1rem;box-sizing:border-box"
                       autocomplete="off" spellcheck="false">
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="fd-prompt-cancel" class="btn" style="background:#6b7280"></button>
                    <button id="fd-prompt-ok" class="btn"></button>
                </div>
            </div>
        `,s.querySelector("h3").textContent=e||"",n&&(s.querySelector("label").textContent=n);const a=s.querySelector("#fd-prompt-input");a.value=o,a.placeholder=i,s.querySelector("#fd-prompt-cancel").textContent=l,s.querySelector("#fd-prompt-ok").textContent=p,document.body.appendChild(s);let d=!1;function f(c){d||(d=!0,_detachModalKeys(),window.fdCloseOverlay(s),r(c))}s.querySelector("#fd-prompt-ok").addEventListener("click",()=>f(a.value.trim()||null)),s.querySelector("#fd-prompt-cancel").addEventListener("click",()=>f(null)),s.addEventListener("click",c=>{c.target===s&&f(null)}),_attachModalKeys(()=>f(a.value.trim()||null),()=>f(null)),a.focus(),a.select()})}function showConfirmModal({title:e,message:n="",confirmLabel:i=t("yes"),cancelLabel:o=t("no"),danger:p=!0}={}){return new Promise(l=>{const r=document.createElement("div");r.className="modal-overlay",r.innerHTML=`
            <div class="modal-content text-center" style="max-width:380px">
                <h3 style="font-size:1.15rem;font-weight:700;margin-bottom:.6rem;color:#1e293b"></h3>
                <p style="color:#64748b;font-size:13.5px;line-height:1.55;margin-bottom:1.25rem;white-space:pre-line"></p>
                <div style="display:flex;gap:8px;justify-content:center">
                    <button id="fd-confirm-no" class="btn" style="background:#6b7280"></button>
                    <button id="fd-confirm-yes" class="btn"></button>
                </div>
            </div>
        `,r.querySelector("h3").textContent=e||"",r.querySelector("p").textContent=n;const s=r.querySelector("#fd-confirm-no"),a=r.querySelector("#fd-confirm-yes");s.textContent=o,a.textContent=i,p&&(a.style.background="#ef4444"),document.body.appendChild(r);let d=!1;function f(c){d||(d=!0,_detachModalKeys(),window.fdCloseOverlay(r),l(c))}a.addEventListener("click",()=>f(!0)),s.addEventListener("click",()=>f(!1)),r.addEventListener("click",c=>{c.target===r&&f(!1)}),_attachModalKeys(()=>f(!0),()=>f(!1)),a.focus()})}function _startCopyJobTracking(e,n){const o=Math.ceil(2400);let p=0,l=!1,r=!1;const s=showToast(`Copying "${n}"…`,{type:"progress",sticky:!0,actions:[{label:"Cancel",onClick:async()=>{if(!r){r=!0,s.setMessage(`Cancelling "${n}"…`);try{await apiCall(`/api/v1/copy/cancel/${e}`,"POST")}catch(d){logging_warn("copy cancel request failed",d)}}}},{label:"Hide",onClick:d=>{l=!0,d()}}]}),a=async()=>{if(!l){p++;try{const d=await apiCall(`/api/v1/copy/status/${e}`,"GET");if(d.status==="done"){s.dismiss(),showToast(`Copied "${n}"`),loadDirectory(currentPath);return}if(d.status==="cancelled"){s.dismiss(),showToast(`Copy of "${n}" cancelled`,{type:"info"});return}if(d.status==="error"){s.dismiss(),showToast(`Copy of "${n}" failed: ${d.error_msg||"unknown error"}`,{type:"error",duration:6e3});return}}catch(d){logging_warn("copy job poll failed, retrying",d)}l||(p<o?setTimeout(a,1500):(s.dismiss(),showToast(`Copy of "${n}" is taking unusually long — check manually`,{type:"info",duration:6e3})))}};setTimeout(a,1500)}async function apiCall(e,n="GET",i=null,o=!0){const p=new Headers({"Content-Type":"application/json"});if(o){if(!authToken)throw new Error("Authentication token not found.");p.set("Authorization",`Bearer ${authToken}`)}const l={method:n,headers:p};i&&(l.body=JSON.stringify(i));try{const r=await fetchWithFallback(`${API_BASE_URL}${e}`,l),s=await r.json();if(!r.ok)throw r.status===401&&o?(authToken=null,currentUsername=null,localStorage.removeItem("fluxdrop_token"),localStorage.removeItem("fluxdrop_username"),renderApp("login"),showMessage(t("session_expired"),t("session_expired_msg")),new Error("SESSION_EXPIRED")):new Error(s.error||`HTTP error! status: ${r.status}`);return s}catch(r){throw r.message!=="SESSION_EXPIRED"&&console.error("API Call Error:",r),r}}function getTrayDismissDelay(){const e=parseInt(localStorage.getItem("fluxdrop_tray_dismiss_ms")||"0",10);return isNaN(e)?0:e}function _requestNotificationPermission(){"Notification"in window&&Notification.permission==="default"&&Notification.requestPermission()}function _notifyUploadDone(e,n=0){if(!("Notification"in window)||Notification.permission!=="granted"||document.hasFocus())return;let i,o;n>0&&e===0?(i="FluxDrop — "+t("upload_failed"),o=t("notify_upload_all_failed",{n})):n>0?(i="FluxDrop — "+t("notify_upload_partial_title"),o=t("notify_upload_partial",{ok:e,failed:n})):(i="FluxDrop — "+t("notify_upload_done_title"),o=t("notify_upload_done",{n:e})),new Notification(i,{body:o,icon:"/fluxdrop_pp/icon-128.png",tag:"fluxdrop-upload-done"})}function renderAuthControls(){authToken?(authControls.innerHTML=`
            <div class="flex items-center gap-2" style="min-width:0">
                <span class="font-medium text-blue-900 fd-welcome-text"
                      style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
                             max-width:min(220px,40vw);font-size:14px"
                      title="${escapeHtmlAttr(currentUsername)}">
                    ${t("welcome_text")} ${escapeHtml(currentUsername)}!
                </span>
                <button id="profile-btn" title="Profile & Settings"
                    style="width:36px;height:36px;border-radius:50%;background:#3b82f6;border:2px solid #93c5fd;
                            color:white;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center;
                            flex-shrink:0;transition:background .2s;overflow:hidden;padding:0"
                    onmouseenter="this.style.background='#2563eb'" onmouseleave="this.style.background='#3b82f6'">
                    <img id="header-avatar"
                         src="${_avatarUrl()}"
                         style="width:36px;height:36px;border-radius:50%;object-fit:cover;display:block"
                         onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"
                         alt="">
                    <span id="header-avatar-fallback"
                          style="display:none;width:100%;height:100%;align-items:center;justify-content:center;font-size:16px">👤</span>
                </button>
            </div>
        `,document.getElementById("profile-btn").addEventListener("click",openProfileMenu)):(authControls.innerHTML=`
            <div class="flex items-center gap-4">
                <button id="show-login-btn" class="btn text-sm">${t("login")}</button>
                <button id="show-register-btn" class="btn bg-green-500 hover:bg-green-600 text-sm">${t("register")}</button>
            </div>
        `,document.getElementById("show-login-btn").addEventListener("click",()=>renderApp("login")),document.getElementById("show-register-btn").addEventListener("click",()=>renderApp("register")))}let _renderAppBusy=!1;async function renderApp(e=null){if(!_renderAppBusy){_renderAppBusy=!0;try{if(renderAuthControls(),!authToken){e==="register"?renderRegisterView():e==="login"?renderLoginView():renderLandingView();return}if(!localStorage.getItem("fluxdrop_user_id"))try{const n=await apiCall("/api/v1/me");n&&n.id&&localStorage.setItem("fluxdrop_user_id",String(n.id))}catch{}_requestNotificationPermission(),checkAndShowPolicies(()=>renderFileBrowserView())}finally{_renderAppBusy=!1}}}function renderLandingView(){appRoot.dataset.fdLanding="1",appRoot.innerHTML=`
        <div style="display:flex;flex-direction:column;gap:2rem;animation:fd-fade-in-up .35s ease both">

            <!-- Hero -->
            <div class="card" style="text-align:center;padding:3rem 2rem">
                <img src="/fluxdrop_pp/icon-128.png" width="72" height="72" style="width:72px;height:72px;margin:0 auto 1rem" alt="FluxDrop">
                <h2 style="font-size:2.2rem;font-weight:800;color:#1e40af;margin-bottom:.75rem">
                    ${t("home_slogan")}
                </h2>
                <p style="font-size:1.1rem;color:#475569;max-width:560px;margin:0 auto 2rem;line-height:1.7">
                    ${t("home_slogan_desc1")}
                    ${t("home_slogan_desc2")}
                </p>
                <div style="display:flex;gap:1rem;justify-content:center;flex-wrap:wrap">
                    <button class="btn" style="font-size:1rem;padding:0.85rem 2rem"
                            onclick="renderApp('login')">${t("login")}</button>
                    <button class="btn" style="font-size:1rem;padding:0.85rem 2rem;background:#16a34a"
                            onclick="renderApp('register')">${t("home_create_account")}</button>
                </div>
            </div>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1.25rem">
                ${[["📁",t("home_card_lable1"),t("home_card_desc1")],["🔗",t("home_card_lable2"),t("home_card_desc2")],["👁",t("home_card_lable3"),t("home_card_desc3")],["⚡",t("home_card_lable4"),t("home_card_desc4")],["🗑",t("home_card_lable5"),t("home_card_desc5")],["🔒",t("home_card_lable6"),t("home_card_desc6")],["👆",t("home_card_lable7_hold"),t("home_card_desc7_hold")]].map(([e,n,i])=>`
                    <div class="card" style="padding:1.5rem">
                        <div style="font-size:2rem;margin-bottom:.5rem">${e}</div>
                        <h3 style="font-weight:700;color:#1e40af;margin-bottom:.4rem">${n}</h3>
                        <p style="color:#64748b;font-size:.92rem;line-height:1.6">${i}</p>
                    </div>
                `).join("")}
            </div>

            <!-- How it works -->
            <div class="card" style="padding:2rem">
                <h3 style="font-size:1.4rem;font-weight:700;color:#1e40af;margin-bottom:1.25rem;text-align:center">
                    ${t("home_card_lable_desc")}
                </h3>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;text-align:center">
                    ${[["1",t("home_card_lable7"),t("home_card_desc7")],["2",t("home_card_lable8"),t("home_card_desc8")],["3",t("home_card_lable9"),t("home_card_desc9")],["4",t("home_card_lable10"),t("home_card_desc10")]].map(([e,n,i])=>`
                        <div>
                            <div style="width:40px;height:40px;border-radius:50%;background:#dbeafe;color:#1d4ed8;
                                        font-weight:800;font-size:1.1rem;display:flex;align-items:center;
                                        justify-content:center;margin:0 auto .6rem">${e}</div>
                            <div style="font-weight:600;color:#1e293b;margin-bottom:.25rem">${n}</div>
                            <div style="font-size:.88rem;color:#64748b">${i}</div>
                        </div>
                    `).join("")}
                </div>
            </div>

            <!-- Footer links -->
            <div style="text-align:center;padding-bottom:1rem;font-size:.85rem;color:#94a3b8">
                <button onclick="showPolicyModal('tos')"
                    style="background:none;border:none;color:#94a3b8;cursor:pointer;text-decoration:underline;font-size:.85rem">
                    ${t("footer_tos")}</button>
                &nbsp;·&nbsp;
                <button onclick="showPolicyModal('pp')"
                    style="background:none;border:none;color:#94a3b8;cursor:pointer;text-decoration:underline;font-size:.85rem">
                    ${t("footer_pp")}</button>
            </div>
        </div>
    `}const POLICY_LABELS={tos:"Terms of Service",pp:"Privacy Policy"};let _policyLang=localStorage.getItem("fluxdrop_policy_lang")||"eng",_versionsCache=null;async function _fetchVersions(){if(_versionsCache)return _versionsCache;try{const e=await fetch("./policies/versions.json",{cache:"no-cache"});e.ok&&(_versionsCache=await e.json())}catch{}return _versionsCache||{}}function _policyUrl(e,n,i){return`./policies/${e==="tos"?"TOS":"PP"}/${n}/v${i}.md`}function _langSelectorHtml(e,n,i,o){if(e.length<=1)return"";const p=e.map(l=>{const r=n&&n[l]||l;return`<option value="${l}"${l===i?" selected":""}>${r}</option>`}).join("");return`<select id="${o}"
        style="font-size:.8rem;padding:3px 6px;border-radius:6px;border:1px solid #cbd5e1;
               color:#475569;background:#f8fafc;cursor:pointer;margin-left:.5rem">
        ${p}
    </select>`}async function showPolicyModal(e){const n=POLICY_LABELS[e]||e.toUpperCase(),i=await _fetchVersions(),o=i.languages||{},p=i[e]||{},l=Object.keys(p).length?Object.keys(p):["eng"];let r=l.includes(_policyLang)?_policyLang:l[0],s=p[r]||"0.0.0";const a=_policyUrl(e,r,s),d=document.createElement("div");d.style.cssText=["position:fixed;top:0;left:0;width:100%;height:100%;z-index:10000","background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;padding:1rem","animation:fd-fade-in .18s ease"].join(";"),d.innerHTML=`
        <div class="fd-modal-panel-in" style="background:#fff;border-radius:1rem;width:100%;max-width:720px;
                    max-height:88vh;display:flex;flex-direction:column;overflow:hidden;
                    box-shadow:0 24px 48px rgba(0,0,0,.3)">
            <div style="padding:1.25rem 1.5rem;border-bottom:1px solid #e2e8f0;
                        display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem">
                <div style="display:flex;align-items:center;flex-wrap:wrap;gap:.4rem">
                    <h2 style="font-size:1.15rem;font-weight:700;color:#1e40af;margin:0">
                        ${n}
                    </h2>
                    <span id="pm-ver-wrap"><span style="font-size:.8rem;color:#94a3b8;font-weight:400">v${s}</span></span>
                    ${_langSelectorHtml(l,o,r,"pm-lang")}
                </div>
                <button id="pm-close" style="background:none;border:none;font-size:1.4rem;
                        cursor:pointer;color:#64748b;line-height:1">✕</button>
            </div>
            <div id="pm-body" class="fd-md-body" data-fd-notranslate style="padding:1.5rem;overflow-y:auto;flex:1;
                                     font-size:.93rem;line-height:1.7;color:#1e293b">
                ${_loadingHtml("2rem")}
            </div>
        </div>`,document.body.appendChild(d);const f=b=>{b.key==="Escape"&&(b.stopPropagation(),c())};function c(){document.removeEventListener("keydown",f,!0),window.fdCloseOverlay(d)}document.addEventListener("keydown",f,!0),d.querySelector("#pm-close").addEventListener("click",c),d.addEventListener("click",b=>{b.target===d&&c()});const m=await _fetchPolicyHistory();function u(b,E){const k=d.querySelector("#pm-ver-wrap"),w=p[b]||"0.0.0",y=((m[e]||{})[b]||[]).slice();if(y.includes(w)||y.unshift(w),y.length<=1){k.innerHTML=`<span style="font-size:.8rem;color:#94a3b8;font-weight:400">v${escapeHtml(w)}</span>`;return}k.innerHTML=`<select id="pm-ver" title="${escapeHtmlAttr(t("policy_version_label"))}"
            style="font-size:.8rem;padding:3px 6px;border-radius:6px;border:1px solid #cbd5e1;
                   color:#475569;background:#f8fafc;cursor:pointer">
            ${y.map(x=>`<option value="${escapeHtmlAttr(x)}"${x===E?" selected":""}>v${escapeHtml(x)}${x===w?" · "+escapeHtml(t("policy_version_current")):""}</option>`).join("")}
        </select>`,k.querySelector("#pm-ver").addEventListener("change",x=>g(b,x.target.value))}async function g(b,E){const k=p[b]||"0.0.0";E=E||k,u(b,E);const w=d.querySelector("#pm-body");w.innerHTML=_loadingHtml("2rem");try{const y=await fetch(_policyUrl(e,b,E),{cache:"no-cache"});if(!y.ok)throw new Error(`HTTP ${y.status}`);const x=await y.text();let v;try{await _loadMarked(),v=_mdParseAndSanitize(x)}catch{v=_mdToHtml(x)}const _=E!==k?`<div style="background:#fef3c7;color:#92400e;border-radius:8px;padding:8px 12px;margin-bottom:1rem;font-size:.85rem">
                       ${escapeHtml(t("policy_old_version_note",{version:E,current:k}))}</div>`:"";w.innerHTML=_+v,w.scrollTop=0}catch(y){w.innerHTML=`<p style="color:#dc2626">${escapeHtml(t("policy_load_failed"))}<br>
                 <small style="color:#94a3b8">${escapeHtml(y.message)}</small></p>`}}const h=d.querySelector("#pm-lang");h&&h.addEventListener("change",()=>{_policyLang=h.value,localStorage.setItem("fluxdrop_policy_lang",_policyLang),g(_policyLang)}),g(r)}let _policyHistoryCache=null;async function _fetchPolicyHistory(){if(_policyHistoryCache)return _policyHistoryCache;try{const e=await fetch(`${API_BASE_URL}/api/v1/policy/history`,{cache:"no-cache"});e.ok&&(_policyHistoryCache=await e.json())}catch{}return _policyHistoryCache||{}}function _mdToHtml(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/^### (.+)$/gm,'<h3 style="font-size:1rem;font-weight:700;color:#1e40af;margin:1.2em 0 .3em">$1</h3>').replace(/^## (.+)$/gm,'<h2 style="font-size:1.15rem;font-weight:700;color:#1e40af;margin:1.4em 0 .4em">$1</h2>').replace(/^# (.+)$/gm,'<h1 style="font-size:1.35rem;font-weight:800;color:#1e40af;margin:1.5em 0 .5em">$1</h1>').replace(/\*\*\*([\s\S]+?)\*\*\*/g,"<strong><em>$1</em></strong>").replace(/___([\s\S]+?)___/g,"<strong><em>$1</em></strong>").replace(/\*\*(.+?)\*\*/g,"<strong>$1</strong>").replace(/__(.+?)__/g,"<strong>$1</strong>").replace(/\*(.+?)\*/g,"<em>$1</em>").replace(/_(.+?)_/g,"<em>$1</em>").replace(/^[-*] (.+)$/gm,'<li style="margin-left:1.5em;margin-bottom:.3em;list-style-type:disc">$1</li>').replace(/^\d+\. (.+)$/gm,'<li style="margin-left:1.5em;margin-bottom:.3em;list-style-type:decimal">$1</li>').replace(/((?:<li[^>]*>.*?<\/li>\n?)+)/g,'<ul style="margin:.4em 0;padding-left:.5em">$1</ul>').replace(/\n{2,}/g,'</p><p style="margin:.6em 0">').replace(/\n/g,"<br>")}async function checkAndShowPolicies(e){let n;try{n=await apiCall("/api/v1/policy/status","GET",null,!0)}catch(p){if(p.message==="SESSION_EXPIRED")return;e();return}const i=[];if(n.token_valid===!1){authToken=null,currentUsername=null,localStorage.removeItem("fluxdrop_token"),localStorage.removeItem("fluxdrop_username"),renderApp("login"),showMessage(t("session_expired"),t("session_expired_msg"));return}if(n.needs_tos&&i.push({type:"tos",version:n.current_tos}),n.needs_pp&&i.push({type:"pp",version:n.current_pp}),i.length===0){e();return}document.getElementById("fd-boot-loading")?.remove();async function o(){if(i.length===0){e();return}const{type:p,version:l}=i.shift();await _showPolicyAgreementModal(p,l,o)}o()}async function _showPolicyAgreementModal(e,n,i){const o=POLICY_LABELS[e]||e.toUpperCase(),p=await _fetchVersions(),l=p.languages||{},r=p[e]||{},s=Object.keys(r).length?Object.keys(r):["eng"];let a=s.includes(_policyLang)?_policyLang:s[0];function d(){m.disabled=!1,m.style.opacity="1",m.style.cursor="pointer"}const f=document.createElement("div");f.style.cssText=["position:fixed;top:0;left:0;width:100%;height:100%;z-index:10001","background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:1rem","animation:fd-fade-in .18s ease"].join(";"),f.innerHTML=`
        <div class="fd-modal-panel-in" style="background:#fff;border-radius:1rem;width:100%;max-width:720px;
                    max-height:92vh;display:flex;flex-direction:column;overflow:hidden;
                    box-shadow:0 24px 48px rgba(0,0,0,.4)">
            <div style="padding:1.25rem 1.5rem;background:#eff6ff;border-bottom:1px solid #bfdbfe;
                        display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:.5rem">
                <div>
                    <h2 style="font-size:1.1rem;font-weight:700;color:#1e40af;margin:0 0 .25rem;display:flex;align-items:center;gap:.5rem">
                        ${t("policy_review_title",{label:o})}
                        ${_langSelectorHtml(s,l,a,"pam-lang")}
                    </h2>
                    <p style="font-size:.85rem;color:#3730a3;margin:0">
                        ${t("policy_version_note",{version:n})}
                    </p>
                </div>
            </div>
            <div id="pam-body" class="fd-md-body" data-fd-notranslate style="padding:1.5rem;overflow-y:auto;flex:1;
                                      font-size:.92rem;line-height:1.7;color:#1e293b">
                <div id="pam-skeleton" style="padding:.5rem 0">
                    ${Array.from({length:18},(E,k)=>`<div style="height:13px;border-radius:4px;margin-bottom:10px;width:${[92,78,85,65,88,70,95,60,82,74,90,55,87,72,80,68,93,63][k]+"%"};background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%);background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></div>`).join("")}
                </div>
            </div>
            <div style="padding:1rem 1.5rem;border-top:1px solid #e2e8f0;
                        display:flex;align-items:center;justify-content:space-between;gap:1rem;background:#f8fafc">
                <span id="pam-scroll-hint" style="font-size:.82rem;color:#94a3b8">
                    ${t("policy_scroll_hint")}
                </span>
                <div style="display:flex;gap:8px">
                    <button id="pam-decline-btn" class="btn" style="background:#e2e8f0;color:#1e293b">
                        ${t("policy_decline_btn")}
                    </button>
                    <button id="pam-agree-btn" class="btn" disabled style="opacity:.45;cursor:not-allowed;white-space:nowrap">
                        ${t("policy_agree_btn",{label:o})}
                    </button>
                </div>
            </div>
        </div>`,document.body.appendChild(f);const c=f.querySelector("#pam-body"),m=f.querySelector("#pam-agree-btn"),u=f.querySelector("#pam-scroll-hint");c.addEventListener("scroll",()=>{c.scrollHeight-c.scrollTop-c.clientHeight<40&&(d(),u.textContent=t("policy_scroll_done"))}),m.addEventListener("click",async()=>{m.disabled=!0,m.textContent=t("policy_saving");const E=showSpinnerOverlay("Saving your agreement…",{minMs:1e3});try{await withMinDelay(apiCall("/api/v1/policy/accept","POST",{[e]:n}),1e3),E(),window.fdCloseOverlay(f),i()}catch(k){if(E(),k.message==="SESSION_EXPIRED"){window.fdCloseOverlay(f);return}m.disabled=!1,m.textContent=t("policy_agree_btn",{label:o}),showMessage(t("msg_error"),t("policy_save_failed")+": "+k.message)}}),f.querySelector("#pam-decline-btn").addEventListener("click",()=>{window.fdCloseOverlay(f),showMessage(t("policy_not_accepted"),t("policy_logout_msg")),handleLogout()});const h=f.querySelector("#pam-lang");h&&h.addEventListener("change",()=>{a=h.value,_policyLang=a,localStorage.setItem("fluxdrop_policy_lang",a),m.disabled=!0,m.style.opacity=".45",m.style.cursor="not-allowed",u.textContent=t("policy_scroll_hint"),b(a)});async function b(E){const k=r[E]||n;c.innerHTML=`<div id="pam-skeleton" style="padding:.5rem 0">
            ${Array.from({length:18},(w,y)=>`<div style="height:13px;border-radius:4px;margin-bottom:10px;width:${[92,78,85,65,88,70,95,60,82,74,90,55,87,72,80,68,93,63][y]+"%"};background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%);background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></div>`).join("")}
        </div>`,c.scrollTop=0;try{const w=await fetch(_policyUrl(e,E,k),{cache:"no-cache",signal:AbortSignal.timeout(15e3)});if(!w.ok)throw new Error(`HTTP ${w.status}`);const y=await w.text();try{await _loadMarked(),c.innerHTML=_mdParseAndSanitize(y)}catch{c.innerHTML=_mdToHtml(y)}c.scrollHeight<=c.clientHeight+40&&(d(),u.textContent="")}catch(w){const x=w.name==="TimeoutError"||w.name==="AbortError"?t("policy_load_slow"):`${t("policy_load_failed")} (${w.message})`;c.innerHTML=`
                <p style="color:#dc2626">${escapeHtml(x)}</p>
                <p>
                    <button id="pam-retry-btn" class="btn" style="background:#3b82f6;margin-right:8px">${escapeHtml(t("retry_btn"))}</button>
                    ${escapeHtml(t("policy_load_retry_hint"))}
                </p>`;const v=c.querySelector("#pam-retry-btn");v&&v.addEventListener("click",()=>b(E)),d(),u.textContent=""}}b(a)}function renderLoginView(){appRoot.dataset.fdLanding||renderLandingView(),_showAuthModal("login")}function renderRegisterView(){appRoot.dataset.fdLanding||renderLandingView(),_showAuthModal("register")}function _showAuthModal(e){document.getElementById("fd-auth-modal")?.remove();const n=document.createElement("div");n.id="fd-auth-modal",n.style.cssText="position:fixed;inset:0;background:rgba(15,23,42,.48);display:flex;align-items:center;justify-content:center;z-index:9500;padding:1rem;backdrop-filter:blur(4px);animation:fd-fade-in .18s ease",n.innerHTML=`
        <div id="fd-auth-card"
             style="background:var(--fd-surface,#fff);border-radius:1.25rem;width:100%;
                    max-width:400px;box-shadow:0 24px 64px rgba(0,0,0,.3);overflow:hidden;
                    animation:fd-modal-in .22s cubic-bezier(.22,1,.36,1)">

            <!-- Tabs -->
            <div style="display:flex;border-bottom:2px solid var(--fd-border,#e2e8f0)">
                <button id="fd-tab-login" data-tab="login"
                    style="flex:1;padding:.85rem 1rem;background:none;border:none;
                           font-weight:700;font-size:.93rem;cursor:pointer;font-family:inherit;
                           color:#3b82f6;border-bottom:2px solid #3b82f6;margin-bottom:-2px;
                           transition:color .15s,border-color .15s">
                    ${t("login")}
                </button>
                <button id="fd-tab-register" data-tab="register"
                    style="flex:1;padding:.85rem 1rem;background:none;border:none;
                           font-weight:600;font-size:.93rem;cursor:pointer;font-family:inherit;
                           color:#94a3b8;border-bottom:2px solid transparent;margin-bottom:-2px;
                           transition:color .15s,border-color .15s">
                    ${t("register")}
                </button>
            </div>

            <div style="padding:1.5rem">
                <!-- Google OAuth (visual-only placeholder) -->
                <button id="fd-google-btn" disabled title="${t("google_coming_soon")}"
                    style="width:100%;display:flex;align-items:center;justify-content:center;
                           gap:.65rem;padding:.72rem 1rem;border:1.5px solid var(--fd-border,#e2e8f0);
                           border-radius:.75rem;background:var(--fd-surface,#fff);font-size:.9rem;
                           font-weight:600;color:var(--fd-text,#374151);cursor:not-allowed;
                           opacity:.6;margin-bottom:1rem;font-family:inherit">
                    <svg width="18" height="18" viewBox="0 0 18 18" style="flex-shrink:0" aria-hidden="true">
                        <path fill="#4285F4" d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.716v2.259h2.908C16.658 14.016 17.64 11.707 17.64 9.2z"/>
                        <path fill="#34A853" d="M9 18c2.43 0 4.467-.806 5.956-2.184l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18z"/>
                        <path fill="#FBBC05" d="M3.964 10.706A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.706V4.962H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.038l3.007-2.332z"/>
                        <path fill="#EA4335" d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.962L3.964 6.294C4.672 4.167 6.656 3.58 9 3.58z"/>
                    </svg>
                    ${t("continue_with_google")}
                    <span style="font-size:.75rem;color:#94a3b8;font-weight:400">(${t("google_coming_soon")})</span>
                </button>

                <!-- Divider -->
                <div style="display:flex;align-items:center;gap:.6rem;margin-bottom:1rem">
                    <div style="flex:1;height:1px;background:var(--fd-border,#e2e8f0)"></div>
                    <span style="font-size:.8rem;color:#94a3b8">${t("auth_or")}</span>
                    <div style="flex:1;height:1px;background:var(--fd-border,#e2e8f0)"></div>
                </div>

                <!-- Login form -->
                <form id="fd-login-form"
                      style="display:${e==="login"?"flex":"none"};flex-direction:column;gap:.75rem">
                    <input type="text" id="username" class="w-full p-3 border rounded-lg"
                           placeholder="${t("username")}" required autocomplete="username">
                    <input type="password" id="password" class="w-full p-3 border rounded-lg"
                           placeholder="${t("password")}" required autocomplete="current-password">
                    <button type="submit" class="btn w-full">${t("login")}</button>
                </form>

                <!-- Register form -->
                <form id="fd-register-form"
                      style="display:${e==="register"?"flex":"none"};flex-direction:column;gap:.75rem">
                    <input type="text" id="reg-username" class="w-full p-3 border rounded-lg"
                           placeholder="${t("placeholder_username")}" required autocomplete="username">
                    <input type="text" id="reg-nickname" class="w-full p-3 border rounded-lg"
                           placeholder="${t("placeholder_nickname")}" required autocomplete="nickname">
                    <input type="email" id="reg-email" class="w-full p-3 border rounded-lg"
                           placeholder="${t("placeholder_email")}" required autocomplete="email">
                    <input type="password" id="reg-password" class="w-full p-3 border rounded-lg"
                           placeholder="${t("password")}" required autocomplete="new-password">
                    <button type="submit" class="btn w-full">${t("register")}</button>
                </form>
            </div>
        </div>`,document.body.appendChild(n),n.querySelectorAll("#fd-tab-login, #fd-tab-register").forEach(i=>{i.addEventListener("click",()=>{const o=i.id==="fd-tab-login"?"login":"register";["login","register"].forEach(p=>{const l=n.querySelector("#fd-tab-"+p),r=n.querySelector("#fd-"+p+"-form"),s=p===o;l.style.color=s?"#3b82f6":"#94a3b8",l.style.fontWeight=s?"700":"600",l.style.borderBottomColor=s?"#3b82f6":"transparent",r.style.display=s?"flex":"none"})})}),n.addEventListener("click",i=>{i.target===n&&window.fdCloseOverlay(n)}),n.querySelector("#fd-login-form").addEventListener("submit",handleLogin),n.querySelector("#fd-register-form").addEventListener("submit",handleRegister)}function renderFileBrowserView(){appRoot.innerHTML=`
        <div class="card" style="min-height:520px">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:1rem;flex-wrap:wrap">
                <h2 class="text-2xl font-semibold text-blue-800" style="flex-shrink:0">${t("file_browser_title")}</h2>
                <div style="display:flex;gap:6px;align-items:center;min-width:0;flex-wrap:wrap;justify-content:flex-end">
                    <!-- Mobile-only collapse toggle -->
                    <button id="btn-toolbar-toggle" class="fd-toolbar-toggle btn text-sm"
                        style="display:none;padding:.4rem .6rem;font-size:15px" title="Toolbar">⋯</button>
                    <!-- Toolbar buttons — collapsible on mobile -->
                    <div id="fd-toolbar-btns" style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end">
                        <button id="btn-up" class="btn bg-gray-300 text-black text-sm" style="padding:.45rem .9rem">${t("up")}</button>
                        <button id="btn-refresh" class="btn text-sm" style="padding:.45rem .9rem">${t("refresh")}</button>
                        <button id="btn-create-folder" class="btn bg-gray-200 text-black text-sm" style="padding:.45rem .9rem">${t("create_a_folder")}</button>
                        <button id="btn-browse-cdn" class="btn bg-yellow-300 text-black text-sm" style="padding:.45rem .9rem">${t("browse_cdn")}</button>
                        <button id="btn-trash" class="btn text-sm" style="background:#dc2626;color:#fff;padding:.45rem .9rem" title="${t("trash_title")}">${t("trash_bin_button")}</button>
                        <button id="btn-folders-mixed" class="btn text-sm" style="padding:.45rem .9rem" title="${t("folder_sort_first")}"></button>
                    </div>
                </div>
            </div>

            <div id="path-breadcrumb" class="text-sm text-gray-600 mb-4"></div>

            <!-- Selection action bar — always in the DOM so activating it never
                 shifts the file list.  Invisible when nothing is selected.
                 Ghost content (opacity:0 buttons) is injected by _updateSelBar()
                 immediately after this template is set as innerHTML. -->
            <div id="fd-sel-bar"
                 style="border-radius:8px;padding:7px 12px;margin-bottom:8px;
                        display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:13px;
                        background:var(--fd-accent-bg,#eff6ff);border:1px solid var(--fd-accent-border,#bfdbfe)">
            </div>

            <!-- Outer drag-and-drop zone — covers both the upload toolbar and the
                 file list so the entire content area accepts drops.
                 fd-upload-wrap defaults to hidden; JS reveals it when a fine pointer
                 (mouse/trackpad) is detected, so the form is never shown on touch-only
                 devices even if the CSS is cached or overridden. -->
            <div id="fd-drop-zone"
                 style="border:2px dashed transparent;border-radius:10px;
                        transition:border-color .15s,background .15s">

                <div class="mb-4 fd-upload-wrap" id="fd-upload-wrap" style="display:none">
                    <!-- Hidden real file input — triggered programmatically -->
                    <input type="file" id="upload-file" multiple style="display:none" />
                    <form id="upload-form" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;row-gap:6px">
                        <button type="button" id="btn-file-choose" class="btn text-sm"
                            style="background:#e2e8f0;color:#374151;font-weight:500;flex-shrink:0">
                            📎 <span id="upload-file-label">${t("no_file_selected")!=="no_file_selected"?t("no_file_selected"):"Choose files…"}</span>
                        </button>
                        <button type="button" id="btn-folder-toggle" class="btn text-sm"
                            style="background:#0ea5e9;flex-shrink:0;padding:.45rem .75rem" title="${t("folder_mode")}">${t("folder_button")}</button>
                        <label class="text-sm" style="flex-shrink:0;white-space:nowrap"><input type="checkbox" id="upload-protected" /> ${t("protected")}</label>
                        <button class="btn" id="btn-upload-submit" type="submit" style="flex-shrink:0;padding:.45rem .9rem">${t("upload")}</button>
                        <span id="upload-spinner" style="display:none;font-size:18px;animation:spin 0.8s linear infinite">⏳</span>
                        <button type="button" id="btn-show-queue"
                            class="btn text-sm hidden"
                            style="background:#6366f1;flex-shrink:0"
                            title="${t("upload_queue")}">
                            📋 ${t("upload_queue")} (<span id="queue-count">0</span>)
                        </button>
                        <button type="button" id="btn-resume-interrupted"
                            class="btn text-sm hidden"
                            style="background:#f59e0b;flex-shrink:0"
                            title="${t("interrupted")}">
                            ⟳ ${t("interrupted")} (<span id="interrupted-count">0</span>)
                        </button>
                    </form>
                </div>

                <!-- Drop hint — appears in the file-list gap while dragging over -->
                <div id="fd-drop-hint"
                     style="display:none;padding:14px 0 8px;text-align:center;
                            color:var(--fd-accent,#3b82f6);font-size:13px;
                            font-weight:500;pointer-events:none">
                    ⬆ Drop files or folders here to upload
                </div>

                <div id="file-list" class="mt-4" style="min-height:320px;user-select:none"></div>

            </div>

            <!-- Mobile-only floating upload button. Hidden by default;
                 _initMobileUploadFab() reveals it on touch-only devices —
                 the exact inverse of fd-upload-wrap's own visibility check,
                 since that toolbar hides itself there and nothing replaced it.
                 Bottom-LEFT to match #ul-tray's side (renderUploadTray, same
                 corner makes sense for an upload trigger) and to avoid sitting
                 under #dl-tray on the right; z-index above both trays (9000)
                 so it stays reachable even while a transfer is in progress. -->
            <button id="fd-mobile-upload-fab" type="button" title="${t("upload")}"
                style="display:none;position:fixed;left:18px;bottom:22px;width:52px;height:52px;
                       border-radius:50%;background:#3b82f6;color:#fff;border:none;
                       align-items:center;justify-content:center;font-size:22px;
                       box-shadow:0 6px 16px rgba(0,0,0,.3);z-index:9100;cursor:pointer">⬆</button>
        </div>
    `,document.getElementById("btn-refresh").addEventListener("click",()=>loadDirectory(currentPath)),document.getElementById("btn-up").addEventListener("click",()=>{if(currentPath==="/"||currentPath==="/cdn")return;let s=currentPath.replace(/\/+$/,""),a=s.lastIndexOf("/");a<=0?s="/":s=s.slice(0,a),navigateTo(s)}),document.getElementById("btn-create-folder").addEventListener("click",promptCreateFolder),document.getElementById("btn-browse-cdn").addEventListener("click",()=>navigateTo("/cdn")),document.getElementById("btn-trash").addEventListener("click",openTrashView),document.getElementById("btn-toolbar-toggle").addEventListener("click",()=>{document.getElementById("fd-toolbar-btns").classList.toggle("fd-toolbar-open")}),document.getElementById("btn-file-choose").addEventListener("click",()=>{document.getElementById("upload-file").click()}),document.getElementById("upload-file").addEventListener("change",function(){const s=this.files?this.files.length:0,a=document.getElementById("upload-file-label");a&&(a.textContent=s===0?t("no_file_selected")!=="no_file_selected"?t("no_file_selected"):"Choose files…":s===1?this.files[0].name:`${s} files selected`),_mobileUploadPending&&(_mobileUploadPending=!1,s>0&&handleUploadForm({preventDefault(){}}))});function e(){const s=document.getElementById("btn-folders-mixed");s&&(s.textContent=sortFoldersMixed?t("folder_sort_mix"):t("folder_sort_first"),s.style.background=sortFoldersMixed?"#6b7280":"#0ea5e9")}e(),document.getElementById("btn-folders-mixed").addEventListener("click",()=>{sortFoldersMixed=!sortFoldersMixed,localStorage.setItem("fluxdrop_sort_mixed",JSON.stringify(sortFoldersMixed)),e(),loadDirectory(currentPath)}),document.getElementById("upload-form").addEventListener("submit",handleUploadForm);let n=!1;const i=document.getElementById("btn-folder-toggle"),o=document.getElementById("upload-file");i.addEventListener("click",()=>{n=!n,n?(o.setAttribute("webkitdirectory",""),o.setAttribute("mozdirectory",""),o.removeAttribute("multiple"),i.textContent=t("file_button"),i.style.background="#6366f1",i.title=t("files_mode")):(o.removeAttribute("webkitdirectory"),o.removeAttribute("mozdirectory"),o.setAttribute("multiple",""),i.textContent=t("folder_button"),i.style.background="#0ea5e9",i.title=t("folder_mode")),o.value=""}),(function(){const a=document.getElementById("fd-upload-wrap");if(!a)return;const d=window.matchMedia("(pointer: fine)"),f=window.matchMedia("(hover: hover)");function c(){d.matches||f.matches?a.style.removeProperty("display"):a.style.display="none"}c(),d.addEventListener("change",c),f.addEventListener("change",c)})(),(function(){const a=document.getElementById("fd-mobile-upload-fab");if(!a)return;const d=window.matchMedia("(pointer: fine)"),f=window.matchMedia("(hover: hover)"),c=window.matchMedia("(max-width: 820px)");function m(){const u=!(d.matches||f.matches)||c.matches;a.style.display=u?"flex":"none"}m(),d.addEventListener("change",m),f.addEventListener("change",m),c.addEventListener("change",m),a.addEventListener("click",()=>{_mobileUploadPending=!0,document.getElementById("upload-file").click()})})(),(function(){const a=document.getElementById("fd-drop-zone"),d=document.getElementById("fd-drop-hint");if(!a||!window.matchMedia("(pointer: fine)").matches)return;let f=0;function c(u){f=u?Math.max(f,1):0,a.style.borderColor=u?"var(--fd-accent,#3b82f6)":"transparent",a.style.background=u?"var(--fd-accent-bg,#eff6ff)":"",d&&(d.style.display=u?"block":"none")}a.addEventListener("dragenter",u=>{u.preventDefault(),f++,c(!0)}),a.addEventListener("dragleave",()=>{--f<=0&&c(!1)}),a.addEventListener("dragover",u=>u.preventDefault());async function m(u){const g=[];let h=!1;async function b(k,w){if(k.isFile){const y=await new Promise((x,v)=>k.file(x,v));try{Object.defineProperty(y,"webkitRelativePath",{value:w+k.name,configurable:!0,writable:!1})}catch{}g.push({file:y,rel:w+k.name})}else if(k.isDirectory){h=!0;const y=k.createReader();let x;do{x=await new Promise((v,_)=>y.readEntries(v,_));for(const v of x)await b(v,w+k.name+"/")}while(x.length>0)}}const E=[];for(let k=0;k<u.length;k++){const w=u[k];if(w.kind!=="file")continue;const y=w.webkitGetAsEntry?.();if(y)E.push(y);else{const x=w.getAsFile();x&&g.push({file:x,rel:x.name})}}return await Promise.all(E.map(k=>b(k,""))),{results:g,hasDir:h}}a.addEventListener("drop",async u=>{u.preventDefault(),c(!1);const{results:g,hasDir:h}=await m(u.dataTransfer.items);if(!g.length)return;h&&!n?(n=!0,i&&(i.textContent=t("file_button")||"📄 Files",i.style.background="#6366f1",i.title=t("files_mode")||"Switch to file mode")):!h&&n&&(n=!1,i&&(i.textContent=t("folder_button")||"📁 Folder",i.style.background="#0ea5e9",i.title=t("folder_mode")||"Switch to folder mode"));const b=document.getElementById("upload-file-label");b&&(b.textContent=g.length===1?g[0].file.name:`${g.length} items dropped`);const E=document.getElementById("upload-protected")?.checked||!1,k=currentPath.startsWith("/cdn")?"catbox":"user",w=currentPath.endsWith("/")?currentPath:currentPath+"/";window.addEventListener("beforeunload",windowLock);const y=g.map(({file:v,rel:_})=>({file:v,destRel:w+_,ownerType:k,isProtected:E}));if(y.length===1)try{await uploadChunked(y[0].file,y[0].destRel,{ownerType:k}),_notifyUploadDone(1),showMessage(t("upload_successful"),t("upload_success_msg",{name:y[0].file.name})),loadDirectory(currentPath)}catch(v){v.name!=="PauseSignal"&&v.message!=="Upload cancelled"&&showMessage(t("upload_failed"),v.message||String(v))}finally{window.removeEventListener("beforeunload",windowLock)}else{let H=function(){window.removeEventListener("beforeunload",windowLock),_notifyUploadDone(T,B)};var x=H;const[v,..._]=y;window._uploadQueue=[...window._uploadQueue||[],..._];const S=()=>{const A=document.getElementById("btn-show-queue"),R=document.getElementById("queue-count");if(A&&R){const P=window._uploadQueue;P.length>0?(A.classList.remove("hidden"),R.textContent=P.length):A.classList.add("hidden")}};S(),_lastUploadBatchCount+=y.length;let T=0,B=0;async function F(A){for(;A;){try{await uploadChunked(A.file,A.destRel,{ownerType:A.ownerType}),T++,loadDirectory(currentPath)}catch(R){if(R.name==="PauseSignal"){_pausedQueueDrain=()=>{_pausedQueueDrain=null;let P=null;window._uploadQueue?.length>0&&(P=window._uploadQueue.shift(),S()),P?F(P):H()};return}R.message!=="Upload cancelled"&&(B++,showMessage(t("upload_failed"),`${A.file.name}: ${R.message||String(R)}`),window.removeEventListener("beforeunload",windowLock))}window._uploadQueue?.length>0?(A=window._uploadQueue.shift(),S()):A=null}H()}F(v)}})})(),window._uploadQueue=window._uploadQueue||[];function p(){const s=document.getElementById("btn-show-queue"),a=document.getElementById("queue-count");if(!s||!a)return;const d=window._uploadQueue;d.length>0?(s.classList.remove("hidden"),a.textContent=d.length):s.classList.add("hidden")}function l(){const s=document.getElementById("btn-resume-interrupted"),a=document.getElementById("interrupted-count");if(!s||!a)return;const d=getAllInterruptedUploads();d.length>0?(s.classList.remove("hidden"),a.textContent=d.length):s.classList.add("hidden")}p(),l(),document.getElementById("btn-show-queue").addEventListener("click",()=>{openUploadQueuePanel(p)});function r(){l()}document.getElementById("btn-resume-interrupted").addEventListener("click",()=>{openInterruptedManager(l)}),(function(){const a=_APP_BASE.replace(/[.*+?^${}()|[\]\\]/g,"\\$&"),d=window.location.pathname.match(new RegExp("^"+a+"/files(/.*)?$"));if(d)try{currentPath=decodeURIComponent(d[1]||"/")}catch{currentPath=d[1]||"/"}_syncUrlToPath(currentPath)})(),loadDirectory(currentPath)}function apiPathFor(e){return e||(e="/"),e.startsWith("/")||(e="/"+e),`/api/v1/list${encodePath(e)}`}function skeletonRows(e=6){const n=["background:linear-gradient(90deg,var(--fd-skel-base,#e2e8f0) 25%,var(--fd-skel-shine,#f1f5f9) 50%,var(--fd-skel-base,#e2e8f0) 75%)","background-size:200% 100%","animation:fd-shimmer 1.4s infinite","border-radius:4px","display:inline-block"].join(";");if(!document.getElementById("fd-shimmer-style")){const p=document.createElement("style");p.id="fd-shimmer-style",p.textContent="@keyframes fd-shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}",document.head.appendChild(p)}const i=[["55%","8%","14%"],["40%","10%","14%"],["62%","7%","14%"],["48%","9%","14%"],["35%","11%","14%"],["58%","8%","14%"]],o=["55%","40%","65%","48%","35%","60%"];return Array.from({length:e},(p,l)=>{const r=o[l%o.length];return`<tr class="border-t">
            <td style="padding:9px 8px;vertical-align:middle">
                <span style="${n};width:${r};height:14px"></span>
            </td>
            <td style="padding:9px 8px;vertical-align:middle">
                <span style="${n};width:70%;height:13px"></span>
            </td>
            <td style="padding:9px 8px;vertical-align:middle" class="fd-col-mtime">
                <span style="${n};width:80%;height:13px"></span>
            </td>
            <td style="padding:9px 8px;vertical-align:middle;text-align:right">
                <span style="${n};width:64px;height:24px;border-radius:6px;margin-left:4px"></span>
                <span style="${n};width:52px;height:24px;border-radius:6px;margin-left:4px"></span>
                <span style="${n};width:48px;height:24px;border-radius:6px;margin-left:4px"></span>
            </td>
        </tr>`}).join("")}async function loadDirectory(e){const n=document.getElementById("file-list"),i=document.getElementById("path-breadcrumb");e||(e="/"),e.startsWith("/")||(e="/"+e),currentPath=e,(function(r){const s=r.replace(/\/+$/,"").split("/").filter((f,c)=>c===0?!0:!!f);let a="",d="";s.forEach((f,c)=>{if(c===0)d="/",a+=`<button onclick="navigateTo('/')" style="background:none;border:none;color:#3b82f6;cursor:pointer;font-weight:600;padding:0 2px">${t("fluxdrop_file_manager_path_root")}</button>`;else{d=d.endsWith("/")?d+f:d+"/"+f;const m=d;a+=' <span style="color:#94a3b8">/</span> ',c===s.length-1?a+=`<span style="color:#1e293b;font-weight:600" data-fd-notranslate>${escapeHtml(f)}</span>`:a+=`<button onclick="navigateTo('${escapeHtmlAttr(m)}')" style="background:none;border:none;color:#3b82f6;cursor:pointer;padding:0 2px" data-fd-notranslate>${escapeHtml(f)}</button>`}}),i.innerHTML=a})(e);function o(){const l=[{key:"name",label:"Name",align:"left"},{key:"size",label:"Size",align:"left"},{key:"mtime",label:"Modified",align:"left",cls:"fd-col-mtime"}],r=(d,f)=>`padding:8px;font-size:12px;font-weight:600;color:#64748b;text-align:${d};user-select:none;white-space:nowrap;`,s="background:none;border:none;cursor:pointer;font-size:12px;font-weight:700;color:#64748b;padding:0;display:inline-flex;align-items:center;gap:3px;";return`<thead><tr style="border-bottom:2px solid #e2e8f0">
            ${l.map(d=>{const f=currentSort.key===d.key?currentSort.dir==="asc"?" ▲":" ▼":" ⇅",c=currentSort.key===d.key?"color:#2563eb;":"",m=d.cls?` class="${d.cls}"`:"";return`<th style="${r(d.align)}"${m}>
                <button onclick="window._sortBy('${d.key}')"
                    style="${s}${c}">${d.label}<span style="font-size:10px;opacity:.7">${f}</span></button>
            </th>`}).join("")}
            <th style="padding:4px 2px;font-size:14px;font-weight:400;color:#94a3b8;text-align:right;width:1px;white-space:nowrap">⋮</th>
        </tr></thead>`}const p=`<table style="width:100%;table-layout:fixed;border-collapse:collapse">
        <colgroup>
            <col style="width:auto">
            <col style="width:8%">
            <col class="fd-col-mtime" style="width:17%">
            <col style="width:72px">
        </colgroup>`;n.innerHTML=p+o()+`<tbody>${skeletonRows(7)}</tbody></table>`;try{const l=e==="/"?"/api/v1/list/":`/api/v1/list${encodePath(e)}`,s=(await apiCall(l,"GET",null,!0)).entries||[];if(s.length===0){n.innerHTML=`<p class="text-sm text-gray-600" style="padding:1rem">${t("empty_folder")}</p>`,_updateSelBar();return}const d=sortEntries(s).map(f=>renderEntryRow(f)).join("");n.innerHTML=p+o()+`<tbody>${d}</tbody></table>`,attachRowListeners(),_applySelectionVisuals(),_updateSelBar()}catch(l){if(l.message==="SESSION_EXPIRED")return;n.innerHTML=`<p class="text-sm text-red-600" style="padding:1rem">Failed to load directory: ${escapeHtml(l.message)}</p>`,_updateSelBar()}}function sortEntries(e){const{key:n,dir:i}=currentSort,o=i==="asc"?1:-1;function p(l,r){if(!sortFoldersMixed&&l.is_dir!==r.is_dir)return l.is_dir?-1:1;let s,a;return n==="size"?(s=l.is_dir?-1:l.size||0,a=r.is_dir?-1:r.size||0,o*(s-a)):n==="mtime"?(s=l.mtime||"",a=r.mtime||"",o*s.localeCompare(a)):o*(l.name||"").localeCompare(r.name||"",void 0,{sensitivity:"base"})}return e.slice().sort(p)}window._sortBy=function(e){currentSort.key===e?currentSort.dir=currentSort.dir==="asc"?"desc":"asc":currentSort={key:e,dir:"asc"},localStorage.setItem("fluxdrop_sort",JSON.stringify(currentSort)),loadDirectory(currentPath)};function _ab(e,n,i,o){const p=Object.entries(o).map(([l,r])=>`data-${l}="${r}"`).join(" ");return`<button class="${n}"
        style="background:${i};color:white;border:none;border-radius:6px;
               padding:3px 8px;font-size:11px;font-weight:600;cursor:pointer;
               white-space:nowrap;line-height:1.6"
        ${p}>${e}</button>`}function renderEntryRow(e){const n=escapeHtml(e.name),i=e.path,o=escapeHtmlAttr(i),p=e.is_dir&&e.size!=null,l=p&&e.file_count!=null?` title="${e.file_count} file${e.file_count!==1?"s":""}"`:"",r=e.is_dir?`<span class="folder-size-cell" data-path="${o}" ${p?'data-warm="1"':""}${l}
               style="color:#94a3b8">${p?formatBytes(e.size):"…"}</span>`:formatBytes(e.size),s='style="padding:9px 8px;vertical-align:middle;overflow:hidden;max-width:0"',a=e.is_dir?`<button class="open-btn fd-entry-name" data-path="${o}"
               style="background:none;border:none;cursor:pointer;font-weight:600;
                      color:var(--fd-accent,#2563eb);font-size:14px;text-align:left;padding:0;
                      white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;display:block"
               data-fd-notranslate title="${o}">📁 ${n}</button>`:`<button class="preview-btn fd-entry-name" data-path="${o}"
               style="background:none;border:none;cursor:pointer;font-weight:500;
                      color:var(--fd-text,#1e293b);font-size:14px;text-align:left;padding:0;
                      white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;display:block"
               data-fd-notranslate title="${o}">📄 ${n}</button>`,d=e.uploader?`<div style="font-size:11px;color:#94a3b8;margin-top:2px">by ${escapeHtml(e.uploader)}</div>`:"",f=`<button class="fd-more-btn" data-path="${o}" data-is-dir="${e.is_dir?"1":"0"}"
        style="background:none;border:1px solid var(--fd-border,#e2e8f0);border-radius:5px;
               padding:2px 7px;cursor:pointer;font-size:16px;line-height:1.3;
               color:var(--fd-muted,#64748b);vertical-align:middle;flex-shrink:0"
        title="Actions">⋮</button>`,c='style="padding:9px 8px;vertical-align:middle;white-space:nowrap"';return`<tr class="border-t fd-file-row"
                data-path="${o}"
                data-is-dir="${e.is_dir?"1":"0"}"
                data-name="${escapeHtmlAttr(e.name)}"
                data-size="${e.size||0}"
                data-mtime="${escapeHtmlAttr(e.mtime||"")}"
                data-uploader="${escapeHtmlAttr(e.uploader||"")}"
                style="transition:background 0.12s;user-select:none">
        <td ${s}>
            <div style="display:flex;align-items:center;gap:5px;overflow:hidden">
                <span class="fd-sel-dot" style="display:none;width:14px;height:14px;flex-shrink:0;
                    border:2px solid var(--fd-accent,#3b82f6);border-radius:3px;align-items:center;
                    justify-content:center;font-size:9px;background:transparent"></span>
                <div style="min-width:0;flex:1;overflow:hidden">${a}${d}</div>
            </div>
        </td>
        <td ${c} class="text-sm text-gray-500">${r}</td>
        <td ${c} class="text-sm text-gray-500 fd-col-mtime"
            style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${escapeHtmlAttr(e.mtime||"")}">${formatMtime(e.mtime)}</td>
        <td style="padding:4px 2px;vertical-align:middle;text-align:right;width:1px;white-space:nowrap">${f}</td>
    </tr>`}window.enterDir=function(e){navigateTo(e)};function formatBytes(e){function n(i){return i>=100?Math.round(i).toString():i>=10?i.toFixed(1):i.toFixed(2)}return e<1024?e+" B":e<1048576?n(e/1024)+" kB":e<1073741824?n(e/1048576)+" MB":n(e/1073741824)+" GB"}function formatMtime(e){if(!e)return"—";const n=new Date(e);if(isNaN(n.getTime()))return e;const i=n.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}),o=new Date,p=(r,s)=>r.getFullYear()===s.getFullYear()&&r.getMonth()===s.getMonth()&&r.getDate()===s.getDate();if(p(n,o))return t("fmt_today_at",{time:i});const l=new Date(o);return l.setDate(o.getDate()-1),p(n,l)?t("fmt_yesterday_at",{time:i}):n.toLocaleDateString([],{day:"numeric",month:"short",year:"numeric"})+" "+t("fmt_at_time",{time:i})}let _streamSaverLoaded=!1;function _loadStreamSaver(){return _streamSaverLoaded?Promise.resolve():new Promise((e,n)=>{const i=document.createElement("script");i.src=_APP_BASE+"/assets/streamsaver/StreamSaver.js",i.onload=()=>{_streamSaverLoaded=!0,typeof streamSaver<"u"&&(streamSaver.mitm=window.location.origin+_APP_BASE+"/assets/streamsaver/mitm.html"),e()},i.onerror=()=>n(new Error("StreamSaver unavailable")),document.head.appendChild(i)})}const _CAN_PICK=typeof window.showSaveFilePicker=="function";window.downloadFile=async function(e,n={}){if(activeDownloads.has(e)){renderDownloadTray();return}const i=n.filename||e.split("/").pop()||"download";let o=null,p;if(typeof window.showSaveFilePicker=="function"){const a=i.split(".").pop()||"",d=_mimeForExt(a);try{o=await window.showSaveFilePicker({suggestedName:i,types:d?[{description:"File",accept:{[d]:["."+a]}}]:void 0}),p="picker"}catch(f){if(f.name==="AbortError")return;logging_warn("showSaveFilePicker failed, falling to native:",f)}}p||(p="native");let l,r;if(n.directUrl)l=n.directUrl,r=n.totalSize||null;else try{const a=await mintDownloadToken(e),d=e.split("/").map(encodeURIComponent).join("/");l=`${API_BASE_URL}/api/v1/download${d}?dl_token=${encodeURIComponent(a.download_token)}`,r=a.total_size||null}catch(a){showMessage(t("download_failed"),a.message);return}if(p==="native"){const a={filename:i,totalSize:r,bytesReceived:0,status:"downloading",speed:null,eta:null,error:null,_writer:null,_abort:new AbortController,_resumeFrom:0,_chunks:[],_mode:"native",_dlUrl:l,_path:e,_fileHandle:null};activeDownloads.set(e,a),renderDownloadTray();const d=document.createElement("a");d.href=l,d.download=i,document.body.appendChild(d),d.click(),document.body.removeChild(d),a.status="done";const f=getTrayDismissDelay();setTimeout(()=>{activeDownloads.delete(e),renderDownloadTray()},Math.max(f,4e3)),renderDownloadTray();return}if(p==="blob"&&r&&r>512*1024*1024&&!confirm(`⚠ Your browser doesn't support streaming downloads to disk.

Downloading ${formatBytes(r)} will be buffered entirely in RAM before saving, which may freeze or crash the tab.

Use Chrome or Edge for large files. Continue anyway?`))return;const s={filename:i,totalSize:r,bytesReceived:0,status:"downloading",speed:null,eta:null,error:null,_writer:null,_abort:new AbortController,_resumeFrom:0,_chunks:[],_mode:p,_dlUrl:l,_path:e,_fileHandle:o};activeDownloads.set(e,s),renderDownloadTray(),await _runDownload(e,s)};async function _runDownload(e,n){if(!n._writer&&n._mode!=="blob")try{if(n._mode==="picker"){const l=n.filename.split(".").pop()||"",r=_mimeForExt(l);if(n._resumeFrom>0)if(n._fileHandle)n._writer=await n._fileHandle.createWritable({keepExistingData:!0}),await n._writer.seek(n._resumeFrom);else{n._resumeFrom=0,n.bytesReceived=0;const a=await window.showSaveFilePicker({suggestedName:n.filename,types:r?[{description:"File",accept:{[r]:["."+l]}}]:void 0});n._fileHandle=a,n._writer=await n._fileHandle.createWritable({keepExistingData:!1})}else{if(!n._fileHandle){const a=await window.showSaveFilePicker({suggestedName:n.filename,types:r?[{description:"File",accept:{[r]:["."+l]}}]:void 0});n._fileHandle=a}n._writer=await n._fileHandle.createWritable({keepExistingData:!1})}}else{const l=streamSaver.createWriteStream(n.filename,{size:n.totalSize||void 0});n._writer=l.getWriter()}}catch(l){if(l.name==="AbortError"){activeDownloads.delete(e),renderDownloadTray();return}n._mode="blob",n._writer=null,logging_warn("showSaveFilePicker/StreamSaver failed, falling back to blob:",l)}n.status="downloading",n._abort=new AbortController,renderDownloadTray();const i={...n._authHeader||{}};authToken&&!i.Authorization&&(i.Authorization=`Bearer ${authToken}`),n._resumeFrom>0&&(i.Range=`bytes=${n._resumeFrom}-`);const o=3,p=2e3;try{let l;for(let c=0;;c++)try{l=await fetchWithFallback(n._dlUrl,{headers:i,signal:n._abort.signal});break}catch(m){if(m.name==="AbortError"||c>=o)throw m;const u=p*Math.pow(2,c);n.status="downloading",n._retrying=!0;for(let g=Math.round(u/1e3);g>0;g--)n.error=`Network error — retrying in ${g}s (${c+1}/${o})`,renderDownloadTray(),await new Promise((h,b)=>{const E=setTimeout(h,1e3);n._abort.signal.addEventListener("abort",()=>{clearTimeout(E),b(new DOMException("Aborted","AbortError"))},{once:!0})});n._retrying=!1,n.error=null,renderDownloadTray()}if(!l.ok&&l.status!==206)throw new Error(`Server returned HTTP ${l.status}`);const r=l.headers.get("Content-Range");if(r){const c=r.match(/bytes \d+-\d+\/(\d+)/);c&&(n.totalSize=parseInt(c[1]))}else if(!n.totalSize){const c=l.headers.get("Content-Length");c&&(n.totalSize=parseInt(c))}renderDownloadTray();const s=l.body.getReader();let a=n.bytesReceived,d=Date.now();try{for(;;){const{done:c,value:m}=await s.read();if(c)break;n._mode==="blob"?n._chunks.push(m):await n._writer.write(m),n.bytesReceived+=m.byteLength,n._resumeFrom+=m.byteLength;const u=Date.now(),g=(u-d)/1e3;g>=.4&&(n.speed=(n.bytesReceived-a)/g,n.eta=n.speed>0&&n.totalSize?(n.totalSize-n.bytesReceived)/n.speed:null,a=n.bytesReceived,d=u),renderDownloadTray()}}catch(c){if(c.name!=="AbortError"&&(c.message?.includes("channel")||c.message?.includes("port1")||c.message?.includes("port2"))){if(n._writer){try{n._writer.abort?.()}catch{}n._writer=null}try{s.cancel("channel closed")}catch{}n._abort.abort(),n.status="cancelled",n._resumeFrom=0,n.bytesReceived=0,n.error="Browser dropped the download. Click Resume to start over.",renderDownloadTray();return}throw c}if(n._mode==="blob"){const c=new Blob(n._chunks);n._chunks=[];const m=document.createElement("a");m.href=URL.createObjectURL(c),m.download=n.filename,m.click(),setTimeout(()=>URL.revokeObjectURL(m.href),6e4)}else await n._writer.close(),n._writer=null;n.status="done",n.speed=null,n.eta=null;const f=getTrayDismissDelay();f>0&&!n._dismissScheduled&&(n._dismissScheduled=!0,setTimeout(()=>{activeDownloads.delete(e),renderDownloadTray()},f)),renderDownloadTray()}catch(l){if(l.name==="AbortError")n.status=n._userCancelled?"cancelled":"paused",n._userCancelled&&(n.error="Download cancelled.",n._userCancelled=!1);else if(n.status="error",n.error=l.message,n._writer){try{await n._writer.abort?.()??n._writer.close()}catch{}n._writer=null}renderDownloadTray()}}window.resumeDownload=async function(e){const n=decodeURIComponent(e),i=activeDownloads.get(n);if(i){if(i.status==="cancelled"&&(i.error=null,i.speed=null,i.eta=null,i._writer=null,i._resumeFrom=0,i.bytesReceived=0,i.totalSize=null,i._chunks=[],i._isZip)){activeDownloads.delete(n),renderDownloadTray();const o=n.startsWith("__zip__")?n.slice(7):n;window.downloadFolderZip(o);return}if(!i._isZip)try{const o=await mintDownloadToken(n),p=n.split("/").map(encodeURIComponent).join("/");i._dlUrl=`${API_BASE_URL}/api/v1/download${p}?dl_token=${encodeURIComponent(o.download_token)}`;const l=o.bytes_confirmed||0;l<i._resumeFrom&&(i._resumeFrom=l)}catch(o){showMessage(t("im_resume_failed"),o.message);return}if(i.error=null,i.speed=null,i.eta=null,i._isZip&&!i._writer&&i._mode==="streamsaver")try{const o=streamSaver.createWriteStream(i.filename);i._writer=o.getWriter()}catch{i._mode="blob",i._writer=null}i._writer=i._isZip?i._writer:null,await _runDownload(n,i)}},window.cancelDownload=function(e){try{e=decodeURIComponent(e)}catch{}const n=activeDownloads.get(e);n&&(n._userCancelled=!0,n._abort?.abort(),n._writer&&(n._writer.abort?.().catch(()=>{}),n._writer=null),n._fileHandle=null),activeDownloads.delete(e),renderDownloadTray()},window.downloadFolderZip=async function(e){const n="__zip__"+e;if(activeDownloads.has(n)){renderDownloadTray();return}const o=(e.split("/").filter(Boolean).pop()||"download")+".zip",p=`${API_BASE_URL}/api/v1/zip_meta${e.split("/").map(encodeURIComponent).join("/")}`,l=authToken?{Authorization:`Bearer ${authToken}`}:{},r={filename:o,totalSize:null,bytesReceived:0,status:"downloading",speed:null,eta:null,error:null,_writer:null,_abort:new AbortController,_resumeFrom:0,_chunks:[],_mode:"native",_dlUrl:null,_path:n,_isZip:!0,_authHeader:l,_needsHashing:!1,_jobId:null};activeDownloads.set(n,r),renderDownloadTray();let s;try{const g=await fetchWithFallback(p,{headers:l,signal:r._abort.signal});if(s=await g.json(),!g.ok)throw new Error(s.error||`HTTP ${g.status}`)}catch(g){r.status=g.name==="AbortError"?r._userCancelled?"cancelled":"paused":"error",r.error=g.name==="AbortError"?null:g.message,renderDownloadTray();return}r._jobId=s.job_id;const a=`${API_BASE_URL}${s.poll_url}`;renderDownloadTray();let d=null;for(;;){if(r._abort.signal.aborted){r.status=r._userCancelled?"cancelled":"paused",renderDownloadTray();return}if(await new Promise(h=>{const b=setTimeout(h,1e3);r._abort.signal.addEventListener("abort",()=>{clearTimeout(b),h()},{once:!0})}),r._abort.signal.aborted){r.status=r._userCancelled?"cancelled":"paused",renderDownloadTray();return}let g;try{const h=await fetchWithFallback(a,{headers:l,signal:r._abort.signal});if(g=await h.json(),!h.ok)throw new Error(g.error||`HTTP ${h.status}`)}catch(h){if(h.name==="AbortError")continue;r.status="error",r.error=h.message,renderDownloadTray();return}if(g.status==="error"){r.status="error",r.error=g.error||"Server error building archive",renderDownloadTray();return}if(g.status==="scanning"){const h=g.progress??0,b=g.total;r._needsHashing=!0,r._scanProgress={prog:h,total:b},renderDownloadTray();continue}if(g.status==="ready"){d=g;break}}r._needsHashing=!!d.needs_hashing,r.totalSize=d.size||null,r.filename=d.filename||r.filename,r.error=d.missing&&d.missing.length>0?`⚠ ${d.missing.length} file(s) skipped (unreadable)`:null;const f=`${API_BASE_URL}${d.url}`,c=authToken?`${f}?token=${encodeURIComponent(authToken)}`:f,m=document.createElement("a");if(m.href=c,m.download=r.filename,m.style.display="none",document.body.appendChild(m),d.missing&&d.missing.length>0){const g=d.missing.map(b=>`<li style="font-family:monospace;font-size:12px">${b}</li>`).join(""),h=document.createElement("div");if(h.className="modal-overlay",h.innerHTML=`<div class="modal-content" style="max-width:480px">
            <h3 style="font-size:16px;font-weight:700;margin-bottom:8px">⚠ ${d.missing.length} file(s) will be skipped</h3>
            <p style="font-size:13px;color:#64748b;margin-bottom:10px">These files could not be read and will be absent from the ZIP:</p>
            <ul style="max-height:200px;overflow-y:auto;padding-left:18px;margin-bottom:16px">${g}</ul>
            <div style="display:flex;gap:8px;justify-content:flex-end">
                <button id="zip-missing-cancel" class="btn" style="background:#e2e8f0;color:#1e293b">Cancel</button>
                <button id="zip-missing-ok" class="btn">Download anyway</button>
            </div>
        </div>`,document.body.appendChild(h),await new Promise(b=>{h.querySelector("#zip-missing-ok").addEventListener("click",()=>{h.remove(),b(!0)}),h.querySelector("#zip-missing-cancel").addEventListener("click",()=>{h.remove(),b(!1),r.status="cancelled",renderDownloadTray()})}).then(b=>{}),r.status==="cancelled")return}m.click(),document.body.removeChild(m),r.status="done",renderDownloadTray();const u=getTrayDismissDelay();u>0&&setTimeout(()=>{activeDownloads.delete(n),renderDownloadTray()},u)};function _mimeForExt(e){return{mp4:"video/mp4",webm:"video/webm",mkv:"video/x-matroska",mp3:"audio/mpeg",flac:"audio/flac",wav:"audio/wav",m4a:"audio/mp4",jpg:"image/jpeg",jpeg:"image/jpeg",png:"image/png",gif:"image/gif",webp:"image/webp",svg:"image/svg+xml",pdf:"application/pdf",zip:"application/zip",tar:"application/x-tar",txt:"text/plain",md:"text/markdown",json:"application/json",js:"text/javascript",css:"text/css",html:"text/html"}[e.toLowerCase()]||null}function logging_warn(...e){console.warn("[FluxDrop]",...e)}const activeDownloads=new Map;async function mintDownloadToken(e){return await apiCall("/api/v1/download_token","POST",{path:e})}function renderDownloadTray(){let e=document.getElementById("dl-tray");if(e||(e=document.createElement("div"),e.id="dl-tray",e.style.cssText=`
            position:fixed; bottom:0; right:1rem; width:340px; max-height:60vh;
            overflow-y:auto; background:#1e293b; border-radius:12px 12px 0 0;
            box-shadow:0 -4px 24px rgba(0,0,0,0.4); z-index:9000;
            font-family:Inter,sans-serif; font-size:13px; color:#e2e8f0;
        `,document.body.appendChild(e),e.classList.add("fd-tray-in"),e.addEventListener("animationend",()=>e.classList.remove("fd-tray-in"),{once:!0})),activeDownloads.size===0){e.innerHTML.trim()!==""&&window.fdCollapseTray(e).then(()=>{activeDownloads.size===0&&(e.innerHTML="")});return}e.classList.remove("fd-tray-closing");let n=e.querySelector(".dl-tray-header");n||(n=document.createElement("div"),n.className="dl-tray-header",n.style.cssText="padding:10px 14px 6px;font-weight:700;font-size:14px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center;",n.innerHTML='<span class="dl-count"></span><span style="cursor:pointer;opacity:.6" id="dl-tray-close">✕</span>',e.prepend(n),n.querySelector("#dl-tray-close").addEventListener("click",async()=>{await window.fdCollapseTray(e),e.innerHTML=""})),n.querySelector(".dl-count").textContent=`📥 Downloads (${activeDownloads.size})`,e.querySelectorAll(".dl-row").forEach(i=>{activeDownloads.has(i.dataset.dlPath)||i.remove()});for(const[i,o]of activeDownloads){const p=o.totalSize?Math.round(o.bytesReceived/o.totalSize*100):0,l=formatBytes(o.bytesReceived),r=o.totalSize?formatBytes(o.totalSize):"?",s=o.filename||i.split("/").pop(),a=i.replace(/\\/g,"\\\\").replace(/"/g,'\\"');let d=e.querySelector(`.dl-row[data-dl-path="${CSS.escape(i)}"]`);if(!d){d=document.createElement("div"),d.className="dl-row",d.dataset.dlPath=i,d.style.cssText="padding:10px 14px;border-bottom:1px solid #1e293b",d.innerHTML=`
                <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                    <span class="dl-name" title="${escapeHtml(s)}"
                        style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px"></span>
                    <span class="dl-bytes" style="color:#94a3b8"></span>
                </div>
                <div style="background:#334155;border-radius:4px;height:6px;margin-bottom:6px">
                    <div class="dl-bar"
                        style="background:#3b82f6;height:6px;border-radius:4px;width:0%;transition:width .3s"></div>
                </div>
                <div style="display:flex;justify-content:space-between;align-items:center">
                    <span class="dl-status" style="color:#64748b"></span>
                    <div class="dl-actions"></div>
                </div>`,e.appendChild(d),requestAnimationFrame(()=>{e.scrollTop=e.scrollHeight});const k=d.querySelector(".dl-actions"),w=document.createElement("button");w.textContent=t("cancel"),w.style.cssText="background:#ef4444;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px",w.addEventListener("click",()=>cancelDownload(i));const y=document.createElement("button");y.textContent=t("dl_resume"),y.style.cssText="background:#3b82f6;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px",y.addEventListener("click",()=>resumeDownload(encodeURIComponent(i)));const x=document.createElement("button");x.textContent=t("cancel"),x.style.cssText="background:#64748b;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px;margin-left:4px",x.addEventListener("click",()=>cancelDownload(i));const v=document.createElement("button");v.textContent=t("dl_dismiss"),v.style.cssText="background:#64748b;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px",v.addEventListener("click",()=>{activeDownloads.delete(i),renderDownloadTray()}),d._btns={cancelBtn:w,resumeBtn:y,abortBtn:x,dismissBtn:v,actionsDiv:k}}const f={downloading:"⬇",paused:"⏸",error:"⚠",done:"✅",cancelled:"🚫"};d.querySelector(".dl-name").textContent=(f[o.status]||"")+" "+s,d.querySelector(".dl-bytes").textContent=`${l} / ${r}`;const c=d.querySelector(".dl-bar");c.style.width=p+"%",c.style.background=o._retrying?"#f59e0b":"#3b82f6",c.style.animation=o._retrying?"fd-retry-pulse 1s ease-in-out infinite":"";let m=o.status;if(o.status==="downloading"){const k=[];if(o.speed!=null&&k.push(formatSpeed(o.speed)),o.eta!=null&&k.push("ETA "+formatEta(o.eta)),k.length)m=k.join(" · ");else if(o._retrying&&o.error)m="🔄 "+o.error;else if(o._mode==="native")m="Downloading via browser…";else if(o._isZip&&!o._dlUrl){const w=o._scanProgress,y=w&&w.total?` (${w.prog}/${w.total} files)`:"";m=(o._needsHashing?"Hashing files on demand…":"Building archive…")+y}else m=""}else o.status==="error"?m="⚠ "+(o.error||"failed"):o.status==="cancelled"?m=o.error||"Cancelled":o.status==="paused"&&(m="Paused");d.querySelector(".dl-status").textContent=m;const{actionsDiv:u,cancelBtn:g,resumeBtn:h,abortBtn:b,dismissBtn:E}=d._btns;u.innerHTML="",o.status==="downloading"?u.appendChild(g):o.status==="paused"||o.status==="error"?(u.appendChild(h),u.appendChild(b)):o.status==="cancelled"?(u.appendChild(h),u.appendChild(E)):o.status==="done"&&u.appendChild(E)}}const EXT_IMAGE=new Set(["jpg","jpeg","png","gif","webp","bmp","svg","ico","avif","tiff","tif"]),EXT_IMAGE_HEIC=new Set(["heic","heif"]),EXT_VIDEO=new Set(["mp4","webm","ogg","ogv","mov","m4v","mkv","avi"]),EXT_AUDIO=new Set(["mp3","wav","flac","aac","ogg","oga","m4a","opus","weba"]),EXT_TEXT=new Set(["txt","js","ts","jsx","tsx","py","sh","bash","json","xml","yaml","yml","toml","ini","cfg","conf","html","htm","css","scss","less","csv","log","env","rs","go","c","cpp","h","java","rb","php","swift","kt","sql","r","lua"]),EXT_MARKDOWN=new Set(["md","markdown","mdown","mkd"]),EXT_ARCHIVE=new Set(["zip","tar","gz","tgz","bz2","tbz2","xz","txz","7z","rar","zst","lz4","lzma","cab","iso","dmg","pkg","deb","rpm"]),EXT_PDF=new Set(["pdf"]);function fileCategory(e){const n=(e.split(".").pop()||"").toLowerCase();return EXT_IMAGE.has(n)?"image":EXT_IMAGE_HEIC.has(n)?"heic":EXT_VIDEO.has(n)?"video":EXT_AUDIO.has(n)?"audio":EXT_MARKDOWN.has(n)?"markdown":EXT_PDF.has(n)?"pdf":EXT_TEXT.has(n)?"text":EXT_ARCHIVE.has(n)?"archive":"binary"}let _heic2anyLoaded=!1;function _loadHeic2any(){return _heic2anyLoaded?Promise.resolve():new Promise((e,n)=>{const i=document.createElement("script");i.src="/fluxdrop_pp/assets/heic2any.min.js",i.onload=()=>{_heic2anyLoaded=!0,e()},i.onerror=()=>n(new Error("Failed to load heic2any")),document.head.appendChild(i)})}let _jszipLoaded=!1;function _loadJSZip(){return _jszipLoaded?Promise.resolve():new Promise((e,n)=>{const i=document.createElement("script");i.src="/fluxdrop_pp/assets/jszip.min.js",i.onload=()=>{_jszipLoaded=!0,e()},i.onerror=()=>n(new Error("Failed to load JSZip")),document.head.appendChild(i)})}let _untarLoaded=!1;function _loadUntar(){return _untarLoaded?Promise.resolve():new Promise((e,n)=>{const i=document.createElement("script");i.src="/fluxdrop_pp/assets/untar.min.js",i.onload=()=>{_untarLoaded=!0,e()},i.onerror=()=>n(new Error("Failed to load js-untar")),document.head.appendChild(i)})}let _markedLoaded=!1;function _loadMarked(){return _markedLoaded?Promise.resolve():new Promise((e,n)=>{const i=document.createElement("script");i.src="/fluxdrop_pp/assets/marked.min.js",i.onload=()=>{_markedLoaded=!0,e()},i.onerror=()=>n(new Error("Failed to load marked.js")),document.head.appendChild(i)})}function _mdParseAndSanitize(e){const n=/^(\s{0,3})(#{1,6}\s|```|~~~|>|[-*_]{3,}[ \t]*$|<\/?[a-zA-Z]|[-*+]\s|\d+[.)]\s|\|)/,i=/^(\s{0,3})(>|[-*+]\s|\d+[.)]\s)/,o=e.split(`
`),p=[];let l=!1;for(let u=0;u<o.length;u++){const g=o[u],h=o[u+1];/^\s{0,3}(`{3,}|~{3,})/.test(g)&&(l=!l),p.push(g),!l&&g.trim()!==""&&h!==void 0&&h.trim()!==""&&(!n.test(g)||i.test(g))&&!n.test(h)&&!g.endsWith("  ")&&!g.endsWith("\\")&&(o[u+1]=g+" "+h,p[p.length-1]="")}const r=p.join(`
`);marked.use({gfm:!0,breaks:!1});const s=marked.parse(r),a=new Set(["p","br","hr","h1","h2","h3","h4","h5","h6","strong","em","del","code","pre","blockquote","ul","ol","li","table","thead","tbody","tr","th","td","a","img","input"]),d={a:new Set(["href","title"]),img:new Set(["src","alt","title","width","height"]),input:new Set(["type","checked","disabled"]),th:new Set(["align"]),td:new Set(["align"]),code:new Set(["class"]),pre:new Set(["class"])},f=/^(https?:|mailto:|#|\/)/i,c=document.createElement("div");c.innerHTML=s;function m(u){if(u.nodeType===Node.TEXT_NODE)return;if(u.nodeType!==Node.ELEMENT_NODE){u.remove();return}const g=u.tagName.toLowerCase();if(!a.has(g)){u.replaceWith(...u.childNodes);return}const h=d[g]||new Set;for(const b of[...u.attributes]){if(!h.has(b.name)){u.removeAttribute(b.name);continue}(b.name==="href"||b.name==="src")&&!f.test(b.value)&&u.removeAttribute(b.name)}g==="a"&&(u.setAttribute("target","_blank"),u.setAttribute("rel","noopener noreferrer")),g==="input"&&u.setAttribute("disabled",""),u.childNodes.forEach(m)}return c.childNodes.forEach(m),c.innerHTML}function _renderMarkdown(e,n){e.classList.add("fd-md-body"),e.innerHTML="";const i=document.createElement("div");if(i.className="md-preview",i.setAttribute("data-fd-notranslate",""),i.style.cssText="color:#e2e8f0;font-size:15px;line-height:1.75;padding:1.25rem 1.5rem;overflow-y:auto;max-height:70vh",i.innerHTML=_mdParseAndSanitize(n),!document.getElementById("md-preview-style")){const o=document.createElement("style");o.id="md-preview-style",o.textContent=`
            .md-preview h1,.md-preview h2,.md-preview h3,
            .md-preview h4,.md-preview h5,.md-preview h6 {
                color:#93c5fd;font-weight:700;margin:1.25em 0 .5em;
                border-bottom:1px solid rgba(148,163,184,.2);padding-bottom:.25em }
            .md-preview h1{font-size:1.6em} .md-preview h2{font-size:1.35em}
            .md-preview h3{font-size:1.15em}
            .md-preview p{margin:.6em 0}
            .md-preview a{color:#60a5fa;text-decoration:underline}
            .md-preview a:hover{color:#93c5fd}
            .md-preview strong{color:#f1f5f9;font-weight:700}
            .md-preview em{color:#cbd5e1;font-style:italic}
            .md-preview del{color:#64748b}
            .md-preview code{background:#1e293b;color:#7dd3fc;padding:1px 5px;
                border-radius:4px;font-family:ui-monospace,monospace;font-size:13px}
            .md-preview pre{background:#0f172a;border:1px solid #1e293b;border-radius:8px;
                padding:1rem;overflow-x:auto;margin:.75em 0}
            .md-preview pre code{background:none;padding:0;color:#e2e8f0;font-size:13px}
            .md-preview blockquote{border-left:3px solid #3b82f6;margin:.75em 0;
                padding:.4em .75em .4em 1rem;background:rgba(59,130,246,.08);border-radius:0 6px 6px 0}
            .md-preview blockquote p{margin:0;color:#94a3b8}
            .md-preview hr{border:none;border-top:1px solid #334155;margin:1.25em 0}
            .md-preview ul,.md-preview ol{padding-left:1.5em;margin:.5em 0}
            .md-preview li{margin:.2em 0}
            .md-preview li input[type=checkbox]{margin-right:.4em;accent-color:#3b82f6}
            .md-preview table{border-collapse:collapse;width:100%;margin:.75em 0;font-size:14px}
            .md-preview th,.md-preview td{border:1px solid #334155;padding:6px 12px;text-align:left}
            .md-preview th{background:#1e293b;color:#93c5fd;font-weight:600}
            .md-preview tr:nth-child(even) td{background:rgba(255,255,255,.03)}
            .md-preview img{max-width:100%;border-radius:6px;margin:.5em 0}
        `,document.head.appendChild(o)}e.appendChild(i)}let _previewAbortCtrl=null;async function _fetchBlobWithProgress(e,n,i){const o=e.headers.get("Content-Length"),p=o?parseInt(o):0;if(!p||!e.body)return e.blob();const l="fd-preview-progress-"+Date.now();i.innerHTML=`
        <div style="width:100%;max-width:700px;margin:0 auto">
            <div style="width:100%;aspect-ratio:16/10;border-radius:8px;
                background:linear-gradient(90deg,#1e293b 25%,#334155 50%,#1e293b 75%);
                background-size:200% 100%;animation:fd-shimmer 1.4s infinite;margin-bottom:12px"></div>
            <div style="background:#334155;border-radius:4px;height:5px;overflow:hidden">
                <div id="${l}" style="height:100%;border-radius:4px;background:#3b82f6;width:0%;transition:width .15s"></div>
            </div>
            <div id="${l}-label" style="text-align:center;font-size:12px;color:#64748b;margin-top:6px">0%</div>
        </div>`;const r=e.body.getReader(),s=[];let a=0;for(;;){const{done:c,value:m}=await r.read();if(n&&n.aborted)throw new DOMException("Aborted","AbortError");if(c)break;s.push(m),a+=m.byteLength;const u=Math.min(100,Math.round(a/p*100)),g=document.getElementById(l),h=document.getElementById(l+"-label");g&&(g.style.width=u+"%"),h&&(h.textContent=u+"%  ("+formatBytes(a)+" / "+formatBytes(p)+")")}const d=new Uint8Array(a);let f=0;for(const c of s)d.set(c,f),f+=c.byteLength;return new Blob([d],{type:e.headers.get("Content-Type")||"application/octet-stream"})}async function _previewTrashFile(e,n){_previewAbortCtrl&&_previewAbortCtrl.abort(),_previewAbortCtrl=new AbortController;const i=_previewAbortCtrl.signal,o=document.getElementById("preview-modal"),p=document.getElementById("preview-title"),l=document.getElementById("preview-body"),r=document.getElementById("preview-download-btn");p.textContent=n,l.innerHTML=_loadingHtml("2rem"),r.style.display="none",o.classList.remove("hidden");const s=`${API_BASE_URL}/api/v1/trash/${e}/file`;try{const a=fileCategory(n);if(["image","heic","pdf","text","markdown","audio","video"].includes(a)){const d=await fetchWithFallback(s,{signal:i,headers:authToken?{Authorization:`Bearer ${authToken}`}:{}});if(!d.ok)throw new Error(`HTTP ${d.status}`);l.innerHTML=`<div style="width:100%;max-width:700px;margin:0 auto;
                aspect-ratio:16/10;border-radius:8px;
                background:linear-gradient(90deg,#1e293b 25%,#334155 50%,#1e293b 75%);
                background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></div>`;const f=await d.blob();if(i.aborted){URL.revokeObjectURL(URL.createObjectURL(f));return}const c=URL.createObjectURL(f),m=()=>{URL.revokeObjectURL(c)};if(a==="image"||a==="heic")l.innerHTML=`<img src="${c}" alt="${escapeHtml(n)}"
                    style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto">`;else if(a==="video")l.innerHTML=`<video controls autoplay style="max-width:100%;max-height:70vh;
                    border-radius:8px;display:block;margin:0 auto;background:#000">
                    <source src="${c}">Your browser doesn't support this video format.</video>`;else if(a==="audio")l.innerHTML=`<div style="padding:2rem 1rem;text-align:center">
                    <div style="font-size:4rem;margin-bottom:1rem">🎵</div>
                    <div style="color:#94a3b8;margin-bottom:1.5rem;font-size:15px">${escapeHtml(n)}</div>
                    <audio controls autoplay style="width:100%"><source src="${c}"></audio></div>`;else if(a==="pdf")l.innerHTML=`<iframe src="${c}"
                    style="width:100%;height:65vh;border:none;border-radius:8px;background:#fff"
                    title="${escapeHtml(n)}"></iframe>`;else{const g=await f.text();if(a==="markdown")await _loadMarked(),_renderMarkdown(l,g);else{const h=(n.split(".").pop()||"").toLowerCase();l.innerHTML=`<pre class="lang-${h}">${escapeHtml(g.slice(0,5e4))}${g.length>5e4?`

… (truncated)`:""}</pre>`}}const u=window.closePreview;window.closePreview=function(){m(),window.closePreview=u,u()},r.style.display="none"}else l.innerHTML=`<div style="padding:3rem 1rem;text-align:center">
                <div style="font-size:3.5rem;margin-bottom:1rem">📄</div>
                <div style="color:#94a3b8;margin-bottom:1rem">${escapeHtml(n)}</div>
                <p style="color:#64748b;font-size:14px">No preview available. Restore the file to download it.</p>
            </div>`}catch(a){if(a.name==="AbortError")return;l.innerHTML=`<p style="color:#ef4444;padding:2rem;text-align:center">Preview failed: ${escapeHtml(String(a))}</p>`}}window.closePreview=function(){const e=document.getElementById("preview-modal");if(e.classList.contains("hidden")||e.dataset.fdClosing)return;_previewAbortCtrl&&(_previewAbortCtrl.abort(),_previewAbortCtrl=null),e.dataset.fdClosing="1",e.classList.add("fd-overlay-closing");const n=e.querySelector(".preview-modal-content");n&&n.classList.add("fd-panel-closing");let i=!1;const o=()=>{if(i)return;i=!0,e.classList.remove("fd-overlay-closing"),n&&n.classList.remove("fd-panel-closing"),delete e.dataset.fdClosing,e.classList.add("hidden");const p=document.getElementById("preview-body");p.querySelectorAll("video,audio").forEach(l=>{l.pause(),Array.from(l.querySelectorAll("source")).forEach(r=>r.remove()),l.removeAttribute("src"),l.load()}),p.innerHTML="",document.getElementById("preview-download-btn").style.display="none"};e.addEventListener("animationend",o,{once:!0}),setTimeout(o,200)};function _renderArchiveTree(e,n,i){if(!n.length){e.innerHTML=`<div style="padding:2rem;text-align:center;color:#94a3b8">${t("archive_empty")}</div>`;return}function o(a){const d={children:Object.create(null),files:[]};for(const f of a){const c=f.name.replace(/\\/g,"/").replace(/\/$/,"").split("/");if(f.isDir||c.length>1){let m=d;const u=f.isDir?c:c.slice(0,-1);for(const g of u)m.children[g]||(m.children[g]={children:Object.create(null),files:[]}),m=m.children[g];f.isDir||m.files.push({name:c[c.length-1],size:f.size})}else d.files.push({name:f.name,size:f.size})}return d}function p(a,d){let f="";const c=d*16;for(const[m,u]of Object.entries(a.children).sort(([g],[h])=>g.localeCompare(h)))f+=`<div style="display:flex;align-items:center;gap:6px;padding:3px 8px 3px ${8+c}px;
                         border-radius:5px;cursor:default" class="arc-dir-row"
                         onmouseenter="this.style.background='rgba(255,255,255,.05)'"
                         onmouseleave="this.style.background=''">
                <span style="font-size:13px;flex-shrink:0">📁</span>
                <span style="font-size:13px;color:#93c5fd;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(m)}</span>
            </div>
            ${p(u,d+1)}`;for(const m of a.files.sort((u,g)=>u.name.localeCompare(g.name))){const u=m.size!=null?`<span style="font-size:11px;color:#64748b;flex-shrink:0;margin-left:auto;padding-left:8px">${formatBytes(m.size)}</span>`:"";f+=`<div style="display:flex;align-items:center;gap:6px;padding:3px 8px 3px ${8+c}px;
                         border-radius:5px;cursor:default"
                         onmouseenter="this.style.background='rgba(255,255,255,.05)'"
                         onmouseleave="this.style.background=''">
                <span style="font-size:13px;flex-shrink:0">📄</span>
                <span style="font-size:13px;color:#e2e8f0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(m.name)}</span>
                ${u}
            </div>`}return f}const l=o(n),r=n.filter(a=>!a.isDir).length,s=n.filter(a=>a.isDir).length;e.innerHTML=`
        <div style="padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.08);
                    display:flex;align-items:center;justify-content:space-between">
            <span style="font-size:12px;color:#94a3b8">
                ${r} file${r!==1?"s":""} · ${s} folder${s!==1?"s":""}
            </span>
            <span style="font-size:11px;color:#475569">read-only preview</span>
        </div>
        <div style="overflow:auto;max-height:60vh;padding:6px 4px;font-family:ui-monospace,monospace">
            ${p(l,0)}
        </div>`}window.previewFile=async function(e){_previewAbortCtrl&&_previewAbortCtrl.abort(),_previewAbortCtrl=new AbortController;const n=_previewAbortCtrl.signal,i=e.split("/").pop(),o=fileCategory(e),p=document.getElementById("preview-modal"),l=document.getElementById("preview-title"),r=document.getElementById("preview-body"),s=document.getElementById("preview-download-btn");l.textContent=i,r.innerHTML='<p style="color:#64748b;padding:2rem;text-align:center">Connecting…</p>',s.style.display="none",p.classList.remove("hidden");try{const a=await mintDownloadToken(e),d=`/api/v1/download${encodePath(e)}`,f=`${API_BASE_URL}${d}?dl_token=${encodeURIComponent(a.download_token)}`;if(o==="image"){r.innerHTML=`<div style="width:100%;max-width:700px;margin:0 auto;
                aspect-ratio:16/10;border-radius:8px;
                background:linear-gradient(90deg,#1e293b 25%,#334155 50%,#1e293b 75%);
                background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></div>`,r.innerHTML='<p style="color:#64748b;padding:2rem;text-align:center">Fetching an image…</p>';const c=await fetchWithFallback(f,{signal:n,...authToken?{headers:{Authorization:`Bearer ${authToken}`}}:{}});if(!c.ok)throw new Error(`HTTP ${c.status}`);const m=await _fetchBlobWithProgress(c,n,r),u=URL.createObjectURL(m);if(n.aborted){URL.revokeObjectURL(u);return}r.innerHTML=`<img src="${u}" alt="${escapeHtml(i)}"
                style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto">`;const g=window.closePreview;window.closePreview=function(){URL.revokeObjectURL(u),window.closePreview=g,g()},s.style.display="inline-flex",s.onclick=()=>downloadFile(e)}else if(o==="heic"){r.innerHTML='<p style="color:#94a3b8;padding:2rem;text-align:center">Decoding HEIC…</p>',await _loadHeic2any();const c=await fetchWithFallback(f,{signal:n,...authToken?{headers:{Authorization:`Bearer ${authToken}`}}:{}});if(!c.ok)throw new Error(`HTTP ${c.status}`);const m=await c.blob(),u=await heic2any({blob:m,toType:"image/jpeg",quality:.85}),g=URL.createObjectURL(u);r.innerHTML=`<img src="${g}" alt="${escapeHtml(i)}"
                style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto">`;const h=window.closePreview;window.closePreview=function(){URL.revokeObjectURL(g),window.closePreview=h,h()},s.style.display="inline-flex",s.onclick=()=>downloadFile(e)}else if(o==="video")r.innerHTML=`<video controls autoplay style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto;background:#000"><source src="${f}">Your browser doesn't support this video format.</video>`,s.style.display="inline-flex",s.onclick=()=>downloadFile(e);else if(o==="audio")r.innerHTML=`<div style="padding:2rem 1rem;text-align:center"><div style="font-size:4rem;margin-bottom:1rem">🎵</div><div style="color:#94a3b8;margin-bottom:1.5rem;font-size:15px">${escapeHtml(i)}</div><audio controls autoplay style="width:100%"><source src="${f}">Your browser doesn't support audio playback.</audio></div>`,s.style.display="inline-flex",s.onclick=()=>downloadFile(e);else if(o==="markdown"){r.innerHTML='<p style="color:#94a3b8;padding:2rem;text-align:center">Rendering…</p>',await _loadMarked();const c=await fetchWithFallback(f,{signal:n,...authToken?{headers:{Authorization:`Bearer ${authToken}`}}:{}});if(!c.ok)throw new Error(`HTTP ${c.status}`);const m=await c.text();_renderMarkdown(r,m),s.style.display="inline-flex",s.onclick=()=>downloadFile(e)}else if(o==="text"){const c=await fetchWithFallback(f,{signal:n,...authToken?{headers:{Authorization:`Bearer ${authToken}`}}:{}});if(!c.ok)throw new Error(`HTTP ${c.status}`);const m=await c.text(),u=(e.split(".").pop()||"").toLowerCase();r.innerHTML=`<pre class="lang-${u}">${escapeHtml(m.slice(0,5e4))}${m.length>5e4?`

… (truncated)`:""}</pre>`,s.style.display="inline-flex",s.onclick=()=>downloadFile(e)}else if(o==="pdf"){r.innerHTML='<p style="color:#64748b;padding:2rem;text-align:center">Fetching a PDF…</p>';const c=await fetchWithFallback(f,{signal:n,...authToken?{headers:{Authorization:`Bearer ${authToken}`}}:{}});if(!c.ok)throw new Error(`HTTP ${c.status}`);const m=await c.blob();if(n.aborted)return;const u=new Blob([m],{type:"application/pdf"}),g=URL.createObjectURL(u);r.innerHTML=`<iframe
                src="${g}"
                style="width:100%;height:65vh;border:none;border-radius:8px;background:#fff"
                title="${escapeHtml(i)}">
                <p style="color:#94a3b8;padding:2rem;text-align:center">
                    Your browser cannot display PDFs inline.
                </p>
            </iframe>`;const h=window.closePreview;window.closePreview=function(){URL.revokeObjectURL(g),window.closePreview=h,h()},s.style.display="inline-flex",s.onclick=()=>{closePreview(),downloadFile(e)}}else if(o==="archive"){const c=(e.split(".").pop()||"").toLowerCase();r.innerHTML='<p style="color:#94a3b8;padding:2rem;text-align:center">Reading archive…</p>';const m=c==="zip",u=["tar","gz","tgz"].includes(c),g=["bz2","tbz2","xz","txz","7z","rar","zst","lz4","lzma","cab","iso","dmg","pkg","deb","rpm"].includes(c),h={bz2:"bzip2",tbz2:"bzip2 tar",xz:"XZ",txz:"XZ tar","7z":"7-Zip",rar:"RAR",zst:"Zstandard",lz4:"LZ4",lzma:"LZMA",cab:"Windows Cabinet",iso:"Disc Image",dmg:"macOS Disk Image",pkg:"Package",deb:"Debian Package",rpm:"RPM Package"};if(g){const b=h[c]||"."+c.toUpperCase();r.innerHTML=`<div style="padding:3rem 1rem;text-align:center">
                    <div style="font-size:3rem;margin-bottom:1rem">🗜</div>
                    <div style="color:#94a3b8;font-weight:600;margin-bottom:4px">${escapeHtml(i)}</div>
                    <div style="color:#64748b;font-size:12px;margin-bottom:12px">${b} archive</div>
                    <p style="color:#64748b;font-size:14px">
                        In-browser preview is not available for this format.<br>
                        Download the file and extract it locally.
                    </p></div>`,s.style.display="inline-flex",s.onclick=()=>{closePreview(),downloadFile(e)}}else if(m||u)try{const b=a.download_token,E=e.split("/").map(encodeURIComponent).join("/"),k=`${API_BASE_URL}/api/v1/archive_tree${E}?dl_token=${encodeURIComponent(b)}`,w=await fetchWithFallback(k,{signal:n,headers:authToken?{Authorization:`Bearer ${authToken}`}:{}});if(!w.ok)throw new Error(`HTTP ${w.status}`);const x=(await w.json()).entries.map(v=>({name:v.name,size:v.size,isDir:v.is_dir}));_renderArchiveTree(r,x,i)}catch(b){r.innerHTML=`<p style="color:#ef4444;padding:2rem;text-align:center">
                        Archive preview failed: ${escapeHtml(String(b))}</p>`}else r.innerHTML=`<div style="padding:3rem 1rem;text-align:center">
                    <div style="font-size:3.5rem;margin-bottom:1rem">📦</div>
                    <div style="color:#94a3b8;margin-bottom:1rem">${escapeHtml(i)}</div>
                    <p style="color:#64748b;font-size:14px">No preview available for this archive type yet.</p>
                </div>`,s.style.display="inline-flex",s.onclick=()=>{closePreview(),downloadFile(e)};s.style.display="inline-flex",s.onclick=()=>downloadFile(e)}else r.innerHTML=`<div style="padding:3rem 1rem;text-align:center"><div style="font-size:3.5rem;margin-bottom:1rem">📄</div><div style="color:#94a3b8;margin-bottom:1rem">${escapeHtml(i)}</div><p style="color:#64748b;font-size:14px">No preview available for this file type yet.</p></div>`,s.style.display="inline-flex",s.onclick=()=>{closePreview(),downloadFile(e)}}catch(a){if(a.name==="AbortError")return;r.innerHTML=`<p style="color:#ef4444;padding:2rem;text-align:center">Preview failed: ${escapeHtml(String(a))}</p>`}},window.previewText=window.previewFile;let _selectedPaths=new Set,_lastClickedPath=null;window._fdKeepSelectionOnNav=!1;function _selBarGhost(){return`
    <span style="opacity:0;pointer-events:none;flex-shrink:0">${t("sel_bar_count",{n:0})}</span>
    <button class="btn" style="opacity:0;pointer-events:none;padding:3px 10px;font-size:12px" disabled>⬇ ${t("download")}</button>
    <button class="btn" style="opacity:0;pointer-events:none;padding:3px 10px;font-size:12px;background:#ef4444" disabled>🗑 ${t("trash")}</button>
    <button class="btn" style="opacity:0;pointer-events:none;padding:3px 10px;font-size:12px;background:#6b7280;margin-left:auto" disabled>✕ ${t("sel_bar_clear")}</button>`}async function _trashSelectedPaths(e){if(!e.length)return;const n=e.length;if(!await showConfirmModal({title:t("sel_bar_delete_title",{n}),message:t("sel_bar_delete_msg",{n,days:_lastKnownRetentionDays})}))return;_clearSelection(),_updateSelBar();let o=_lastKnownRetentionDays,p=0;for(const r of e){const s=await deleteItem(r,{skipConfirm:!0,silent:!0});s===!1?p++:s&&(o=s)}const l=e.length-p;l>0&&(_showTrashBatchNotice(l,o),showToast(t("trash_moved_toast",{n:l}))),p>0&&showToast(t("trash_delete_failed")+` (${p})`,{type:"error"}),loadDirectory(currentPath)}function _updateSelBar(){const e=_selectedPaths.size,n=document.getElementById("fd-sel-bar");if(!n)return;if(e===0){n.classList.remove("fd-sel-bar-visible"),n.innerHTML=_selBarGhost(),n.onclick=null;return}n.classList.add("fd-sel-bar-visible");const i=window.matchMedia("(pointer: fine)").matches||window.matchMedia("(hover: hover)").matches;n.innerHTML=`
        <span style="color:var(--fd-accent,#3b82f6);font-weight:600;flex-shrink:0">${t("sel_bar_count",{n:e})}</span>
        ${i?`
        <label style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--fd-muted,#64748b);
                       cursor:pointer;flex-shrink:0;user-select:none" title="${t("sel_bar_keep_tooltip")}">
            <input type="checkbox" id="fd-sel-keep-chk" ${window._fdKeepSelectionOnNav?"checked":""}
                   style="width:13px;height:13px">
            📌 ${t("sel_bar_keep_label")}
        </label>`:""}
        <button data-fdsel="download" class="btn" style="padding:3px 10px;font-size:12px">⬇ ${t("download")}</button>
        <button data-fdsel="trash"    class="btn" style="padding:3px 10px;font-size:12px;background:#ef4444">🗑 ${t("trash")}</button>
        <button data-fdsel="clear"    class="btn" style="padding:3px 10px;font-size:12px;background:#6b7280;margin-left:auto">✕ ${t("sel_bar_clear")}</button>
    `,i&&n.querySelector("#fd-sel-keep-chk").addEventListener("change",function(){window._fdKeepSelectionOnNav=this.checked}),n.onclick=o=>{const p=o.target.closest("[data-fdsel]");if(!p)return;const l=p.dataset.fdsel;if(l==="clear"){_clearSelection(),_updateSelBar();return}if(l==="trash"){_trashSelectedPaths([..._selectedPaths]);return}if(l==="download"){_getFileRows().filter(s=>_selectedPaths.has(s.dataset.path)).forEach(s=>{s.dataset.isDir==="1"?downloadFolderZip(s.dataset.path):downloadFile(s.dataset.path)});return}}}function _doRowSelect(e,n,i){_removeContextMenu();const o=document.getElementById("fd-info-panel");o&&window.fdCloseFloatingPanel(o);const p=_getFileRows(),l=_lastClickedPath?p.findIndex(r=>r.dataset.path===_lastClickedPath):-1;if(i.shiftKey&&l>=0){const r=Math.min(l,n),s=Math.max(l,n);_selectedPaths.clear(),p.forEach((a,d)=>{const f=d>=r&&d<=s;_updateRowSelVisual(a,f),f&&_selectedPaths.add(a.dataset.path)})}else i.ctrlKey||i.metaKey?(_toggleSelect(e),_lastClickedPath=e.dataset.path):(_clearSelection(),_toggleSelect(e,!0),_lastClickedPath=e.dataset.path);_updateSelBar()}function attachRowListeners(){const e=document.getElementById("file-list");e&&(e.querySelectorAll(".fd-more-btn").forEach(n=>{n.addEventListener("click",i=>{i.stopPropagation();const o=n.closest(".fd-file-row"),p=n.getBoundingClientRect();_showContextMenu(p.left,p.bottom+4,o)})}),e.querySelectorAll(".fd-file-row").forEach((n,i)=>{n.addEventListener("click",o=>{o.target.closest("button")||_doRowSelect(n,i,o)}),n.querySelectorAll(".preview-btn, .open-btn").forEach(o=>{o.addEventListener("click",p=>{if(p.stopPropagation(),p.shiftKey||p.ctrlKey||p.metaKey){_doRowSelect(n,i,p);return}o.classList.contains("open-btn")?enterDir(o.dataset.path):previewFile(o.dataset.path)})}),n.addEventListener("dblclick",o=>{o.target.closest("button")||(_clearSelection(),_updateSelBar(),n.dataset.isDir==="1"?enterDir(n.dataset.path):previewFile(n.dataset.path))}),n.addEventListener("contextmenu",o=>{o.preventDefault(),_selectedPaths.has(n.dataset.path)||(_clearSelection(),_toggleSelect(n,!0),_lastClickedPath=n.dataset.path,_updateSelBar()),_showContextMenu(o.clientX,o.clientY,n)})}),document.body._fdSelClearBound||(document.body._fdSelClearBound=!0,document.body.addEventListener("click",n=>{n.target.closest(".fd-file-row, #fd-sel-bar, #fd-ctx-menu, .modal-overlay, .fd-profile-overlay")||_selectedPaths.size>0&&(_clearSelection(),_updateSelBar())})),e.querySelectorAll(".folder-size-cell:not([data-warm])").forEach((n,i)=>{setTimeout(()=>loadFolderSize(n),i*80)}))}function _getFileRows(){return Array.from(document.querySelectorAll("#file-list .fd-file-row"))}function _cancelPendingDotCleanup(e){e._fdSelTimeout&&(clearTimeout(e._fdSelTimeout),e._fdSelTimeout=null),e._fdSelFinish&&(e.removeEventListener("animationend",e._fdSelFinish),e._fdSelFinish=null)}function _updateRowSelVisual(e,n){const i=e.querySelector(".fd-sel-dot");if(i)if(_cancelPendingDotCleanup(i),n)i.style.display="inline-flex",i.style.background="var(--fd-accent,#3b82f6)",i.textContent="✓",i.style.color="#fff",i.classList.remove("fd-sel-dot-out"),i.offsetWidth,i.classList.add("fd-sel-dot-in"),e.style.background="var(--fd-accent-bg,#eff6ff)";else{if(i.style.display==="none")return;i.classList.remove("fd-sel-dot-in"),i.classList.add("fd-sel-dot-out"),e.style.background="";const o=()=>{i.style.display="none",i.style.background="transparent",i.textContent="",i.classList.remove("fd-sel-dot-out"),i._fdSelFinish=null,i._fdSelTimeout=null};i._fdSelFinish=o,i.addEventListener("animationend",o,{once:!0}),i._fdSelTimeout=setTimeout(o,180)}}function _toggleSelect(e,n){const i=e.dataset.path,o=n!==void 0?n:!_selectedPaths.has(i);o?_selectedPaths.add(i):_selectedPaths.delete(i),_updateRowSelVisual(e,o)}function _setRowIndeterminate(e,n){const i=e.querySelector(".fd-sel-dot");if(i)if(_cancelPendingDotCleanup(i),n)i.style.display="inline-flex",i.style.background="var(--fd-accent-dim,#93c5fd)",i.textContent="–",i.style.color="#fff",i.classList.remove("fd-sel-dot-out"),i.offsetWidth,i.classList.add("fd-sel-dot-in");else{if(i.textContent!=="–")return;i.classList.remove("fd-sel-dot-in"),i.classList.add("fd-sel-dot-out");const o=()=>{i.style.display="none",i.style.background="transparent",i.textContent="",i.classList.remove("fd-sel-dot-out"),i._fdSelFinish=null,i._fdSelTimeout=null};i._fdSelFinish=o,i.addEventListener("animationend",o,{once:!0}),i._fdSelTimeout=setTimeout(o,180)}}function _hasSelectedDescendant(e){const n=e.endsWith("/")?e:e+"/";for(const i of _selectedPaths)if(i!==e&&i.startsWith(n))return!0;return!1}function _applySelectionVisuals(){_getFileRows().forEach(e=>{const n=e.dataset.path;_selectedPaths.has(n)?_updateRowSelVisual(e,!0):e.dataset.isDir==="1"&&_hasSelectedDescendant(n)&&_setRowIndeterminate(e,!0)})}function _clearSelection(){_getFileRows().forEach(e=>_updateRowSelVisual(e,!1)),_selectedPaths.clear(),_lastClickedPath=null}function _dropSelectedUnder(e){const n=e.endsWith("/")?e:e+"/";for(const i of[..._selectedPaths])(i===e||i.startsWith(n))&&_selectedPaths.delete(i);(_lastClickedPath===e||_lastClickedPath?.startsWith(n))&&(_lastClickedPath=null)}function _removeContextMenu(){document.getElementById("fd-ctx-menu")?.remove()}function _dismissContextMenu(){const e=document.getElementById("fd-ctx-menu");e&&window.fdCloseFloatingPanel(e)}function _showContextMenu(e,n,i){_removeContextMenu();const o=i.dataset.path,p=i.dataset.isDir==="1",l=_selectedPaths.size,r=l>1&&_selectedPaths.has(o),s=document.createElement("div");s.id="fd-ctx-menu",s.style.cssText=`position:fixed;left:${e}px;top:${n}px;background:var(--fd-surface,#fff);border:1px solid var(--fd-border,#e2e8f0);border-radius:8px;box-shadow:0 6px 24px rgba(0,0,0,0.15);z-index:50000;min-width:190px;padding:4px 0;font-size:13px;overflow:hidden`;const a=(f,c,m,u)=>`<button class="fd-ctx-item" data-action="${m}"
            style="display:block;width:100%;padding:7px 14px;text-align:left;
                   background:none;border:none;cursor:pointer;
                   color:${u?"var(--fd-danger,#dc2626)":"var(--fd-text,#1e293b)"};
                   white-space:nowrap;font-size:13px"
        >${f} ${c}</button>`,d='<div style="border-top:1px solid var(--fd-border,#e2e8f0);margin:4px 0"></div>';if(r){const f=_getFileRows().filter(g=>_selectedPaths.has(g.dataset.path)),c=f.filter(g=>g.dataset.isDir==="1").length,m=f.length-c;let u;c===0?u=t("ctx_download_files",{n:m}):m===0?u=t("ctx_download_folders_zip",{n:c}):u=t("ctx_download_mixed",{nf:m,nd:c}),s.innerHTML=[a("⬇",u,"download-multi"),d,a("🗑",t("ctx_trash_multi",{n:l}),"trash-multi",!0)].join("")}else s.innerHTML=[p?a("📂",t("ctx_open"),"open"):a("👁",t("ctx_preview"),"preview"),p?a("⬇",t("ctx_download_zip"),"zip"):a("⬇",t("ctx_download"),"download"),a("🔗",t("ctx_share"),"share"),a("✂",t("ctx_move_rename"),"move"),a("ℹ",t("ctx_info"),"info"),d,a("🗑",t("ctx_trash"),"trash",!0)].join("");document.body.appendChild(s),s.classList.add("fd-ctx-menu-in"),setTimeout(()=>{document.addEventListener("click",_dismissContextMenu,{once:!0,capture:!0}),document.addEventListener("scroll",_dismissContextMenu,{once:!0,passive:!0})},0),s.querySelectorAll(".fd-ctx-item").forEach(f=>{f.addEventListener("mouseenter",()=>f.style.background="var(--fd-surface3,#f1f5f9)"),f.addEventListener("mouseleave",()=>f.style.background="none"),f.addEventListener("click",()=>{_dismissContextMenu();const c=i.dataset.path,m=i.dataset.isDir==="1";switch(f.dataset.action){case"open":enterDir(c);break;case"preview":previewFile(c);break;case"download":downloadFile(c);break;case"zip":downloadFolderZip(c);break;case"share":openShareDialog(c,m);break;case"move":openMoveDialog(c);break;case"info":_showFileInfo(i);break;case"trash":deleteItem(c);break;case"download-multi":{_getFileRows().filter(u=>_selectedPaths.has(u.dataset.path)).forEach(u=>{u.dataset.isDir==="1"?downloadFolderZip(u.dataset.path):downloadFile(u.dataset.path)});break}case"trash-multi":{_trashSelectedPaths([..._selectedPaths]);break}}})}),requestAnimationFrame(()=>{const f=s.getBoundingClientRect();f.right>window.innerWidth&&(s.style.left=Math.max(4,window.innerWidth-f.width-8)+"px"),f.bottom>window.innerHeight&&(s.style.top=Math.max(4,n-f.height)+"px")})}let _fdInfoInspectorCleanup=()=>{};function _showFileInfo(e){_fdInfoInspectorCleanup(),document.getElementById("fd-info-panel")?.remove();const n=e.dataset.name||"—",i=e.dataset.path||"—",o=e.dataset.isDir==="1",p=e.dataset.mtime||"",l=e.dataset.uploader||"",r=parseInt(e.dataset.size,10),s=o?e.querySelector(".folder-size-cell")?.textContent?.trim()||"…":isNaN(r)?"—":formatBytes(r),a=!o&&n.includes(".")?n.split(".").pop().toUpperCase():null,d=o?"Folder":a?`${a} file`:"File",f=document.createElement("div");if(f.id="fd-info-panel",f.style.cssText="position:fixed;right:12px;top:70px;width:280px;z-index:20000;background:var(--fd-surface,#fff);border:1px solid var(--fd-border,#e2e8f0);border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,0.14);padding:0;overflow:hidden;font-size:13px;animation:fd-info-in .18s ease",!document.getElementById("fd-info-kf")){const g=document.createElement("style");g.id="fd-info-kf",g.textContent="@keyframes fd-info-in{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:none}}",document.head.appendChild(g)}const c=(g,h,b)=>`<div style="display:flex;justify-content:space-between;padding:5px 14px;
                     border-bottom:1px solid var(--fd-border,#e2e8f0)">
            <span style="color:var(--fd-muted,#64748b);flex-shrink:0;margin-right:8px;white-space:nowrap">${g}</span>
            <span style="color:var(--fd-text,#1e293b);text-align:right;word-break:break-all;font-family:${g==="CRC-32"?"monospace":"inherit"}">${b?h:escapeHtml(h)}</span>
         </div>`;f.innerHTML=`<div style="background:var(--fd-surface3,#f1f5f9);padding:10px 14px;
                     display:flex;justify-content:space-between;align-items:center;
                     border-bottom:1px solid var(--fd-border,#e2e8f0)">
            <span style="font-weight:600;color:var(--fd-text,#1e293b);font-size:14px">
                ${o?"📁":"📄"} Info
            </span>
            <button id="fd-info-close" style="background:none;border:none;cursor:pointer;
                font-size:18px;color:var(--fd-muted,#64748b);padding:0 2px;line-height:1">✕</button>
        </div>`+c("Name",n)+c("Path",i)+c("Type",d)+c("Size",s)+c("Modified",p?formatMtime(p):"—")+(l?c("Uploaded by",l):"")+(o?"":`<div id="fd-info-cs-wrap">
            <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 14px;border-bottom:1px solid var(--fd-border,#e2e8f0);gap:8px">
                <span style="color:var(--fd-muted,#64748b);flex-shrink:0;white-space:nowrap">CRC-32</span>
                <span id="fd-cs-val-crc32" style="display:flex;align-items:center;gap:4px;min-width:0"><span style="color:#94a3b8;font-size:12px">Loading…</span></span>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 14px;border-bottom:1px solid var(--fd-border,#e2e8f0);gap:8px">
                <span style="color:var(--fd-muted,#64748b);flex-shrink:0;white-space:nowrap">SHA-256</span>
                <span id="fd-cs-val-sha256" style="display:flex;align-items:center;gap:4px;min-width:0"><span style="color:#94a3b8;font-size:12px">Loading…</span></span>
            </div>
        </div>`)+(o?"":`<div style="padding:8px 14px;border-bottom:1px solid var(--fd-border,#e2e8f0)">
            <button id="fd-info-dl" class="btn"
                style="width:100%;padding:5px;font-size:12px;text-align:center">
                ⬇ Download
            </button></div>`),document.body.appendChild(f);let m=!1;try{m=localStorage.getItem("fd_pin_info_panel")==="1"}catch{}document.getElementById("fd-info-close").addEventListener("click",()=>{_fdInfoInspectorCleanup(),window.fdCloseFloatingPanel(f)});const u=document.getElementById("fd-info-dl");if(u&&u.addEventListener("click",()=>{_fdInfoInspectorCleanup(),f.remove(),downloadFile(i)}),o||_initChecksumSection(i,f),m){const g=h=>{if(f.contains(h.target)||h.target.closest&&h.target.closest(".fd-more-btn"))return;const b=h.target.closest&&h.target.closest(".fd-file-row");b&&(h.preventDefault(),h.stopPropagation(),_showFileInfo(b))};setTimeout(()=>document.addEventListener("click",g,!0),10),_fdInfoInspectorCleanup=()=>{document.removeEventListener("click",g,!0),_fdInfoInspectorCleanup=()=>{}}}else{const g=h=>{f.contains(h.target)||(window.fdCloseFloatingPanel(f),document.removeEventListener("click",g,!0))};setTimeout(()=>document.addEventListener("click",g,!0),10)}}function _initChecksumSection(e,n){let i=null;function o(a){const d=n.querySelector(`#fd-cs-val-${a}`);d&&(d.innerHTML='<span style="color:#d97706;font-size:12px">⧗ Calculating…</span>')}function p(a,d){const f=n.querySelector(`#fd-cs-val-${a}`);if(!f)return;const c=a==="sha256"?d.slice(0,16)+"…":d;f.innerHTML=`<span style="font-family:monospace;font-size:11px;color:var(--fd-text,#1e293b);word-break:break-all;text-align:right" title="${escapeHtmlAttr(d)}">${escapeHtml(c)}</span><button id="fd-cs-copy-${a}" title="Copy ${a.toUpperCase()}" style="border:none;background:none;cursor:pointer;color:#94a3b8;font-size:13px;padding:0 0 0 3px;flex-shrink:0;line-height:1">⧉</button>`,n.querySelector(`#fd-cs-copy-${a}`)?.addEventListener("click",m=>{m.stopPropagation(),navigator.clipboard?.writeText(d);const u=n.querySelector(`#fd-cs-copy-${a}`);u&&(u.textContent="✓",setTimeout(()=>{u&&(u.textContent="⧉")},1500))})}function l(a,d,f){const c=n.querySelector(`#fd-cs-val-${a}`);if(!c)return;const m=f?` title="${escapeHtmlAttr(f)}"`:"",u=f?"⚠️ error":"—";c.innerHTML=`<span style="color:#94a3b8;font-size:12px"${m}>${u}</span><button id="fd-cs-calc-${a}" style="border:none;background:#f1f5f9;color:#3b82f6;cursor:pointer;padding:2px 7px;border-radius:6px;font-size:11px;font-weight:600;margin-left:4px;flex-shrink:0">${f?"Retry":"Calc"}</button>`,n.querySelector(`#fd-cs-calc-${a}`)?.addEventListener("click",async g=>{g.stopPropagation();for(const h of d)o(h);try{await apiCall("/api/v1/checksums/compute","POST",{path:e,algos:d},!0)}catch(h){l(a,d,h.message||"Request failed");return}r()})}function r(){n.isConnected&&(clearTimeout(i),i=setTimeout(s,1800))}async function s(){if(!n.isConnected){clearTimeout(i);return}let a;try{a=await apiCall(`/api/v1/fileinfo${encodePath(e)}`,"GET",null,!0)}catch{const h='<span style="color:#94a3b8;font-size:12px">—</span>';["crc32","sha256"].forEach(b=>{const E=n.querySelector(`#fd-cs-val-${b}`);E&&(E.innerHTML=h)});return}if(!n.isConnected)return;const d=a.job,f=d&&(d.status==="pending"||d.status==="running"),c=d&&d.status==="error",m=c?d.error||"Computation failed":null,u=d&&d.algos||"",g=[];a.crc32||g.push("crc32"),a.sha256||g.push("sha256"),a.crc32?p("crc32",a.crc32.toLowerCase()):f&&u.includes("crc32")?o("crc32"):l("crc32",g.length?g:["crc32"],c&&u.includes("crc32")?m:null),a.sha256?p("sha256",a.sha256.toLowerCase()):f&&u.includes("sha256")?o("sha256"):l("sha256",g.length?g:["sha256"],c&&u.includes("sha256")?m:null),f&&n.isConnected&&r()}s()}async function loadFolderSize(e){const n=e.dataset.path;if(!(!n||!authToken))try{const i=`/api/v1/foldersize${encodePath(n)}`,o=await apiCall(i,"GET",null,!0);e.isConnected&&(e.textContent=formatBytes(o.size),e.title=`${o.file_count} file${o.file_count!==1?"s":""}`,e.style.color="")}catch{e.isConnected&&(e.textContent="—",e.style.color="#94a3b8")}}window.deleteItem=async function(e,n={}){const i=typeof n=="boolean"?{skipConfirm:n}:n||{},o=!!i.skipConfirm,p=!!i.silent,l=stripInternalPrefix(e);if(!o&&!await showConfirmModal({title:t("trash_single_title",{name:l}),message:t("sel_bar_delete_msg",{n:1,days:_lastKnownRetentionDays})}))return!1;try{const s=(await apiCall("/api/v1/trash","POST",{path:e})).retention_days||30;return _lastKnownRetentionDays=s,_selectedPaths.delete(e),p||(_updateSelBar(),showToast(t("trash_single_toast",{name:l,days:s}))),loadDirectory(currentPath),s}catch(r){return showMessage(t("trash_delete_failed"),r.message),!1}};const _TRASH_BATCH_NOTICE_KEY="fd-trash-batch-notice-v1";function _showTrashBatchNotice(e,n){const i=n||30;localStorage.getItem(_TRASH_BATCH_NOTICE_KEY)||(localStorage.setItem(_TRASH_BATCH_NOTICE_KEY,"1"),showMessage(t("trash_moved_toast",{n:e}),t("trash_batch_notice_body",{days:i})))}(function(){if(document.getElementById("_fd-spin-style"))return;const e=document.createElement("style");e.id="_fd-spin-style",e.textContent="@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}",document.head.appendChild(e)})();async function openTrashView(){document.getElementById("trash-overlay")?.remove();const e=document.createElement("div");e.id="trash-overlay",e.className="modal-overlay",e.innerHTML=`
        <div class="modal-content" style="max-width:680px;width:95vw;padding:0;overflow:hidden;border-radius:14px">
            <div style="background:linear-gradient(135deg,#dc2626,#b91c1c);padding:16px 20px;
                        display:flex;align-items:center;justify-content:space-between">
                <div>
                    <div style="color:white;font-weight:700;font-size:16px">🗑 Trash</div>
                    <div id="trash-subtitle" style="color:rgba(255,255,255,.75);font-size:12px;margin-top:2px"></div>
                </div>
                <div onclick="window.fdCloseOverlay(document.getElementById('trash-overlay'))"
                    style="background:rgba(255,255,255,.15);border:none;color:white;
                           border-radius:6px;padding:4px 10px;cursor:pointer;font-size:14px
                           ;display:inline-block">${t("close")||"✕"}</div>
            </div>
            <div id="trash-notice" style="display:none;padding:8px 20px;background:#fef3c7;
                border-bottom:1px solid #fde68a;font-size:12px;color:#92400e"></div>
            <div style="padding:12px 20px;border-bottom:1px solid #e2e8f0;display:flex;
                        justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
                <span style="font-size:12px;color:#64748b">
                    ${t("trash_retention_notice")!=="trash_retention_notice"?t("trash_retention_notice"):"Files are automatically deleted after their retention period. Trash does not count toward your storage quota."}
                </span>
                <button id="trash-empty-btn"
                    style="background:#ef4444;color:white;border:none;border-radius:7px;
                           padding:6px 14px;cursor:pointer;font-size:12px;font-weight:600;
                           white-space:nowrap">
                    ${t("trash_empty_btn")!=="trash_empty_btn"?t("trash_empty_btn"):"Empty Trash"}
                </button>
            </div>
            <div id="trash-body" style="max-height:55vh;overflow-y:auto;padding:8px 0">
                ${_loadingHtml()}
            </div>
        </div>`,document.body.appendChild(e),e.addEventListener("click",n=>{n.target===e&&window.fdCloseOverlay(e)}),await _refreshTrashView(),document.getElementById("trash-empty-btn").addEventListener("click",async()=>{if(await showConfirmModal({title:"Empty Trash?",message:"Everything in the Trash will be permanently deleted. This cannot be undone."}))try{await apiCall("/api/v1/trash","DELETE"),await _refreshTrashView()}catch(i){alert("Failed to empty trash: "+i.message)}})}async function _refreshTrashView(){const e=document.getElementById("trash-body"),n=document.getElementById("trash-subtitle"),i=document.getElementById("trash-notice");if(!e)return;e.innerHTML=_loadingHtml();let o;try{o=await apiCall("/api/v1/trash","GET")}catch(a){e.innerHTML=`<div style="padding:24px;text-align:center;color:#ef4444">Failed: ${escapeHtml(a.message)}</div>`;return}const p=o.items||[];if(o.retention_days&&(_lastKnownRetentionDays=o.retention_days),n.textContent=p.length===1?t("trash_1_item")!=="trash_1_item"?t("trash_1_item"):"1 item":t("trash_n_items")!=="trash_n_items"?t("trash_n_items",{n:p.length}):`${p.length} items`,o.retention_days===7&&i?(i.textContent="⚠ "+t("trash_retention_reduced_notice",{days:o.retention_days}),i.style.display="block"):i&&(i.style.display="none"),!p.length){e.innerHTML='<div style="padding:40px;text-align:center;color:#94a3b8;font-size:15px">🗑 Trash is empty</div>';return}function l(a){return a?new Date(a*1e3).toLocaleString():"—"}function r(a){return a<1024?a+" B":a<1048576?(a/1024).toFixed(1)+" KB":a<1073741824?(a/1048576).toFixed(1)+" MB":(a/1073741824).toFixed(2)+" GB"}function s(a){const d=Math.ceil((a-Date.now()/1e3)/86400);return d<=0?`<span style="color:#ef4444">${t("trash_days_expiring")!=="trash_days_expiring"?t("trash_days_expiring"):"Expiring soon"}</span>`:d===1?`<span style="color:#f59e0b">${t("trash_days_1")!=="trash_days_1"?t("trash_days_1"):"1 day left"}</span>`:d<=3?`<span style="color:#f59e0b">${t("trash_days_n")!=="trash_days_n"?t("trash_days_n",{n:d}):`${d} days left`}</span>`:`<span style="color:#64748b">${t("trash_days_n")!=="trash_days_n"?t("trash_days_n",{n:d}):`${d} days left`}</span>`}e.innerHTML=p.map(a=>`
        <div class="trash-row" data-id="${a.id}"
             style="display:flex;align-items:center;gap:10px;padding:10px 20px;
                    border-bottom:1px solid #f1f5f9;transition:background .12s"
             onmouseenter="this.style.background='#f8fafc'"
             onmouseleave="this.style.background=''">
            <span style="font-size:18px;flex-shrink:0">${a.is_dir?"📁":"📄"}</span>
            <div style="flex:1;min-width:0">
                <div style="font-weight:500;font-size:13px;overflow:hidden;text-overflow:ellipsis;
                            white-space:nowrap" title="${escapeHtmlAttr(a.original_path)}">
                    ${escapeHtml(a.name)}
                </div>
                <div style="font-size:11px;color:#94a3b8;margin-top:2px">
                    ${escapeHtml(a.original_path)} &nbsp;·&nbsp;
                    ${r(a.size_bytes)} &nbsp;·&nbsp;
                    ${t("trash_deleted_label")} ${l(a.deleted_at)}
                </div>
            </div>
            <div style="flex-shrink:0;font-size:11px;text-align:right;min-width:70px">
                ${s(a.expires_at)}
            </div>
            <div style="display:flex;gap:6px;flex-shrink:0">
                ${a.is_dir?`<button class="trash-browse-btn" data-trash-path="${escapeHtmlAttr(a.trash_path)}" data-id="${a.id}"
                           style="background:#6366f1;color:white;border:none;border-radius:6px;
                                  padding:4px 10px;cursor:pointer;font-size:12px">
                           ${t("trash_browse")}
                       </button>`:`<button class="trash-preview-btn" data-id="${a.id}" data-name="${escapeHtmlAttr(a.name)}"
                           style="background:#6366f1;color:white;border:none;border-radius:6px;
                                  padding:4px 10px;cursor:pointer;font-size:12px">
                           ${t("trash_preview")}
                       </button>`}
                <button class="trash-restore-btn" data-id="${a.id}"
                    style="background:#22c55e;color:white;border:none;border-radius:6px;
                           padding:4px 10px;cursor:pointer;font-size:12px;font-weight:600">
                    ${t("trash_restore")}
                </button>
                <button class="trash-del-btn" data-id="${a.id}" data-name="${escapeHtmlAttr(a.name)}"
                    style="background:#ef4444;color:white;border:none;border-radius:6px;
                           padding:4px 10px;cursor:pointer;font-size:12px">
                    ${t("trash_delete")}
                </button>
            </div>
        </div>`).join(""),e.querySelectorAll(".trash-restore-btn").forEach(a=>{a.addEventListener("click",async()=>{const d=+a.dataset.id;try{const f=await apiCall(`/api/v1/trash/${d}/restore`,"POST");loadDirectory(currentPath),await _refreshTrashView()}catch(f){alert("Restore failed: "+f.message)}})}),e.querySelectorAll(".trash-del-btn").forEach(a=>{a.addEventListener("click",async()=>{const d=+a.dataset.id,f=a.dataset.name||"";if(await showConfirmModal({title:t("trash_perm_delete_title",{name:f}),message:t("trash_perm_delete_body")}))try{await apiCall(`/api/v1/trash/${d}`,"DELETE"),await _refreshTrashView()}catch(m){showToast(t("trash_delete_failed")+": "+m.message,{type:"error"})}})}),e.querySelectorAll(".trash-preview-btn").forEach(a=>{a.addEventListener("click",()=>{_previewTrashFile(+a.dataset.id,a.dataset.name)})})}window.promptRename=function(e){openMoveDialog(e)};async function openMoveDialog(e){const n=e.split("/").pop()||e,i=e.includes("/")&&e.slice(0,e.lastIndexOf("/"))||"/";if(!document.getElementById("fd-move-style")){const y=document.createElement("style");y.id="fd-move-style",y.textContent=`
            .mv-tree-row{display:flex;align-items:center;gap:0;cursor:pointer;border-radius:6px;
                padding:3px 6px;font-size:13px;user-select:none;white-space:nowrap}
            .mv-tree-row:hover{background:#f1f5f9}
            .mv-tree-row.mv-selected{background:#dbeafe;font-weight:600}
            .mv-tree-row.mv-selected:hover{background:#bfdbfe}
            .mv-expand-btn{background:none;border:none;cursor:pointer;padding:0 2px;
                font-size:11px;width:18px;text-align:center;color:#64748b;flex-shrink:0}
            .mv-expand-btn:hover{color:#1e293b}
            .mv-tree-label{overflow:hidden;text-overflow:ellipsis}
            #mv-name-input{width:100%;padding:7px 10px;border:1px solid #e2e8f0;border-radius:8px;
                font-size:14px;font-family:Inter,sans-serif;outline:none;box-sizing:border-box}
            #mv-name-input:focus{border-color:#3b82f6;box-shadow:0 0 0 2px rgba(59,130,246,.15)}
            .mv-tab{padding:6px 14px;border:none;border-radius:6px;font-size:13px;font-weight:600;
                cursor:pointer;background:none;color:#64748b;transition:background .15s,color .15s}
            .mv-tab.mv-active{background:#3b82f6;color:#fff}
            .mv-tab:not(.mv-active):hover{background:#f1f5f9;color:#1e293b}
        `,document.head.appendChild(y)}const o=document.createElement("div");o.className="modal-overlay",o.id="mv-dialog-overlay",o.innerHTML=`
        <div class="modal-content" style="max-width:560px;width:95vw;padding:0;overflow:hidden;border-radius:14px">
            <!-- Header -->
            <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:16px 20px;display:flex;align-items:center;justify-content:space-between">
                <div>
                    <div style="color:white;font-weight:700;font-size:16px">📁 Move / Rename / Copy</div>
                    <div style="color:rgba(255,255,255,.75);font-size:12px;margin-top:2px;max-width:380px;
                        overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtmlAttr(e)}">${escapeHtml(e)}</div>
                </div>
                <button id="mv-close" style="background:rgba(255,255,255,.2);border:none;border-radius:50%;
                    width:30px;height:30px;color:white;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center">✕</button>
            </div>

            <!-- Tabs -->
            <div style="display:flex;gap:6px;padding:14px 20px 0">
                <button class="mv-tab mv-active" data-tab="move">✂️ Move</button>
                <button class="mv-tab" data-tab="rename">✏️ Rename</button>
                <button class="mv-tab" data-tab="copy">📋 Copy</button>
            </div>

            <!-- Move/Copy tab body -->
            <div id="mv-tab-move" style="padding:14px 20px 20px">
                <div style="font-size:13px;color:#64748b;margin-bottom:8px">
                    Select destination folder — then confirm below.
                </div>
                <!-- New folder shortcut -->
                <div style="display:flex;gap:6px;margin-bottom:8px">
                    <input id="mv-new-folder-input" placeholder="New subfolder name…" style="flex:1;padding:5px 9px;border:1px solid #e2e8f0;border-radius:7px;font-size:13px;font-family:Inter,sans-serif;outline:none">
                    <button id="mv-new-folder-btn" style="background:#0ea5e9;color:white;border:none;border-radius:7px;padding:5px 12px;font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap">+ Folder</button>
                </div>
                <!-- Tree -->
                <div id="mv-tree" style="border:1px solid #e2e8f0;border-radius:8px;background:#f8fafc;
                    height:240px;overflow-y:auto;padding:6px 4px"></div>
                <!-- Selected path display -->
                <div style="margin-top:8px;font-size:12px;color:#64748b">
                    Destination: <span id="mv-dest-label" style="font-weight:600;color:#1e293b">/</span>
                </div>
            </div>

            <!-- Rename tab body -->
            <div id="mv-tab-rename" style="display:none;padding:14px 20px 20px">
                <label style="display:block;font-size:13px;color:#64748b;margin-bottom:6px">New name (filename only, no slashes):</label>
                <input id="mv-name-input" type="text" value="${escapeHtmlAttr(n)}" spellcheck="false" autocomplete="off">
                <div style="font-size:12px;color:#94a3b8;margin-top:6px">The file stays in its current folder. To also move it, use the Move tab.</div>
            </div>

            <!-- Footer -->
            <div style="padding:12px 20px 18px;display:flex;gap:8px;justify-content:flex-end;border-top:1px solid #f1f5f9">
                <button id="mv-cancel-btn" class="btn" style="background:#e2e8f0;color:#1e293b">Cancel</button>
                <button id="mv-confirm-btn" class="btn" style="background:#3b82f6;min-width:110px">Move here</button>
            </div>
        </div>`,document.body.appendChild(o);let p="move",l=i;const r=new Map,s=y=>o.querySelector("#"+y),a=o.querySelector(".modal-content");function d(y){if(!a){y();return}const x=a.getBoundingClientRect().height;y();const v=a.getBoundingClientRect().height;if(Math.abs(x-v)<2)return;const _=a.style.overflow;a.style.overflow="hidden",a.style.height=x+"px",a.offsetHeight,a.style.transition="height .22s cubic-bezier(.4,0,.2,1)",a.style.height=v+"px";const S=T=>{T&&T.type==="transitionend"&&T.propertyName!=="height"||(a.style.transition="",a.style.height="",a.style.overflow=_,a.removeEventListener("transitionend",S))};a.addEventListener("transitionend",S),setTimeout(S,300)}function f(y){p=y,o.querySelectorAll(".mv-tab").forEach(v=>{v.classList.toggle("mv-active",v.dataset.tab===y)}),d(()=>{s("mv-tab-move").style.display=y==="move"||y==="copy"?"":"none",s("mv-tab-rename").style.display=y==="rename"?"":"none"});const x=s("mv-confirm-btn");y==="move"&&(x.textContent=t("mv_move_here"),x.style.background="#3b82f6"),y==="copy"&&(x.textContent=t("mv_copy_here"),x.style.background="#0ea5e9"),y==="rename"&&(x.textContent=t("mv_rename_btn"),x.style.background="#8b5cf6")}function c(){s("mv-dest-label").textContent=l||"/"}function m(y){return r.has(y)||r.set(y,{children:[],loaded:!1,expanded:!1,loading:!1}),r.get(y)}async function u(y){const x=m(y);if(!(x.loaded||x.loading)){x.loading=!0;try{const v=y==="/"?"/api/v1/list/":`/api/v1/list${encodePath(y)}`,_=await apiCall(v,"GET",null,!0);x.children=(_.entries||[]).filter(S=>S.is_dir).map(S=>S.path).sort((S,T)=>S.localeCompare(T,void 0,{sensitivity:"base"})),x.loaded=!0}catch{x.children=[],x.loaded=!0}x.loading=!1}}function g(y,x){return y.map(v=>{const _=m(v),S=v.split("/").pop()||v,T=v===l,B=_.loaded?_.children.length>0:!0,H=_.loading?"⟳":!B&&_.loaded?"·":_.expanded?"▾":"▸";return`<div class="mv-tree-row${T?" mv-selected":""}"
                        data-path="${escapeHtmlAttr(v)}"
                        style="padding-left:${8+x*16}px">
                    <button class="mv-expand-btn" data-expand="${escapeHtmlAttr(v)}">${H}</button>
                    <span class="mv-tree-label" title="${escapeHtmlAttr(v)}">📁 ${escapeHtml(S)}</span>
                </div>
                ${_.expanded&&_.children.length>0?g(_.children,x+1):""}`}).join("")}async function h(){const y=s("mv-tree");if(!y)return;const x=m("/");x.loaded||(y.innerHTML=_loadingHtml("12px"),await u("/"),x.expanded=!0),y.innerHTML=`
            <div class="mv-tree-row${l==="/"?" mv-selected":""}" data-path="/"
                style="padding-left:8px;font-weight:600">
                <button class="mv-expand-btn" data-expand="/">▾</button>
                <span class="mv-tree-label">🏠 / (root)</span>
            </div>
            ${g(x.children,1)}`,b()}function b(){const y=s("mv-tree");y&&(y.querySelectorAll(".mv-tree-row").forEach(x=>{x.addEventListener("click",v=>{v.target.classList.contains("mv-expand-btn")||(l=x.dataset.path,c(),h())})}),y.querySelectorAll(".mv-expand-btn").forEach(x=>{x.addEventListener("click",async v=>{v.stopPropagation();const _=x.dataset.expand,S=m(_);S.loaded?S.expanded=!S.expanded:(await u(_),S.expanded=!0),h()})}))}s("mv-new-folder-btn").addEventListener("click",async()=>{const y=s("mv-new-folder-input"),x=y.value.trim();if(!x)return;const v=(l.endsWith("/")?l:l+"/")+x;try{await apiCall("/api/v1/mkdir","POST",{path:v},!0),y.value="";const _=m(l);_.loaded=!1,_.expanded=!0,await u(l),l=v,c(),h()}catch(_){showMessage(t("create_folder_failed"),_.message)}}),s("mv-new-folder-input").addEventListener("keydown",y=>{y.key==="Enter"&&s("mv-new-folder-btn").click()}),o.querySelectorAll(".mv-tab").forEach(y=>{y.addEventListener("click",()=>f(y.dataset.tab))}),s("mv-confirm-btn").addEventListener("click",async()=>{const y=s("mv-confirm-btn");if(!o.isConnected)return;if(p==="rename"){const v=s("mv-name-input").value.trim();if(!v||v.includes("/")){showMessage(t("mv_invalid_name_title"),t("mv_invalid_name_body"));return}const _=i==="/"?"/"+v:i+"/"+v;y.disabled=!0,y.textContent=t("mv_renaming");const S=showSpinnerOverlay(t("mv_renaming"),{minMs:1e3});try{await withMinDelay(apiCall("/api/v1/rename","POST",{old:e,new:_}),1e3),S(),o.remove(),_dropSelectedUnder(e),_updateSelBar(),loadDirectory(currentPath)}catch(T){S(),y.disabled=!1,y.textContent=t("mv_rename_btn"),T.message!=="SESSION_EXPIRED"&&showMessage(t("mv_rename_failed_title"),T.message)}return}if(!l){showMessage(t("mv_no_destination_title"),t("mv_no_destination_body"));return}const x=(l.endsWith("/")?l:l+"/")+n;if(p==="move"){if(x===e){showMessage(t("mv_same_location_title"),t("mv_same_location_body"));return}y.disabled=!0,y.textContent=t("mv_moving");const v=showSpinnerOverlay(t("mv_moving"),{minMs:1e3});try{await withMinDelay(apiCall("/api/v1/rename","POST",{old:e,new:x}),1e3),v(),o.remove(),_dropSelectedUnder(e),_updateSelBar(),loadDirectory(currentPath)}catch(_){v(),y.disabled=!1,y.textContent=t("mv_move_here"),_.message!=="SESSION_EXPIRED"&&showMessage(t("mv_move_failed_title"),_.message)}}else{if(x===e){showMessage(t("mv_same_location_title"),t("mv_same_location_body"));return}y.disabled=!0,y.textContent=t("mv_copying");try{const v=await apiCall("/api/v1/copy","POST",{src:e,dest:x});o.remove();const _=e.split("/").filter(Boolean).pop()||e;_startCopyJobTracking(v.job_id,_)}catch(v){y.disabled=!1,y.textContent=t("mv_copy_here"),v.message!=="SESSION_EXPIRED"&&showMessage(t("mv_copy_failed_title"),v.message)}}});const E=()=>{window.fdCloseOverlay(o),_detachModalKeys()};s("mv-cancel-btn").addEventListener("click",E),s("mv-close").addEventListener("click",E);function k(){_attachModalKeys(()=>{o.isConnected&&s("mv-confirm-btn").click()},E)}o.querySelectorAll(".mv-tab").forEach(y=>{y.addEventListener("click",()=>k())}),k(),s("mv-name-input").addEventListener("keydown",y=>{y.key==="Enter"&&(y.preventDefault(),y.stopPropagation(),s("mv-confirm-btn").click())}),o.addEventListener("click",y=>{y.target===o&&E()}),c();async function w(y){const x=y.split("/").filter(Boolean);let v="/";m("/").expanded=!0,await u("/");for(const _ of x){v=v==="/"?"/"+_:v+"/"+_;const S=m(v);S.expanded=!0,await u(v)}}w(i).then(()=>h())}async function promptCreateFolder(){const e=await showPromptModal({title:t("create_folder_title"),label:t("folder_name_label"),defaultValue:"NewFolder",confirmLabel:t("create")});if(e)try{let n=currentPath.endsWith("/")?currentPath+e:currentPath+"/"+e;await apiCall("/api/v1/mkdir","POST",{path:n},!0),showToast(t("folder_created_toast",{name:e})),loadDirectory(currentPath)}catch(n){try{const i=new FormData;i.append("fileToUpload",new Blob([""]),".placeholder");let o=currentPath.endsWith("/")?currentPath+e:currentPath+"/"+e;const p="/api/v1/upload/"+encodePath(o);await uploadFormData(p,i),showToast(t("folder_created_toast",{name:e})),loadDirectory(currentPath)}catch(i){showMessage(t("create_folder_failed"),n.message||String(i))}}}const ANON_TOKEN_KEY_PREFIX="fluxdrop_anon_upload_";function saveAnonDeviceToken(e,n){try{localStorage.setItem(ANON_TOKEN_KEY_PREFIX+e,n)}catch{}}function loadAnonDeviceToken(e){try{return localStorage.getItem(ANON_TOKEN_KEY_PREFIX+e)||null}catch{return null}}function removeAnonDeviceToken(e){try{localStorage.removeItem(ANON_TOKEN_KEY_PREFIX+e)}catch{}}const INTERRUPTED_KEY_PREFIX="fluxdrop_interrupted_";function saveInterruptedUpload(e,n){try{localStorage.setItem(INTERRUPTED_KEY_PREFIX+e,JSON.stringify(n))}catch{}}function loadInterruptedUpload(e){try{const n=localStorage.getItem(INTERRUPTED_KEY_PREFIX+e);return n?JSON.parse(n):null}catch{return null}}function removeInterruptedUpload(e){try{localStorage.removeItem(INTERRUPTED_KEY_PREFIX+e)}catch{}}function getAllInterruptedUploads(){const e=[];try{for(let n=0;n<localStorage.length;n++){const i=localStorage.key(n);if(i&&i.startsWith(INTERRUPTED_KEY_PREFIX))try{e.push(JSON.parse(localStorage.getItem(i)))}catch{}}}catch{}return e}function _concurrencyForSpeed(e){if(!e||e<=0)return 3;const n=e/1024;return n<100?1:n<500?2:n<2e3?3:n<5e3?4:6}async function uploadChunked(e,n,i={}){const o=i.ownerType||"user",p=i.shareToken||"";function l($){const z={};return authToken&&(z.Authorization=`Bearer ${authToken}`),$&&(z["X-Anon-Device-Token"]=$),z}let r,s,a,d,f,c=null;if(i.resumeToken)r=i.resumeToken,s=i.resumeAnonToken||loadAnonDeviceToken(r)||null,a=i.resumeChunkSize||1*1024*1024,d=e.size===0?0:Math.ceil(e.size/a)||1,f=i.resumeFromChunk||0;else{const[z,I]=await Promise.allSettled([fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/config`,{headers:l(null)}).then(X=>X.ok?X.json():null).catch(()=>null),(async()=>{const X=new Uint8Array(524288),le=performance.now(),de=await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/speed_probe`,{method:"POST",headers:{"Content-Type":"application/octet-stream","Content-Length":String(524288),...l(null)},body:X}),ne=(performance.now()-le)/1e3;return de.ok&&ne>0?524288/ne:null})()]),L=z.status==="fulfilled"?z.value:null,M=I.status==="fulfilled"?I.value:null;let j=L&&L.chunk_size?L.chunk_size:1*1024*1024;const C=20,O=32*1024,W=L&&L.max_chunk_size?L.max_chunk_size:j,Y=_concurrencyForSpeed(M),q=M?M/Y:null;let D=null;q&&(D=Math.round(Math.max(O,Math.min(q*C,W))));const ae=D||j,re=e.size===0?0:Math.ceil(e.size/ae)||1,se={filename:e.name,dest_path:n,total_size:e.size,total_chunks:re,preferred_chunk_size:D,sha256:null,owner_type:o,share_token:p},G=await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/init`,{method:"POST",headers:{"Content-Type":"application/json",...l(null)},body:JSON.stringify(se)});if(!G.ok){const X=await G.json().catch(()=>({}));throw new Error(X.error||`Init failed: HTTP ${G.status}`)}const Q=await G.json();r=Q.upload_token,a=Q.chunk_size||j,d=e.size===0?0:Math.ceil(e.size/a)||1,f=0,s=Q.anon_device_token||null,s&&saveAnonDeviceToken(r,s),c=M}const m=i.reuseId!=null?i.reuseId:++uploadIdCounter,u=activeUploads.get(m)||{filename:e.name,loaded:f*a,total:e.size,status:"uploading",speed:null,eta:null,error:null,measuredSpeed:c,paused:!1,cancelled:!1,abortController:null,uploadToken:r,anonDeviceToken:s,chunkSize:a,totalChunks:d,nextChunk:f,destRel:n,ownerType:o,shareToken:p,file:e};u.status="uploading",u.paused=!1,u.cancelled=!1,u.uploadToken=r,u.anonDeviceToken=s,u.chunkSize=a,u.totalChunks=d,u.nextChunk=f,c&&(u.measuredSpeed=c),activeUploads.set(m,u),o==="user"&&saveInterruptedUpload(r,{uploadToken:r,filename:e.name,destRel:n,totalChunks:d,chunkSize:a,nextChunkIdx:f,ownerType:o,shareToken:p,anonDeviceToken:null,total:e.size}),u.measuredSpeed&&u.measuredSpeed>0&&(u.speed=u.measuredSpeed),renderUploadTray();const g=1,h=6;let b=_concurrencyForSpeed(u.measuredSpeed),E=0,k=null,w=u.speed||0,y=null;function x(){y||(y=setInterval(()=>{if(u.cancelled||N){clearInterval(y),y=null;return}if(u.paused)return;const $=u.speed||0;if(w>0&&$>0){const z=$/w;z<.85&&b>g?b=Math.max(g,b-1):z>=.95&&b<h&&E<b+1&&P<d&&(b++,k&&k())}w=$},3e3))}const v=new Map;let _=f*a,S=Date.now(),T=_;const B=.25,H=800;function F($){_=Math.max(0,Math.min(e.size,_+$)),u.loaded=_;const z=Date.now(),I=z-S;if(I>=H){const L=(_-T)/(I/1e3);L>0&&(u.speed=u.speed!=null?B*L+(1-B)*u.speed:L,u.eta=(e.size-_)/u.speed),T=_,S=z}renderUploadTray()}async function A($){const z=await $.arrayBuffer(),I=await crypto.subtle.digest("SHA-256",z);return Array.from(new Uint8Array(I)).map(L=>L.toString(16).padStart(2,"0")).join("")}async function R($){const z=$*a,I=e.slice(z,z+a);let L=null;try{L=await A(I)}catch{}return new Promise((M,j)=>{const C=new XMLHttpRequest;v.set($,C),u.abortController={abort:()=>{v.forEach(q=>q.abort())}};let O=0;function W(){O>0&&(F(-O),O=0)}C.upload.onprogress=q=>{if(!q.lengthComputable)return;const D=q.loaded-O;O=q.loaded,D>0&&F(D)},C.onload=()=>{if(v.delete($),C.status>=200&&C.status<300){const q=I.size-O;q>0&&F(q),renderUploadTray(),M()}else{W(),renderUploadTray();let q=`Chunk ${$} failed: HTTP ${C.status}`;try{const D=JSON.parse(C.responseText);D.error&&(q=D.error)}catch{}j(new Error(q))}},C.onerror=()=>{v.delete($),W(),renderUploadTray(),j(new Error(`Chunk ${$} network error`))},C.onabort=()=>{v.delete($),W(),renderUploadTray();const q=new Error("Upload cancelled");q.name="AbortError",j(q)},C.open("POST",`${API_BASE_URL}/api/v1/upload_session/${r}/chunk/${$}`),C.setRequestHeader("Content-Type","application/octet-stream"),L&&C.setRequestHeader("X-Chunk-SHA256",L);const Y=l(s);for(const[q,D]of Object.entries(Y))C.setRequestHeader(q,D);C.timeout=9e4,C.ontimeout=()=>{v.delete($),W(),renderUploadTray(),j(new Error(`Chunk ${$} timed out`))},C.send(I)})}let P=f,N=null;async function oe(){for(;;){for(;u.paused&&!u.cancelled;)await new Promise(z=>setTimeout(z,200));if(u.cancelled||N)return;const $=P++;if($>=d)return;u.nextChunk=$,o==="user"&&saveInterruptedUpload(r,{uploadToken:r,filename:e.name,destRel:n,totalChunks:d,chunkSize:a,nextChunkIdx:$,ownerType:o,shareToken:p,anonDeviceToken:null,total:e.size});try{await R($)}catch(z){if(z.name==="AbortError"){if(u.paused&&!u.cancelled){$<P&&(P=$);return}u.cancelled=!0;return}if(u.cancelled)return;const I=3;let L=z;for(let M=1;M<=I;M++){if(u.cancelled)return;const j=1500*M;u.status="uploading",u._retrying=!0;for(let C=Math.round(j/1e3);C>0;C--){if(u.cancelled)return;u.error=`Chunk ${$} failed. Retry ${M}/${I} in ${C}s…`,renderUploadTray(),await new Promise(O=>setTimeout(O,1e3))}if(u._retrying=!1,u.cancelled)return;try{await R($),L=null,u.error=null,u._retrying=!1;break}catch(C){if(L=C,C.name==="AbortError"){u.cancelled=!0;return}}}if(L){N=L,u.error=L.message,o==="user"&&saveInterruptedUpload(r,{uploadToken:r,filename:e.name,destRel:n,totalChunks:d,chunkSize:a,nextChunkIdx:$,ownerType:o,shareToken:p,anonDeviceToken:null,total:e.size});return}}}}if(x(),await new Promise($=>{let z=!1;function I(){!z&&E===0&&(z=!0,clearInterval(y),y=null,$())}k=function(){if(u.cancelled||N||P>=d){I();return}E++,oe().finally(()=>{E--,I()})};const L=Math.min(b,Math.max(0,d-f));for(let M=0;M<L;M++)k();L===0&&$()}),u.paused&&!u.cancelled){u.nextChunk=P;const $=new Error("Upload paused");throw $.name="PauseSignal",$}if(u.cancelled){u.status="cancelling",renderUploadTray();try{await Promise.race([fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${r}/cancel`,{method:"DELETE",headers:l(s)}),new Promise($=>setTimeout($,5e3))])}catch{}throw u.status="cancelled",removeInterruptedUpload(r),s&&removeAnonDeviceToken(r),renderUploadTray(),new Error("Upload cancelled")}if(N)throw u.status="error",u.error=N.message,renderUploadTray(),s&&removeAnonDeviceToken(r),N;u.status="verifying",u.speed=null,u.eta=null,u.verifyPct=0,u.verifyEta=null,u.verifyBytes=0,u.verifyTotal=e.size,renderUploadTray();let U=null,V=null,Z=0,J=Date.now();const ee=.3;function ie(){U||(U=setInterval(async()=>{try{const $=await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${r}/assembly_progress`,{headers:l(s)});if(!$.ok)return;const z=await $.json();if(z.error){clearInterval(U);return}u.verifyPct=z.pct||0,u.verifyBytes=z.bytes_hashed||0,u.verifyTotal=z.total_bytes||e.size;const I=Date.now(),L=(I-J)/1e3;if(L>=.5&&u.verifyBytes>Z){const M=(u.verifyBytes-Z)/L;V=V!=null?ee*M+(1-ee)*V:M,u.verifyEta=V>0?(u.verifyTotal-u.verifyBytes)/V:null,Z=u.verifyBytes,J=I}renderUploadTray(),z.done&&(clearInterval(U),U=null)}catch{}},500))}ie();const K=await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${r}/complete`,{method:"POST",headers:l(s)});if(clearInterval(U),!K.ok){const $=await K.json().catch(()=>({}));throw u.status="error",u.error=$.error||`Complete failed: HTTP ${K.status}`,renderUploadTray(),s&&removeAnonDeviceToken(r),new Error(u.error)}u.loaded=e.size,u.status="done";const te=getTrayDismissDelay();return te>0&&!u._dismissScheduled&&(u._dismissScheduled=!0,setTimeout(()=>{activeUploads.delete(m),renderUploadTray()},te)),u.speed=null,u.eta=null,renderUploadTray(),removeInterruptedUpload(r),s&&removeAnonDeviceToken(r),await K.json()}function windowLock(){event.preventDefault(),event.returnValue=""}async function handleUploadForm(e){e.preventDefault(),window.addEventListener("beforeunload",windowLock);const n=document.getElementById("upload-file");if(!n.files.length){showMessage(t("upload_title"),t("upload_no_file"));return}const i=Array.from(n.files),o=document.getElementById("upload-protected").checked,p=currentPath.startsWith("/cdn")?"catbox":"user",l=document.getElementById("btn-upload-submit"),r=document.getElementById("upload-spinner");function s(){l&&(l.disabled=!0,l.style.opacity="0.6"),r&&(r.style.display="inline")}function a(){l&&(l.disabled=!1,l.style.opacity=""),r&&(r.style.display="none")}s();const d=currentPath.endsWith("/")?currentPath:currentPath+"/",f=i.map(m=>{const u=m.webkitRelativePath||m.name;return{file:m,destRel:d+u,ownerType:p,isProtected:o}});if(f.length===1)try{const m=uploadChunked(f[0].file,f[0].destRel,{ownerType:p});setTimeout(a,600),await m,a(),_notifyUploadDone(1),showMessage(t("upload_successful"),t("upload_success_msg",{name:f[0].file.name})),window.removeEventListener("beforeunload",windowLock),loadDirectory(currentPath)}catch(m){if(a(),m.name==="PauseSignal"||m.message==="Upload cancelled")return;showMessage(t("upload_failed"),m.message||String(m))}else{let E=function(){_notifyUploadDone(h,b),_lastUploadBatchCount=0,window.removeEventListener("beforeunload",windowLock)};var c=E;const[m,...u]=f;window._uploadQueue=[...window._uploadQueue||[],...u];const g=()=>{const w=document.getElementById("btn-show-queue"),y=document.getElementById("queue-count");if(w&&y){const x=window._uploadQueue;x.length>0?(w.classList.remove("hidden"),y.textContent=x.length):w.classList.add("hidden")}};g(),setTimeout(a,400),_lastUploadBatchCount+=f.length;let h=0,b=0;async function k(w){let y=w;for(;y;){try{await uploadChunked(y.file,y.destRel,{ownerType:y.ownerType}),h++,loadDirectory(currentPath)}catch(x){if(x.name==="PauseSignal"){_pausedQueueDrain=()=>{_pausedQueueDrain=null;let v=null;window._uploadQueue&&window._uploadQueue.length>0&&(v=window._uploadQueue.shift(),g()),v?k(v):E()};return}x.message!=="Upload cancelled"&&(b++,showMessage(t("upload_failed"),`${y.file.name}: ${x.message||String(x)}`),window.removeEventListener("beforeunload",windowLock))}window._uploadQueue&&window._uploadQueue.length>0?(y=window._uploadQueue.shift(),g()):(y=null,E())}}k(m),showMessage(t("queued"),t("upload_queued_msg",{n:i.length}))}n.value=""}const activeUploads=new Map;let uploadIdCounter=0;function formatSpeed(e){return e<1024?e.toFixed(0)+" B/s":e<1048576?(e/1024).toFixed(1)+" KB/s":e<1073741824?(e/1048576).toFixed(1)+" MB/s":(e/1073741824).toFixed(2)+" GB/s"}function formatEta(e){return!isFinite(e)||e<0?"…":e<60?Math.ceil(e)+"s":e<3600?Math.floor(e/60)+"m "+Math.ceil(e%60)+"s":Math.floor(e/3600)+"h "+Math.floor(e%3600/60)+"m"}function renderUploadTray(){let e=document.getElementById("ul-tray");if(e||(e=document.createElement("div"),e.id="ul-tray",e.style.cssText=`
            position:fixed; bottom:0; left:1rem; width:340px; max-height:60vh;
            overflow-y:auto; background:#1e293b; border-radius:12px 12px 0 0;
            box-shadow:0 -4px 24px rgba(0,0,0,0.4); z-index:9000;
            font-family:Inter,sans-serif; font-size:13px; color:#e2e8f0;
        `,document.body.appendChild(e),e.classList.add("fd-tray-in"),e.addEventListener("animationend",()=>e.classList.remove("fd-tray-in"),{once:!0})),activeUploads.size===0){e.innerHTML.trim()!==""&&window.fdCollapseTray(e).then(()=>{activeUploads.size===0&&(e.innerHTML="")});return}e.classList.remove("fd-tray-closing");let n=e.querySelector(".ul-tray-header");n||(n=document.createElement("div"),n.className="ul-tray-header",n.style.cssText="padding:10px 14px 6px;font-weight:700;font-size:14px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center;",n.innerHTML='<span class="ul-count"></span><span style="cursor:pointer;opacity:.6" id="ul-tray-close">✕</span>',e.prepend(n),n.querySelector("#ul-tray-close").addEventListener("click",async()=>{await window.fdCollapseTray(e),e.innerHTML=""})),n.querySelector(".ul-count").textContent=`📤 Uploads (${activeUploads.size})`,e.querySelectorAll(".ul-row").forEach(i=>{activeUploads.has(+i.dataset.ulId)||i.remove()});for(const[i,o]of activeUploads){const p=o.total?Math.round(o.loaded/o.total*100):0,l=formatBytes(o.loaded),r=o.total?formatBytes(o.total):"?";let s=e.querySelector(`.ul-row[data-ul-id="${+i}"]`);if(!s){s=document.createElement("div"),s.className="ul-row",s.dataset.ulId=i,s.style.cssText="padding:10px 14px;border-bottom:1px solid #1e293b",s.innerHTML=`
                <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                    <span class="ul-name" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:160px"></span>
                    <span class="ul-bytes" style="color:#94a3b8"></span>
                </div>
                <div style="background:#334155;border-radius:4px;height:6px;margin-bottom:6px">
                    <div class="ul-bar" style="background:#22c55e;height:6px;border-radius:4px;width:0%;transition:width .2s"></div>
                </div>
                <div style="display:flex;justify-content:space-between;align-items:center">
                    <span class="ul-status" style="color:#64748b"></span>
                    <div class="ul-actions"></div>
                </div>`,e.appendChild(s),requestAnimationFrame(()=>{e.scrollTop=e.scrollHeight});const h=s.querySelector(".ul-actions"),b=document.createElement("button");b.textContent=t("dl_dismiss"),b.style.cssText="background:#64748b;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px",b.addEventListener("click",()=>{activeUploads.delete(i),renderUploadTray()});const E=document.createElement("button");E.textContent="⏸ "+t("ul_pause"),E.style.cssText="background:#f59e0b;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px",E.addEventListener("click",()=>{o.paused=!0,o.status="paused",o.abortController&&o.abortController.abort(),renderUploadTray()});const k=document.createElement("button");k.textContent="▶ "+t("im_resume"),k.style.cssText="background:#22c55e;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px",k.addEventListener("click",()=>{o.paused=!1,o.cancelled=!1,o.status="uploading",renderUploadTray(),uploadChunked(o.file,o.destRel,{ownerType:o.ownerType,shareToken:o.shareToken,resumeToken:o.uploadToken,resumeFromChunk:o.nextChunk,resumeChunkSize:o.chunkSize,resumeAnonToken:o.anonDeviceToken,reuseId:i}).then(()=>{loadDirectory(currentPath),_pausedQueueDrain&&_pausedQueueDrain()}).catch(y=>{if(y.name!=="PauseSignal"){if(y.message==="Upload cancelled"){_pausedQueueDrain&&_pausedQueueDrain();return}showMessage(t("upload_failed"),y.message),_pausedQueueDrain&&_pausedQueueDrain()}})});const w=document.createElement("button");w.textContent="✕ "+t("ul_cancel"),w.style.cssText="background:#ef4444;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px;margin-left:4px",w.addEventListener("click",()=>{const y=o.paused;o.status="cancelling",renderUploadTray(),o.cancelled=!0,o.paused=!1,o.abortController&&o.abortController.abort(),y&&_pausedQueueDrain&&_pausedQueueDrain()}),h.appendChild(E),h.appendChild(k),h.appendChild(w),h.appendChild(b),s._dismissBtn=b,s._pauseBtn=E,s._resumeBtn=k,s._cancelBtn=w,s._actionsDiv=h}const a={uploading:"⬆",verifying:"🔍",done:"✅",error:"⚠",paused:"⏸",cancelling:"⏳",cancelled:"🚫"};s.querySelector(".ul-name").textContent=(a[o.status]||"")+" "+o.filename,s.querySelector(".ul-bytes").textContent=`${l} / ${r}`;const d=s.querySelector(".ul-bar"),f=o.status==="verifying"&&o.verifyPct!=null&&o.verifyPct>0?o.verifyPct:p;d.style.width=f+"%",d.style.background=o._retrying||o.status==="paused"||o.status==="cancelling"?"#f59e0b":o.status==="error"||o.status==="cancelled"?"#ef4444":o.status==="verifying"?"#a78bfa":"#22c55e",d.style.animation=o._retrying?"fd-retry-pulse 1s ease-in-out infinite":"";let c=o.status;if(o.status==="uploading"){const h=[];o.speed!=null&&h.push(formatSpeed(o.speed)),o.eta!=null&&h.push("ETA "+formatEta(o.eta)),h.length?c=h.join(" · "):o._retrying&&o.error&&(c="🔄 "+o.error)}else if(o.status==="verifying")if(o.verifyPct!=null&&o.verifyPct>0){const h=[`🔍 Verifying… ${o.verifyPct.toFixed(0)}%`];o.verifyEta!=null&&h.push("ETA "+formatEta(o.verifyEta)),o.verifyBytes&&o.verifyTotal&&h.push(`${formatBytes(o.verifyBytes)} / ${formatBytes(o.verifyTotal)}`),c=h.join(" · ")}else c="🔍 Verifying integrity…";else o.status==="paused"?c="⏸ Paused — click Resume to continue":o.status==="cancelling"?c="⏳ Cancelling…":o.status==="error"?c="⚠ "+(o.error||"failed"):o.status==="cancelled"&&(c="🚫 Cancelled");s.querySelector(".ul-status").textContent=c;const m=o.status==="uploading"||o.status==="verifying",u=o.status==="paused",g=o.status==="done"||o.status==="error"||o.status==="cancelled";s._pauseBtn.style.display=m?"":"none",s._resumeBtn.style.display=u?"":"none",s._cancelBtn.style.display=m||u?"":"none",s._dismissBtn.style.display=g?"":"none"}}function uploadFormData(e,n){return new Promise((i,o)=>{const p=++uploadIdCounter,r={filename:(()=>{for(const[,c]of n.entries())if(c instanceof File)return c.name;return"file"})(),loaded:0,total:0,status:"uploading",speed:null,eta:null,error:null};activeUploads.set(p,r),renderUploadTray();const s=new XMLHttpRequest;let a=Date.now(),d=0,f=a;s.upload.addEventListener("progress",c=>{r.loaded=c.loaded,r.total=c.total||0;const m=Date.now(),u=(m-f)/1e3;if(u>=.5){const g=c.loaded-d;r.speed=g/u,r.eta=r.speed>0&&r.total?(r.total-c.loaded)/r.speed:null,d=c.loaded,f=m}renderUploadTray()}),s.addEventListener("load",()=>{if(s.status>=200&&s.status<300){r.loaded=r.total,r.status="done";const c=getTrayDismissDelay();c>0&&!r._dismissScheduled&&(r._dismissScheduled=!0,setTimeout(()=>{activeUploads.delete(p),renderUploadTray()},c)),r.speed=null,r.eta=null,renderUploadTray();try{i(JSON.parse(s.responseText))}catch{i(s.responseText)}}else r.status="error",r.error=`HTTP ${s.status}`,renderUploadTray(),o(new Error(`Upload failed: ${s.status}`))}),s.addEventListener("error",()=>{const c=new XMLHttpRequest;c.upload.addEventListener("progress",m=>{r.loaded=m.loaded,r.total=m.total||0,renderUploadTray()}),c.addEventListener("load",()=>{if(c.status>=200&&c.status<300){r.loaded=r.total,r.status="done";const m=getTrayDismissDelay();m>0&&!r._dismissScheduled&&(r._dismissScheduled=!0,setTimeout(()=>{activeUploads.delete(p),renderUploadTray()},m)),r.speed=null,r.eta=null,renderUploadTray();try{i(JSON.parse(c.responseText))}catch{i(c.responseText)}}else r.status="error",r.error=`HTTP ${c.status}`,renderUploadTray(),o(new Error(`Upload failed: ${c.status}`))}),c.addEventListener("error",()=>{r.status="error",r.error="Network error",renderUploadTray(),o(new Error("Upload failed: network error"))}),authToken&&c.setRequestHeader("Authorization",`Bearer ${authToken}`),c.open("POST",`${API_HTTP}${e}`),authToken&&c.setRequestHeader("Authorization",`Bearer ${authToken}`),c.send(n)}),s.open("POST",`${API_BASE_URL}${e}`),authToken&&s.setRequestHeader("Authorization",`Bearer ${authToken}`),s.send(n)})}async function handleRegister(e){e.preventDefault();const n=document.getElementById("reg-username").value,i=document.getElementById("reg-nickname").value,o=document.getElementById("reg-email").value,p=document.getElementById("reg-password").value,l=e.target.querySelector('button[type="submit"]'),r=l?l.textContent:"";l&&(l.disabled=!0,l.innerHTML=`<span class="fd-btn-spin" aria-hidden="true"></span>${t("registering")}`);const s=showSpinnerOverlay(t("registering"),{minMs:600});try{await apiCall("/auth/register","POST",{username:n,nickname:i,email:o,password:p},!1),s(),showMessage(t("register_success_title"),t("register_success_body"));const a=document.getElementById("fd-auth-modal");a?a.querySelector("#fd-tab-login")?.click():renderApp("login")}catch(a){s(),showMessage(t("register_failed_title"),a.message)}finally{l&&(l.disabled=!1,l.textContent=r)}}async function handleLogin(e){e.preventDefault();const n=document.getElementById("username").value,i=document.getElementById("password").value;try{const o=await apiCall("/auth/login","POST",{username:n,password:i},!1);authToken=o.token,currentUsername=o.username,isAdmin=!!o.is_admin,localStorage.setItem("fluxdrop_token",authToken),localStorage.setItem("fluxdrop_is_admin",o.is_admin?"1":"0"),localStorage.setItem("fluxdrop_username",currentUsername),o.id&&localStorage.setItem("fluxdrop_user_id",String(o.id));const p=document.getElementById("fd-auth-modal");p&&window.fdCloseOverlay(p),delete appRoot.dataset.fdLanding;const l=`fluxdrop_welcomed_${currentUsername}`;localStorage.getItem(l)?renderApp():(localStorage.setItem(l,"1"),renderApp(),_showWelcomeScreen())}catch(o){showMessage(t("login_failed"),o.message)}}function _showWelcomeScreen(){const e=()=>{if(document.querySelector('[id^="pam-"]')?.closest('[style*="z-index:10001"]')){setTimeout(e,400);return}_doShowWelcome()};setTimeout(e,300)}function _doShowWelcome(){const e=document.createElement("div");e.id="fd-welcome-overlay",e.style.cssText=["position:fixed;top:0;left:0;width:100%;height:100%;z-index:10200","background:rgba(15,23,42,.72);display:flex;align-items:center;justify-content:center;padding:1rem","animation:fadeIn .25s ease"].join(";");const n=[["📁","File browser","Browse, create folders, rename, move, and delete files. Sorting and breadcrumb navigation included."],["⬆","Chunked uploads","Upload files up to 10 GB in resumable chunks. Pause, resume, or queue multiple uploads simultaneously."],["📁➡📄","Folder upload","Click the <strong>📁 Folder</strong> toggle next to the upload input to switch between file and folder upload mode. FluxDrop preserves the full directory structure."],["👁","Previews","Click any file name to preview it in-app — images, video, audio, text, Markdown, PDFs, and even ZIP contents."],["🔗","Sharing","Right-click (or use the Share button) on any file or folder to generate a public link. Set expiry, restrict to logged-in users, or allow anonymous uploads."],["🗑","Trash bin","Deleted files land in the Trash (🗑 button, top right). Items are kept for 30 days and can be restored at any time."],["⬇","Downloads","All downloads run in a floating tray (bottom-right). Large downloads support pause/resume via HTTP Range."],["🔒","Protected files","Tick the <em>Protected</em> checkbox before uploading to mark a file as private — it won't appear in public share listings."],["👤","Profile & settings","Click the 👤 button (top-right) to manage your profile, view shared links, check server status, and adjust preferences."],["📡","CDN browser","Click <strong>Browse CDN</strong> to browse the CDN storage area, separate from your personal file space."]];if(e.innerHTML=`
        <div style="background:#fff;border-radius:1.25rem;width:100%;max-width:740px;
                    max-height:92vh;display:flex;flex-direction:column;overflow:hidden;
                    box-shadow:0 32px 64px rgba(0,0,0,.45)">
            <!-- Header -->
            <div style="background:linear-gradient(135deg,#1e40af,#4f46e5);padding:1.75rem 2rem 1.5rem;flex-shrink:0">
                <div style="display:flex;align-items:center;gap:.9rem;margin-bottom:.5rem">
                    <img src="/fluxdrop_pp/icon-128.png" width="44" height="44" style="width:44px;height:44px" alt="">
                    <h2 style="color:white;font-size:1.55rem;font-weight:800;margin:0">Welcome to FluxDrop!</h2>
                </div>
                <p style="color:rgba(255,255,255,.82);margin:0;font-size:.95rem;line-height:1.6">
                    Here's a quick tour of everything available to you.
                </p>
            </div>
            <!-- Feature grid -->
            <div style="overflow-y:auto;flex:1;padding:1.5rem 2rem">
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem">
                    ${n.map(([i,o,p])=>`
                        <div style="display:flex;gap:.75rem;padding:.9rem 1rem;background:#f8fafc;
                                    border-radius:.75rem;border:1px solid #e2e8f0;align-items:flex-start">
                            <div style="font-size:1.4rem;flex-shrink:0;line-height:1;margin-top:.1rem">${i}</div>
                            <div>
                                <div style="font-weight:700;color:#1e293b;font-size:.95rem;margin-bottom:.25rem">${o}</div>
                                <div style="color:#475569;font-size:.85rem;line-height:1.55">${p}</div>
                            </div>
                        </div>`).join("")}
                </div>
                <div style="margin-top:1.25rem;padding:1rem 1.25rem;background:#eff6ff;border-radius:.75rem;
                            border:1px solid #bfdbfe;font-size:.88rem;color:#1e40af;line-height:1.6">
                    💡 <strong>Tip:</strong> This tour won't show again — you can always re-read the
                    <a href="#" onclick="event.preventDefault();document.getElementById('fd-welcome-overlay').remove();showPolicyModal('tos')"
                       style="color:#1d4ed8;text-decoration:underline">Terms of Service</a> and
                    <a href="#" onclick="event.preventDefault();document.getElementById('fd-welcome-overlay').remove();showPolicyModal('pp')"
                       style="color:#1d4ed8;text-decoration:underline">Privacy Policy</a> from the footer.
                </div>
            </div>
            <!-- Footer -->
            <div style="padding:1rem 2rem;border-top:1px solid #e2e8f0;display:flex;justify-content:flex-end;flex-shrink:0">
                <button id="fd-welcome-ok" class="btn" style="padding:.7rem 2rem;font-size:.95rem">
                    Get started →
                </button>
            </div>
        </div>`,!document.getElementById("fd-fadein-style")){const i=document.createElement("style");i.id="fd-fadein-style",i.textContent="@keyframes fadeIn{from{opacity:0}to{opacity:1}}",document.head.appendChild(i)}document.body.appendChild(e),e.querySelector("#fd-welcome-ok").addEventListener("click",()=>e.remove()),e.addEventListener("click",i=>{i.target===e&&e.remove()})}async function handleLogout(){try{await apiCall("/auth/logout","POST")}catch(e){console.error("Logout failed on server, but logging out client-side anyway.",e)}finally{authToken=null,currentUsername=null,isAdmin=!1,localStorage.removeItem("fluxdrop_token"),localStorage.removeItem("fluxdrop_is_admin"),localStorage.removeItem("fluxdrop_username"),renderApp()}}function _showAvatarEditor(e,n){const l=document.createElement("div");l.style.cssText="position:fixed;inset:0;background:rgba(0,0,0,.78);display:flex;align-items:center;justify-content:center;z-index:20000;font-family:Inter,sans-serif",l.innerHTML=`
        <div style="background:#1e293b;border-radius:14px;overflow:hidden;
                    width:340px;max-width:96vw;
                    box-shadow:0 24px 64px rgba(0,0,0,.65)">
            <!-- Header -->
            <div style="display:flex;justify-content:space-between;align-items:center;
                        padding:13px 16px;border-bottom:1px solid #334155">
                <span style="color:#e2e8f0;font-weight:700;font-size:14px">✂ ${t("avatar_crop_title")}</span>
                <button id="aed-x" style="background:rgba(255,255,255,.1);border:none;color:#e2e8f0;
                    border-radius:50%;width:26px;height:26px;cursor:pointer;font-size:15px;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <!-- Canvas -->
            <div style="padding:16px 20px;display:flex;flex-direction:column;align-items:center;gap:10px">
                <canvas id="aed-cv" width="300" height="300"
                    style="border-radius:8px;cursor:grab;touch-action:none;
                           max-width:calc(96vw - 40px);max-height:calc(96vw - 40px)"></canvas>
                <p style="margin:0;font-size:11px;color:#475569;text-align:center">
                    ${t("avatar_crop_hint")}
                </p>
            </div>
            <!-- Footer -->
            <div style="display:flex;justify-content:space-between;align-items:center;
                        gap:8px;padding:13px 16px;border-top:1px solid #334155">
                <button id="aed-reset"
                    style="background:#334155;color:#cbd5e1;border:none;border-radius:7px;
                           padding:7px 14px;cursor:pointer;font-size:13px">${t("avatar_crop_reset")}</button>
                <div style="display:flex;gap:8px">
                    <button id="aed-cancel"
                        style="background:#334155;color:#cbd5e1;border:none;border-radius:7px;
                               padding:7px 14px;cursor:pointer;font-size:13px">${t("cancel")}</button>
                    <button id="aed-ok"
                        style="background:#3b82f6;color:#fff;border:none;border-radius:7px;
                               padding:7px 18px;cursor:pointer;font-size:13px;font-weight:600">
                        ${t("avatar_set_photo")}
                    </button>
                </div>
            </div>
        </div>`,document.body.appendChild(l);const r=l.querySelector("#aed-cv"),s=r.getContext("2d"),a=new Image;let d=URL.createObjectURL(e),f=0,c=0,m=1,u=1;function g(){s.clearRect(0,0,300,300),s.save(),s.translate(300/2+f,300/2+c),s.scale(m,m),s.drawImage(a,-a.naturalWidth/2,-a.naturalHeight/2),s.restore(),s.save(),s.fillStyle="rgba(0,0,0,0.52)",s.beginPath(),s.rect(0,0,300,300),s.arc(300/2,300/2,130,0,Math.PI*2,!0),s.fill("evenodd"),s.strokeStyle="rgba(96,165,250,0.85)",s.lineWidth=2,s.beginPath(),s.arc(300/2,300/2,130,0,Math.PI*2),s.stroke(),s.restore()}function h(){const _=a.naturalWidth*m/2,S=a.naturalHeight*m/2,T=Math.max(0,_-130),B=Math.max(0,S-130);f=Math.max(-T,Math.min(T,f)),c=Math.max(-B,Math.min(B,c))}a.onload=()=>{u=Math.max(260/a.naturalWidth,260/a.naturalHeight),m=u,f=0,c=0,g()},a.src=d;let b=null;r.addEventListener("mousedown",_=>{b={sx:_.clientX,sy:_.clientY,ox:f,oy:c},r.style.cursor="grabbing"});const E=_=>{b&&(f=b.ox+(_.clientX-b.sx),c=b.oy+(_.clientY-b.sy),h(),g())},k=()=>{b=null,r.style.cursor="grab"};window.addEventListener("mousemove",E),window.addEventListener("mouseup",k),r.addEventListener("wheel",_=>{_.preventDefault(),m=Math.max(u,Math.min(m*(_.deltaY<0?1.1:.9),u*10)),h(),g()},{passive:!1});const w={};let y=null,x=null;r.addEventListener("touchstart",_=>{_.preventDefault(),[..._.changedTouches].forEach(T=>{w[T.identifier]={x:T.clientX,y:T.clientY}});const S=Object.keys(w);if(S.length===2){const[T,B]=S.map(H=>w[H]);y=Math.hypot(B.x-T.x,B.y-T.y),x=m}if(S.length===1){const T=_.changedTouches[0];b={sx:T.clientX,sy:T.clientY,ox:f,oy:c}}},{passive:!1}),r.addEventListener("touchmove",_=>{_.preventDefault(),[..._.changedTouches].forEach(T=>{w[T.identifier]={x:T.clientX,y:T.clientY}});const S=Object.keys(w);if(S.length===2&&y){const[T,B]=S.map(F=>w[F]),H=Math.hypot(B.x-T.x,B.y-T.y);m=Math.max(u,Math.min(x*H/y,u*10))}else if(S.length===1&&b){const T=_.changedTouches[0];f=b.ox+(T.clientX-b.sx),c=b.oy+(T.clientY-b.sy)}h(),g()},{passive:!1}),r.addEventListener("touchend",_=>{[..._.changedTouches].forEach(S=>{delete w[S.identifier]}),Object.keys(w).length<2&&(y=null,x=null),Object.keys(w).length===0&&(b=null)});function v(){window.removeEventListener("mousemove",E),window.removeEventListener("mouseup",k),URL.revokeObjectURL(d),l.remove()}l.querySelector("#aed-x").addEventListener("click",v),l.querySelector("#aed-cancel").addEventListener("click",v),l.querySelector("#aed-reset").addEventListener("click",()=>{m=u,f=0,c=0,g()}),l.querySelector("#aed-ok").addEventListener("click",()=>{const _=document.createElement("canvas");_.width=_.height=600;const S=_.getContext("2d"),T=600/260;S.translate((130+f)*T,(130+c)*T),S.scale(m*T,m*T),S.drawImage(a,-a.naturalWidth/2,-a.naturalHeight/2),_.toBlob(B=>{v(),B&&n(B)},"image/jpeg",.88)})}function openProfileMenu(){const e=document.getElementById("profile-menu-modal");if(e){e.remove();return}const n=document.createElement("div");n.id="profile-menu-modal",n.className="fd-profile-overlay",n.style.cssText="position:fixed;inset:0;z-index:8000;display:flex;align-items:flex-start;justify-content:flex-end;padding:70px 1rem 0 0",n.innerHTML=`
        <div id="profile-menu-panel" data-fd-dark="surface" style="background:white;border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,0.18);min-width:260px;overflow:hidden;animation:fadeSlideDown .15s ease">
            <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:18px 20px;display:flex;align-items:center;gap:12px" data-fd-dark="header">
                <!-- Avatar with fallback emoji -->
                <div style="width:46px;height:46px;border-radius:50%;overflow:hidden;
                            background:rgba(255,255,255,0.25);flex-shrink:0;
                            display:flex;align-items:center;justify-content:center;font-size:22px">
                    <img id="pm-avatar-img"
                         src="${_avatarUrl()}"
                         style="width:46px;height:46px;object-fit:cover;display:block"
                         onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"
                         alt="">
                    <span id="pm-avatar-fallback"
                          style="display:none;width:100%;height:100%;
                                 align-items:center;justify-content:center;font-size:22px">👤</span>
                </div>
                <div>
                    <div style="color:white;font-weight:700;font-size:15px">${currentUsername}</div>
                    <div style="color:rgba(255,255,255,0.75);font-size:12px">${t("menu_account_info_fluxdrop")}</div>
                </div>
            </div>
            <div id="pm-quota-bar" style="padding:10px 16px 6px;border-bottom:1px solid var(--fd-border,#e2e8f0)">
                <div style="font-size:11px;color:#94a3b8;margin-bottom:4px">${t("menu_account_info_storage_loading")}</div>
                <div style="background:#e2e8f0;border-radius:4px;height:5px;overflow:hidden">
                    <div id="pm-quota-fill" style="height:100%;border-radius:4px;background:#3b82f6;width:0%;transition:width .4s"></div>
                </div>
            </div>
            <div style="padding:8px 0">
                <button class="profile-menu-item" id="pm-profile">${t("menu_account_info_profile")}</button>
                <button class="profile-menu-item" id="pm-shares">${t("menu_account_info_links")}</button>
                <button class="profile-menu-item" id="pm-beacon">${t("menu_account_info_ip_beacon")}</button>
                <button class="profile-menu-item" id="pm-status">${t("menu_account_info_status")}</button>
                <div style="height:1px;background:var(--fd-border,#f1f5f9);margin:4px 0"></div>
                ${isAdmin?`<button class="profile-menu-item" id="pm-admin">${t("menu_account_info_admin_panel")}</button>`:""}
                <button class="profile-menu-item" id="pm-logout" style="color:#ef4444">${t("menu_account_info_logout")}</button>
            </div>
        </div>`;const i=document.createElement("style");i.textContent=`
        .profile-menu-item{display:block;width:100%;text-align:left;padding:10px 20px;background:none;border:none;font-size:14px;cursor:pointer;color:#1e293b;transition:background .15s}
        .profile-menu-item:hover{background:#f8fafc}
        @keyframes fadeSlideDown{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}`,n.appendChild(i),document.body.appendChild(n),n.addEventListener("click",o=>{o.target===n&&window.fdCloseOverlay(n)}),document.getElementById("pm-profile").addEventListener("click",()=>{n.remove(),openProfilePanel()}),document.getElementById("pm-quota-bar").style.cursor="pointer",document.getElementById("pm-quota-bar").title=t("pp_open_space_analyzer"),document.getElementById("pm-quota-bar").addEventListener("click",()=>{window.fdCloseOverlay(n),openSpaceAnalyzer()}),document.getElementById("pm-shares").addEventListener("click",()=>{n.remove(),openShareManager()}),document.getElementById("pm-beacon").addEventListener("click",()=>{n.remove(),window.location.href="/beacon/ui"}),document.getElementById("pm-status").addEventListener("click",()=>{n.remove(),window.location.href="/status"}),document.getElementById("pm-logout").addEventListener("click",()=>{n.remove(),handleLogout()}),isAdmin&&document.getElementById("pm-admin")?.addEventListener("click",()=>{n.remove(),openAdminPanel()}),apiCall("/api/v1/me","GET").then(o=>{const p=document.getElementById("pm-quota-bar"),l=document.getElementById("pm-quota-fill");if(!p||!l)return;const r=o.usage_bytes||0,s=o.quota_bytes||1,a=Math.min(100,r/s*100),d=a>=95?"#ef4444":a>=75?"#f59e0b":"#3b82f6",f=c=>c>=1073741824?(c/1073741824).toFixed(1)+" GB":c>=1048576?(c/1048576).toFixed(1)+" MB":(c/1024).toFixed(0)+" KB";p.querySelector("div").textContent=`${t("menu_account_info_storage")} ${f(r)} ${t("quota_of_word")} ${f(s)} (${a.toFixed(0)}%)`,l.style.width=a.toFixed(1)+"%",l.style.background=d}).catch(()=>{const o=document.getElementById("pm-quota-bar");o&&(o.querySelector("div").textContent=t("menu_account_info_storage")+" unavailable")})}async function openProfilePanel(){const e=document.getElementById("profile-panel-overlay");if(e){e.remove();return}const n=document.createElement("div");n.className="modal-overlay",n.id="profile-panel-overlay",n.style.zIndex="9000",n.innerHTML=`
        <div data-fd-dark="surface" style="background:white;border-radius:16px;width:95vw;max-width:500px;
                    overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.3);display:flex;flex-direction:column;max-height:90vh">
            <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:18px 24px;
                        display:flex;align-items:center;justify-content:space-between;flex-shrink:0">
                <div style="color:white;font-weight:700;font-size:18px">${t("menu_account_info_profile")}</div>
                <button id="pp-close" style="background:rgba(255,255,255,.2);border:none;border-radius:50%;
                    width:32px;height:32px;color:white;font-size:18px;cursor:pointer;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <div style="overflow-y:auto;flex:1;padding:20px 24px;display:grid;gap:20px">
                <!-- Quota card -->
                <div id="pp-quota-card" data-fd-dark="surface2" style="background:#f8fafc;border-radius:10px;padding:14px 16px">
                    <div style="font-size:13px;color:#64748b;margin-bottom:8px">${t("loading")}</div>
                </div>

                <!-- Edit profile section -->
                <div>
                    <div style="font-size:13px;font-weight:700;color:#374151;margin-bottom:10px;
                                text-transform:uppercase;letter-spacing:.05em">${t("profile_info_profile_info")}</div>

                    <!-- Profile picture -->
                    <div style="display:flex;align-items:center;gap:14px;margin-bottom:12px">
                        <div id="pp-avatar-wrap" style="position:relative;flex-shrink:0">
                            <img id="pp-avatar-img"
                                 src="${_avatarUrl()}"
                                 style="width:64px;height:64px;border-radius:50%;object-fit:cover;
                                        border:2px solid #e2e8f0;background:#f1f5f9"
                                 onerror="this.style.display='none';document.getElementById('pp-avatar-fallback').style.display='flex'"
                                 alt="${t("pp_avatar_alt")}">
                            <div id="pp-avatar-fallback"
                                 style="display:none;width:64px;height:64px;border-radius:50%;
                                        background:#dbeafe;border:2px solid #e2e8f0;
                                        align-items:center;justify-content:center;font-size:28px">👤</div>
                        </div>
                        <div style="display:grid;gap:6px">
                            <label id="pp-avatar-btn" class="btn"
                                   style="padding:5px 12px;font-size:12px;cursor:pointer;display:inline-block">
                                ${t("avatar_change_photo")}
                                <input type="file" id="pp-avatar-file" accept="image/*"
                                       style="display:none">
                            </label>
                            <button id="pp-avatar-remove"
                                    style="background:none;border:none;color:#94a3b8;font-size:12px;
                                           cursor:pointer;text-align:left;padding:0;text-decoration:underline">
                                ${t("avatar_remove_photo")}
                            </button>
                            <div id="pp-avatar-msg" style="font-size:11px;color:#94a3b8">
                                ${t("avatar_hint")}
                            </div>
                        </div>
                    </div>

                    <div style="display:grid;gap:10px">
                        <label style="font-size:13px;font-weight:600;color:#374151">${t("profile_info_nickname")}
                            <input id="pp-nickname" type="text" placeholder="${t("loading")}"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <label style="font-size:13px;font-weight:600;color:#374151">${t("email")}
                            <input id="pp-email" type="email" placeholder="${t("loading")}"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <div id="pp-profile-msg" style="display:none;font-size:13px;border-radius:6px;padding:6px 10px"></div>
                        <button id="pp-save-profile" class="btn" style="justify-self:end;padding:.5rem 1.25rem">${t("save_changes")}</button>
                    </div>
                </div>

                <hr style="border:none;border-top:1px solid var(--fd-border,#e2e8f0);margin:0">

                <!-- Change password section -->
                <div>
                    <div style="font-size:13px;font-weight:700;color:#374151;margin-bottom:10px;
                                text-transform:uppercase;letter-spacing:.05em">${t("change_password")}</div>
                    <div style="display:grid;gap:10px">
                        <label style="font-size:13px;font-weight:600;color:#374151">${t("current_pw")}
                            <input id="pp-cur-pw" type="password" autocomplete="current-password"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <label style="font-size:13px;font-weight:600;color:#374151">${t("new_password")}
                            <input id="pp-new-pw" type="password" autocomplete="new-password"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <label style="font-size:13px;font-weight:600;color:#374151">${t("profile_info_password_confirm")}
                            <input id="pp-confirm-pw" type="password" autocomplete="new-password"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <div id="pp-pw-msg" style="display:none;font-size:13px;border-radius:6px;padding:6px 10px"></div>
                        <button id="pp-change-pw" class="btn" style="justify-self:end;padding:.5rem 1.25rem;background:#6366f1">${t("change_password")}</button>
                    </div>
                </div>

                <!-- Settings card -->
                <div>
                    <div style="font-size:13px;font-weight:700;color:#374151;margin-bottom:10px;
                                text-transform:uppercase;letter-spacing:.05em">${t("transfer_tray")}</div>
                    <label style="font-size:13px;font-weight:600;color:#374151">
                        ${t("auto_dismiss")}
                        <select id="pp-dismiss-delay" style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                            border:1px solid #e2e8f0;border-radius:8px;font-size:14px;font-family:Inter,sans-serif">
                            <option value="0">${t("never_dismiss")}</option>
                            <option value="3000">${t("profile_info_info_modal_message_autoclose_selector_3s")}</option>
                            <option value="5000">${t("profile_info_info_modal_message_autoclose_selector_5s")}</option>
                            <option value="10000">${t("profile_info_info_modal_message_autoclose_selector_10s")}</option>
                            <option value="30000">${t("profile_info_info_modal_message_autoclose_selector_30s")}</option>
                        </select>
                    </label>
                </div>

                <!-- Account info footer -->
                <div id="pp-account-info" style="font-size:12px;color:#94a3b8;padding-bottom:4px"></div>
            </div>
        </div>`,document.body.appendChild(n),n.addEventListener("click",d=>{d.target===n&&window.fdCloseOverlay(n)}),n.querySelector("#pp-close").addEventListener("click",()=>window.fdCloseOverlay(n));function i(d,f,c){const m=n.querySelector("#"+d);m&&(m.textContent=f,m.style.display=f?"block":"none",m.style.background=c?"#fef2f2":"#f0fdf4",m.style.color=c?"#ef4444":"#16a34a")}try{const d=await apiCall("/api/v1/me","GET");if(!n.isConnected)return;const f=d.usage_bytes||0,c=d.quota_bytes||1,m=Math.min(100,f/c*100),u=m>=95?"#ef4444":m>=75?"#f59e0b":"#22c55e",g=E=>E>=1073741824?(E/1073741824).toFixed(2)+" GB":E>=1048576?(E/1048576).toFixed(1)+" MB":(E/1024).toFixed(0)+" KB",h=d.quota_override?` · <span style="color:#6366f1;font-size:11px">${t("quota_pinned")}</span>`:` · <span style="color:#94a3b8;font-size:11px">${t("quota_dynamic")}</span>`;n.querySelector("#pp-quota-card").innerHTML=`
            <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px">
                <span style="font-size:13px;font-weight:600;color:#374151">${t("storage_quota")}</span>
                <span style="font-size:13px;color:#475569">${g(f)} <span style="color:#94a3b8">${t("quota_of_word")}</span> ${g(c)}</span>
            </div>
            <div style="background:#e2e8f0;border-radius:6px;height:8px;overflow:hidden;margin-bottom:6px">
                <div style="height:100%;border-radius:6px;background:${u};width:${m.toFixed(1)}%;transition:width .4s"></div>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="font-size:12px;color:#64748b">${t("profile_info_quota_space",{pct:m.toFixed(1),free:g(c-f),pin:h})}</span>
                ${m>=95?`<span style="font-size:12px;color:#ef4444;font-weight:600">${t("profile_info_quota_space_warning")}</span>`:""}
            </div>
            <div style="font-size:11px;color:#94a3b8;margin-top:6px;text-align:right">${t("profile_info_quota_space_analyzer_hinter")}</div>`;const b=n.querySelector("#pp-quota-card");b.style.cursor="pointer",b.title=t("pp_open_space_analyzer"),b.addEventListener("click",()=>{window.fdCloseOverlay(n),openSpaceAnalyzer()}),n.querySelector("#pp-nickname").value=d.nickname||"",n.querySelector("#pp-email").value=d.email||"",d.id&&localStorage.setItem("fluxdrop_user_id",String(d.id)),n.querySelector("#pp-account-info").innerHTML=`ID ${d.id} ${t("profile_info_username")} <strong>${escapeHtml(d.username)}</strong> ${t("profile_info_join_time")} ${(d.created_at||"").slice(0,10)}`+(d.is_admin?` · <span style="color:#92400e;background:#fef3c7;padding:1px 6px;border-radius:999px;font-weight:600">${t("profile_info_admin_badge")}</span>`:"")}catch(d){if(!n.isConnected)return;n.querySelector("#pp-quota-card").innerHTML=`<div style="color:#ef4444;font-size:13px">${t("pp_load_failed")}: ${escapeHtml(d.message)}</div>`}n.querySelector("#pp-save-profile").addEventListener("click",async()=>{const d=n.querySelector("#pp-save-profile"),f=n.querySelector("#pp-nickname").value.trim(),c=n.querySelector("#pp-email").value.trim();if(!f&&!c){i("pp-profile-msg",t("pp_nothing_to_save"),!0);return}i("pp-profile-msg","",!1),d.disabled=!0,d.textContent=t("pp_saving");try{await apiCall("/api/v1/me","PATCH",{nickname:f,email:c}),i("pp-profile-msg",t("pp_saved"),!1)}catch(m){if(!n.isConnected)return;i("pp-profile-msg",m.message,!0)}finally{n.isConnected&&(d.disabled=!1,d.textContent=t("save_changes"))}});function o(){_bumpAvatarVersion();const d=localStorage.getItem("fluxdrop_user_id")||"0",f=_avatarUrl(d),c=n.querySelector("#pp-avatar-img"),m=n.querySelector("#pp-avatar-fallback"),u=document.getElementById("header-avatar"),g=document.getElementById("header-avatar-fallback");c&&(c.style.display="block",m&&(m.style.display="none"),c.onerror=()=>{c.style.display="none",m&&(m.style.display="flex")},c.src=f),u&&(u.style.display="block",g&&(g.style.display="none"),u.onerror=()=>{u.style.display="none",g&&(g.style.display="flex")},u.src=f)}const p=n.querySelector("#pp-avatar-file"),l=n.querySelector("#pp-avatar-msg");async function r(d){l.textContent=t("uploading"),l.style.color="#64748b";const f=new FormData;f.append("avatar",d,"avatar.jpg");try{const c=await fetchWithFallback(`${API_BASE_URL}/api/v1/me/avatar`,{method:"POST",headers:authToken?{Authorization:`Bearer ${authToken}`}:{},body:f}),m=await c.json();if(!c.ok)throw new Error(m.error||`HTTP ${c.status}`);l.textContent="✓ "+t("pp_avatar_saved",{mime:m.mime,kb:Math.round(m.size_bytes/1024)}),l.style.color="#16a34a",o()}catch(c){l.textContent="⚠ "+c.message,l.style.color="#ef4444"}}p&&p.addEventListener("change",function(){const d=this.files&&this.files[0];if(d){if(!d.type.startsWith("image/")){l.textContent="⚠ "+t("pp_avatar_not_image"),l.style.color="#ef4444";return}this.value="",_showAvatarEditor(d,f=>r(f))}});const s=n.querySelector("#pp-avatar-remove");s&&s.addEventListener("click",async()=>{l.textContent=t("pp_avatar_removing"),l.style.color="#64748b";try{const d=await fetchWithFallback(`${API_BASE_URL}/api/v1/me/avatar`,{method:"DELETE",headers:authToken?{Authorization:`Bearer ${authToken}`}:{}});if(!d.ok)throw new Error(`HTTP ${d.status}`);l.textContent=t("pp_avatar_removed"),l.style.color="#64748b",o()}catch(d){l.textContent="⚠ "+d.message,l.style.color="#ef4444"}}),n.querySelector("#pp-change-pw").addEventListener("click",async()=>{const d=n.querySelector("#pp-change-pw"),f=n.querySelector("#pp-cur-pw").value,c=n.querySelector("#pp-new-pw").value,m=n.querySelector("#pp-confirm-pw").value;if(!f||!c||!m){i("pp-pw-msg",t("pp_pw_all_required"),!0);return}if(c!==m){i("pp-pw-msg",t("pp_pw_mismatch"),!0);return}if(c.length<8){i("pp-pw-msg",t("pp_pw_too_short",{n:8}),!0);return}i("pp-pw-msg","",!1),d.disabled=!0,d.textContent=t("pp_pw_changing");try{const u=await apiCall("/api/v1/me/password","PATCH",{current_password:f,new_password:c});i("pp-pw-msg",t("pp_pw_changed"),!1),n.querySelector("#pp-cur-pw").value="",n.querySelector("#pp-new-pw").value="",n.querySelector("#pp-confirm-pw").value=""}catch(u){if(!n.isConnected)return;i("pp-pw-msg",u.message,!0)}finally{n.isConnected&&(d.disabled=!1,d.textContent=t("change_password"))}});const a=n.querySelector("#pp-dismiss-delay");a&&(a.value=localStorage.getItem("fluxdrop_tray_dismiss_ms")||"0",a.addEventListener("change",()=>{localStorage.setItem("fluxdrop_tray_dismiss_ms",a.value)}))}async function openAdminPanel(){const e=document.getElementById("admin-panel-overlay");if(e){e.remove();return}const n=document.createElement("div");n.className="modal-overlay",n.id="admin-panel-overlay",n.style.zIndex="9000",n.innerHTML=`
        <div style="background:white;border-radius:16px;width:95vw;max-width:860px;
                    max-height:88vh;display:flex;flex-direction:column;overflow:hidden;
                    box-shadow:0 20px 60px rgba(0,0,0,0.3)">
            <div style="background:linear-gradient(135deg,#1e293b,#334155);padding:18px 24px;
                        display:flex;align-items:center;justify-content:space-between;flex-shrink:0">
                <div>
                    <div style="color:white;font-weight:700;font-size:18px">${t("menu_account_info_admin_panel")}</div>
                    <div style="color:rgba(255,255,255,.55);font-size:12px;margin-top:2px">${t("admin_panel_info")}</div>
                </div>
                <button id="ap-close" style="background:rgba(255,255,255,.15);border:none;border-radius:50%;
                    width:32px;height:32px;color:white;font-size:18px;cursor:pointer;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <div id="ap-tabs" style="display:flex;gap:4px;padding:8px 24px 0;background:#f8fafc;flex-shrink:0">
                <button class="ap-tab" data-tab="users">${t("admin_tab_users")}</button>
                <button class="ap-tab" data-tab="reports">${t("admin_tab_reports")} <span id="ap-reports-badge"></span></button>
            </div>
            <div id="ap-stats" style="background:#f8fafc;border-bottom:1px solid #e2e8f0;
                padding:10px 24px;display:flex;gap:24px;flex-shrink:0;flex-wrap:wrap"></div>
            <div style="overflow-y:auto;flex:1;padding:16px 24px">
                <div id="ap-body">
                    <div style="display:flex;align-items:center;gap:12px;padding:24px 0;color:#64748b;font-size:14px">
                        <span style="display:inline-block;width:22px;height:22px;border:3px solid #e2e8f0;
                                     border-top-color:#3b82f6;border-radius:50%;
                                     animation:fd-spin 0.8s linear infinite;flex-shrink:0"></span>
                        ${t("admin_panel_loading")}
                    </div>
                </div>
            </div>
        </div>`,document.body.appendChild(n),n.addEventListener("click",i=>{i.target===n&&window.fdCloseOverlay(n)}),document.getElementById("ap-close").addEventListener("click",()=>window.fdCloseOverlay(n)),_apInjectStyle(),n.querySelectorAll(".ap-tab").forEach(i=>{i.addEventListener("click",()=>_apShowTab(i.dataset.tab))}),_apRefreshReportsBadge(),await _apShowTab("users")}async function _apShowTab(e){document.querySelectorAll("#ap-tabs .ap-tab").forEach(i=>i.classList.toggle("ap-tab-active",i.dataset.tab===e));const n=document.getElementById("ap-body");n&&(n.innerHTML=`<div style="padding:24px 0;color:#64748b;font-size:14px">${t("loading")}</div>`),e==="reports"?await _apLoadReports():await _apLoadUsers()}async function _apRefreshReportsBadge(){try{const e=await apiCall("/api/v1/admin/reports?status=open","GET"),n=document.getElementById("ap-reports-badge");n&&(n.innerHTML=e.open_count?`<span class="ap-badge" style="background:#fee2e2;color:#b91c1c">${e.open_count}</span>`:"")}catch{}}function _apInjectStyle(){if(document.getElementById("ap-style"))return;const e=document.createElement("style");e.id="ap-style",e.textContent=`
        .ap-row{display:grid;grid-template-columns:1fr 90px 140px 100px;gap:12px;
            align-items:center;padding:10px 12px;border-radius:8px;transition:background .12s}
        .ap-row:hover{background:#f8fafc}
        .ap-row+.ap-row{border-top:1px solid #f1f5f9}
        .ap-bar-wrap{background:#e2e8f0;border-radius:4px;height:6px;overflow:hidden}
        .ap-bar-fill{height:100%;border-radius:4px;transition:width .3s}
        .ap-badge{display:inline-block;padding:2px 7px;border-radius:999px;font-size:11px;font-weight:600}
        .ap-btn{border:none;border-radius:6px;padding:4px 10px;font-size:12px;
            font-weight:600;cursor:pointer;transition:opacity .15s}
        .ap-btn:hover{opacity:.85}
        .ap-tab{border:none;background:none;padding:8px 14px;font-size:13px;font-weight:600;
            color:#64748b;cursor:pointer;border-radius:8px 8px 0 0;font-family:inherit}
        .ap-tab-active{background:white;color:#1e293b;box-shadow:0 -1px 0 #e2e8f0}
        .ap-rep{border:1px solid #e2e8f0;border-radius:10px;padding:12px 14px;margin-bottom:10px}
        .ap-rep-closed{opacity:.7}
        .ap-rep-meta{font-size:12px;color:#64748b;margin-top:4px;line-height:1.6}
        .ap-rep-msg{white-space:pre-wrap;font-size:13px;background:#f8fafc;border-radius:6px;
            padding:8px 10px;margin-top:8px;color:#334155;max-height:160px;overflow:auto}
        .ap-rep-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
    `,document.head.appendChild(e)}let _apUsagePollTimer=null;async function _apLoadUsers(){const e=document.getElementById("ap-body"),n=document.getElementById("ap-stats");if(!e)return;const i=e.parentElement,o=i?i.scrollTop:0;try{const l=(await apiCall("/api/v1/admin/users","GET")).users||[],r=l.reduce((a,d)=>a+(d.usage_bytes||0),0),s=l.filter(a=>a.is_admin).length;if(n&&(n.innerHTML=[`<span style="font-size:13px;color:#475569"><strong style="color:#1e293b">${l.length}</strong> ${t("admin_panel_user_count")}</span>`,`<span style="font-size:13px;color:#475569"><strong style="color:#1e293b">${s}</strong> ${t("admin_panel_admin_count")}</span>`,`<span style="font-size:13px;color:#475569">${t("admin_panel_used")} <strong style="color:#1e293b">${_apFmtBytes(r)}</strong></span>`].join('<span style="color:#cbd5e1;margin:0 4px">|</span>')),l.length===0){e.innerHTML=`<p style="color:#64748b;font-size:14px;padding:20px 0">${t("admin_panel_no_users")}</p>`;return}_apInjectStyle(),e.innerHTML=`
            <div class="ap-row" style="font-size:12px;font-weight:700;color:#94a3b8;
                border-bottom:2px solid #e2e8f0;border-radius:0;padding-bottom:6px">
                <span>${t("admin_col_user")}</span><span>${t("admin_col_usage")}</span><span>${t("admin_col_quota")}</span>
                <span style="text-align:right">${t("fluxdrop_file_manager_actions")}</span>
            </div>`+l.map(a=>_apRenderRow(a)).join(""),i&&(i.scrollTop=o),e.querySelectorAll(".ap-edit-btn").forEach(a=>{a.addEventListener("click",()=>_apOpenEditModal(+a.dataset.id,l))}),e.querySelectorAll(".ap-del-btn").forEach(a=>{a.addEventListener("click",()=>_apDeleteUser(+a.dataset.id,a.dataset.name))}),clearTimeout(_apUsagePollTimer),l.some(a=>a.usage_bytes==null)&&(_apUsagePollTimer=setTimeout(()=>{const a=document.querySelector("#ap-tabs .ap-tab-active");a&&a.dataset.tab==="users"&&_apLoadUsers()},4e3))}catch(p){const l=document.getElementById("ap-body");p.message!=="SESSION_EXPIRED"&&l&&(l.innerHTML=`<p style="color:#ef4444;font-size:14px;padding:20px 0">${t("admin_panel_load_failed",{err:escapeHtml(p.message)})}</p>`)}}let _apReportsFilter="open";async function _apLoadReports(){const e=document.getElementById("ap-body"),n=document.getElementById("ap-stats");if(e)try{const o=await apiCall("/api/v1/admin/reports"+(_apReportsFilter==="open"?"?status=open":""),"GET"),p=o.reports||[];n&&(n.innerHTML=`
            <span style="font-size:13px;color:#475569"><strong style="color:#1e293b">${o.open_count}</strong> ${t("admin_reports_open_count")}</span>
            <label style="font-size:13px;color:#475569;margin-left:auto;display:flex;align-items:center;gap:6px">
                ${t("admin_reports_show")}
                <select id="ap-rep-filter" style="padding:3px 6px;border:1px solid #e2e8f0;border-radius:6px;font-size:13px">
                    <option value="open" ${_apReportsFilter==="open"?"selected":""}>${t("admin_reports_filter_open")}</option>
                    <option value="all" ${_apReportsFilter==="all"?"selected":""}>${t("admin_reports_filter_all")}</option>
                </select>
            </label>`),document.getElementById("ap-rep-filter")?.addEventListener("change",r=>{_apReportsFilter=r.target.value,_apLoadReports()});const l=document.getElementById("ap-reports-badge");if(l&&(l.innerHTML=o.open_count?`<span class="ap-badge" style="background:#fee2e2;color:#b91c1c">${o.open_count}</span>`:""),!p.length){e.innerHTML=`<p style="color:#64748b;font-size:14px;padding:20px 0">${t("admin_reports_none")}</p>`;return}e.innerHTML=p.map(_apRenderReport).join(""),e.querySelectorAll(".ap-rep-act").forEach(r=>{r.addEventListener("click",()=>_apReportAction(+r.dataset.id,r.dataset.action))})}catch(i){i.message!=="SESSION_EXPIRED"&&(e.innerHTML=`<p style="color:#ef4444;font-size:14px;padding:20px 0">${t("admin_panel_load_failed",{err:escapeHtml(i.message)})}</p>`)}}function _apRenderReport(e){const n={open:"background:#fee2e2;color:#b91c1c",action_taken:"background:#dcfce7;color:#166534",dismissed:"background:#f1f5f9;color:#475569"}[e.status]||"",i=e.share_token?t("admin_reports_kind_share"):e.cdn_path?t("admin_reports_kind_cdn"):t("admin_reports_kind_unknown"),o=e.reporter_username?escapeHtml(e.reporter_username)+(e.reporter_email?` · ${escapeHtml(e.reporter_email)}`:""):e.reporter_email?escapeHtml(e.reporter_email):t("admin_reports_anonymous"),p=/^https?:\/\//i.test(e.target_url)?escapeHtmlAttr(e.target_url):"",l=(s,a,d)=>`<button class="ap-btn ap-rep-act" data-id="${e.id}" data-action="${s}" style="background:${d};color:white">${a}</button>`;let r="";return e.status==="open"?(e.share_token&&e.share_active&&(r+=l("disable_link",t("admin_reports_disable_link"),"#ef4444")),e.cdn_file_exists&&(r+=l("delete_file",t("admin_reports_delete_file"),"#ef4444")),r+=l("resolve",t("admin_reports_resolve"),"#16a34a"),r+=l("dismiss",t("admin_reports_dismiss"),"#64748b")):r+=l("reopen",t("admin_reports_reopen"),"#64748b"),`<div class="ap-rep ${e.status==="open"?"":"ap-rep-closed"}">
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <strong style="font-size:14px">#${e.id}</strong>
            <span class="ap-badge" style="${n}">${t("admin_reports_status_"+e.status)}</span>
            <span class="ap-badge" style="background:#fef3c7;color:#92400e">${t("report_reason_"+e.reason)}</span>
            <span style="font-size:12px;color:#94a3b8;margin-left:auto">${escapeHtml(String(e.created_at||""))} UTC</span>
        </div>
        <div class="ap-rep-meta" data-fd-notranslate>
            ${i}: ${p?`<a href="${p}" target="_blank" rel="noopener noreferrer" style="color:#3b82f6;word-break:break-all">${escapeHtml(e.target_url)}</a>`:escapeHtml(e.target_url)}
            ${e.share_token&&!e.share_active?` <em>(${t("admin_reports_link_gone")})</em>`:""}<br>
            ${t("admin_reports_owner")}: ${e.owner_username?escapeHtml(e.owner_username):"—"}
            · ${t("admin_reports_reporter")}: ${o}
            ${e.resolution_note?`<br>${t("admin_reports_note")}: ${escapeHtml(e.resolution_note)}`:""}
        </div>
        ${e.message?`<div class="ap-rep-msg" data-fd-notranslate>${escapeHtml(e.message)}</div>`:""}
        <div class="ap-rep-actions">${r}</div>
    </div>`}async function _apReportAction(e,n){if(!((n==="disable_link"||n==="delete_file")&&!await showConfirmModal({title:t(n==="disable_link"?"admin_reports_confirm_disable":"admin_reports_confirm_delete",{id:e}),message:t("admin_reports_confirm_body")})))try{await apiCall(`/api/v1/admin/reports/${e}`,"POST",{action:n}),showToast(t("admin_reports_done")),await _apLoadReports()}catch(i){i.message!=="SESSION_EXPIRED"&&showMessage(t("update_failed"),i.message)}}function _apFmtBytes(e){return e>=1073741824?(e/1073741824).toFixed(1)+" GB":e>=1048576?(e/1048576).toFixed(1)+" MB":e>=1024?(e/1024).toFixed(0)+" KB":e+" B"}function _apRenderRow(e){const n=e.usage_bytes==null,i=!n&&e.quota_bytes>0?Math.min(100,e.usage_bytes/e.quota_bytes*100):0,o=i>=95?"#ef4444":i>=75?"#f59e0b":"#22c55e";return`<div class="ap-row">
        <div>
            <div style="font-size:14px;font-weight:600;color:#1e293b">${e.is_admin?`<span class="ap-badge" style="background:#fef3c7;color:#92400e">${t("profile_info_admin_badge")}</span> `:""}${escapeHtml(e.username)}</div>
            <div style="font-size:11px;color:#94a3b8;margin-top:1px">${escapeHtml(e.nickname||"")} · ${escapeHtml(e.email||"")}</div>
            <div style="font-size:11px;color:#cbd5e1;margin-top:1px">${t("admin_row_id_joined",{id:e.id,date:(e.created_at||"").slice(0,10)})}</div>
        </div>
        <div>
            <div style="font-size:12px;color:#475569;margin-bottom:3px">${n?t("admin_usage_calculating"):_apFmtBytes(e.usage_bytes)}</div>
            <div class="ap-bar-wrap"><div class="ap-bar-fill" style="width:${i.toFixed(1)}%;background:${o}"></div></div>
            <div style="font-size:10px;color:#94a3b8;margin-top:2px">${n?"…":i.toFixed(0)+"%"}</div>
        </div>
        <div>
            <div style="font-size:12px;color:#475569">${_apFmtBytes(e.quota_bytes||0)}</div>
            ${e.quota_override?`<div style="font-size:10px;color:#6366f1;margin-top:1px">${t("admin_panel_pinned_badge")}</div>`:`<div style="font-size:10px;color:#94a3b8;margin-top:1px">${t("admin_panel_dynamic_quota")}</div>`}
        </div>
        <div style="display:flex;gap:5px;justify-content:flex-end">
            <button class="ap-btn ap-edit-btn" data-id="${e.id}"
                style="background:#3b82f6;color:white">${t("admin_panel_edit_button")}</button>
            <button class="ap-btn ap-del-btn" data-id="${e.id}" data-name="${escapeHtmlAttr(e.username)}"
                style="background:#ef4444;color:white">${t("admin_panel_delete_button")}</button>
        </div>
    </div>`}function _apOpenEditModal(e,n){const i=n.find(l=>l.id===e);if(!i)return;const o=document.getElementById("ap-edit-overlay");o&&o.remove();const p=document.createElement("div");p.className="modal-overlay",p.id="ap-edit-overlay",p.style.zIndex="9500",p.innerHTML=`
        <div style="background:white;border-radius:14px;width:95vw;max-width:460px;
                    overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.35)">
            <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:16px 20px;
                        display:flex;align-items:center;justify-content:space-between">
                <div style="color:white;font-weight:700;font-size:16px">${t("admin_edit_title",{name:escapeHtml(i.username)})}</div>
                <button id="ap-edit-close" style="background:rgba(255,255,255,.2);border:none;border-radius:50%;
                    width:28px;height:28px;color:white;font-size:16px;cursor:pointer;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <div style="padding:20px;display:grid;gap:12px">
                <label style="font-size:13px;font-weight:600;color:#374151">${t("username_login")}
                    <input id="ape-username" type="text" value="${escapeHtmlAttr(i.username)}"
                        style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                               border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                               box-sizing:border-box;font-family:Inter,sans-serif">
                </label>
                <label style="font-size:13px;font-weight:600;color:#374151">${t("admin_edit_nickname")}
                    <input id="ape-nickname" type="text" value="${escapeHtmlAttr(i.nickname||"")}"
                        style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                               border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                               box-sizing:border-box;font-family:Inter,sans-serif">
                </label>
                <label style="font-size:13px;font-weight:600;color:#374151">${t("email")}
                    <input id="ape-email" type="email" value="${escapeHtmlAttr(i.email||"")}"
                        style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                               border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                               box-sizing:border-box;font-family:Inter,sans-serif">
                </label>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
                    <label style="font-size:13px;font-weight:600;color:#374151">${t("admin_edit_quota_gb")}
                        <input id="ape-quota" type="number" min="1" step="1"
                            value="${Math.round((i.quota_bytes||0)/1024**3)}"
                            style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                   border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                   box-sizing:border-box;font-family:Inter,sans-serif">
                    </label>
                    <label style="font-size:13px;font-weight:600;color:#374151;display:flex;flex-direction:column">
                        <span>${t("admin_edit_flags")}</span>
                        <span style="display:flex;flex-direction:column;gap:6px;margin-top:8px">
                            <label style="display:flex;align-items:center;gap:7px;font-weight:400;cursor:pointer">
                                <input type="checkbox" id="ape-is-admin" ${i.is_admin?"checked":""}> ${t("admin_edit_flag_admin")}
                            </label>
                            <label style="display:flex;align-items:center;gap:7px;font-weight:400;cursor:pointer">
                                <input type="checkbox" id="ape-quota-override" ${i.quota_override?"checked":""}> ${t("admin_edit_flag_pin_quota")}
                            </label>
                        </span>
                    </label>
                </div>
                <div id="ape-error" style="display:none;color:#ef4444;font-size:13px;
                    background:#fef2f2;border-radius:6px;padding:6px 10px"></div>
            </div>
            <div style="padding:12px 20px 18px;display:flex;gap:8px;justify-content:flex-end;
                        border-top:1px solid #f1f5f9">
                <button id="ape-cancel" class="btn" style="background:#e2e8f0;color:#1e293b">${t("cancel")}</button>
                <button id="ape-save" class="btn" style="background:#3b82f6;min-width:80px">${t("admin_edit_save")}</button>
            </div>
        </div>`,document.body.appendChild(p),p.addEventListener("click",l=>{l.target===p&&window.fdCloseOverlay(p)}),p.querySelector("#ap-edit-close").addEventListener("click",()=>window.fdCloseOverlay(p)),p.querySelector("#ape-cancel").addEventListener("click",()=>window.fdCloseOverlay(p)),p.querySelector("#ape-save").addEventListener("click",async()=>{if(!p.isConnected)return;const l=p.querySelector("#ape-save"),r=p.querySelector("#ape-error"),s=parseFloat(p.querySelector("#ape-quota").value);if(isNaN(s)||s<1){r.textContent=t("admin_edit_quota_min_err"),r.style.display="block";return}r.style.display="none",l.disabled=!0,l.textContent=t("admin_edit_saving");try{await apiCall(`/api/v1/admin/users/${e}`,"PATCH",{username:p.querySelector("#ape-username").value.trim(),nickname:p.querySelector("#ape-nickname").value.trim(),email:p.querySelector("#ape-email").value.trim(),quota_bytes:Math.round(s*1024**3),is_admin:p.querySelector("#ape-is-admin").checked?1:0,quota_override:p.querySelector("#ape-quota-override").checked?1:0}),window.fdCloseOverlay(p),await _apLoadUsers()}catch(a){if(!p.isConnected)return;l.disabled=!1,l.textContent=t("admin_edit_save"),a.message!=="SESSION_EXPIRED"&&(r.textContent=a.message,r.style.display="block")}})}async function _apDeleteUser(e,n){const i=t("admin_delete_confirm",{name:n}),[o,...p]=i.split(`

`);if(await showConfirmModal({title:o,message:p.join(`

`)}))try{await apiCall(`/api/v1/admin/users/${e}`,"DELETE"),await _apLoadUsers()}catch(r){r.message!=="SESSION_EXPIRED"&&showMessage(t("admin_delete_failed"),r.message)}}async function openShareDialog(e,n){const i=e.split("/").pop()||e,o=document.createElement("div");o.className="modal-overlay",o.id="share-dialog-overlay",o.innerHTML=`
        <div class="modal-content" style="max-width:500px">
            <h3 style="font-size:18px;font-weight:700;margin-bottom:4px">${t("share_dlg_title",{name:i})}</h3>
            <p style="font-size:13px;color:#64748b;margin-bottom:16px">${n?t("share_dlg_kind_folder"):t("share_dlg_kind_file")}: <code style="background:#f1f5f9;padding:1px 5px;border-radius:4px">${e}</code></p>

            <div style="display:grid;gap:10px;margin-bottom:18px">
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-require-account" style="width:16px;height:16px">
                    <span style="font-size:14px">${t("share_dlg_require_account")}</span>
                </label>
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-stats" checked style="width:16px;height:16px">
                    <span style="font-size:14px">${t("share_dlg_track_stats")}</span>
                </label>

                <div style="display:flex;align-items:center;gap:10px">
                    <span style="font-size:14px;font-weight:600;white-space:nowrap">${t("share_dlg_expires_label")}</span>
                    <select id="sh-expiry-preset" style="flex:1;padding:6px 10px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;background:white">
                        <option value="">${t("share_dlg_exp_never")}</option>
                        <option value="1">${t("share_dlg_exp_1d")}</option>
                        <option value="7">${t("share_dlg_exp_7d")}</option>
                        <option value="30">${t("share_dlg_exp_30d")}</option>
                        <option value="90">${t("share_dlg_exp_90d")}</option>
                        <option value="custom">${t("share_dlg_exp_custom")}</option>
                    </select>
                    <input type="date" id="sh-expiry-custom"
                        style="display:none;padding:6px 10px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px"
                        min="${new Date().toISOString().slice(0,10)}">
                </div>

                <hr style="border:none;border-top:1px solid #e2e8f0;margin:2px 0">
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-allow-preview" style="width:16px;height:16px">
                    <span style="font-size:14px">${t("share_dlg_allow_preview")}</span>
                </label>
                ${n?"":`<label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-cdn-embed" style="width:16px;height:16px">
                    <span style="font-size:14px">${t("share_dlg_allow_cdn")}</span>
                </label>`}

                ${n?`
                <hr style="border:none;border-top:1px solid #e2e8f0;margin:2px 0">
                <label style="display:flex;align-items:center;gap:10px">
                    <span style="font-size:14px;font-weight:600;white-space:nowrap">${t("share_dlg_upload_who")}</span>
                    <select id="sh-upload-policy" style="flex:1;padding:6px 10px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;background:white">
                        <option value="none">${t("share_dlg_upload_none")}</option>
                        <option value="anon">${t("share_dlg_upload_anon")}</option>
                        <option value="auth">${t("share_dlg_upload_auth")}</option>
                    </select>
                </label>`:""}
            </div>

            <div id="sh-result" style="display:none;background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:12px;margin-bottom:14px">
                <div style="font-size:12px;color:#166534;margin-bottom:6px;font-weight:600">${t("share_dlg_link_created")}</div>
                <div style="display:flex;gap:6px">
                    <input id="sh-link-box" type="text" readonly style="flex:1;font-size:12px;padding:6px;border:1px solid #ccc;border-radius:6px;background:white;color:#1e293b">
                    <button id="sh-copy-btn" style="background:#16a34a;color:white;border:none;border-radius:6px;padding:6px 12px;cursor:pointer;font-size:12px">${t("share_dlg_copy")}</button>
                </div>
            </div>

            <div style="display:flex;gap:8px;justify-content:flex-end">
                <button id="sh-cancel-btn" class="btn" style="background:#e2e8f0;color:#1e293b">${t("cancel")}</button>
                <button id="sh-create-btn" class="btn" style="background:#8b5cf6">${t("share_dlg_create")}</button>
            </div>
        </div>`,document.body.appendChild(o);const p=document.getElementById("sh-expiry-preset"),l=document.getElementById("sh-expiry-custom");p.addEventListener("change",()=>{l.style.display=p.value==="custom"?"block":"none"});function r(){const u=p.value;if(!u)return null;if(u==="custom")return l.value?new Date(l.value+"T23:59:59").toISOString():null;const g=new Date;return g.setDate(g.getDate()+parseInt(u)),g.toISOString()}const s=o.querySelector("#sh-cancel-btn"),a=o.querySelector("#sh-create-btn"),d=o.querySelector("#sh-result"),f=o.querySelector("#sh-link-box"),c=o.querySelector("#sh-copy-btn");s.addEventListener("click",()=>window.fdCloseOverlay(o)),o.addEventListener("click",u=>{u.target===o&&window.fdCloseOverlay(o)});let m=!1;a.addEventListener("click",async()=>{if(m){window.fdCloseOverlay(o);return}if(!o.isConnected)return;if(a.disabled=!0,a.innerHTML='<span style="display:inline-flex;align-items:center;gap:6px"><svg style="animation:spin 0.8s linear infinite;width:14px;height:14px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>'+t("share_dlg_creating")+"</span>",!document.getElementById("fd-spin-style")){const b=document.createElement("style");b.id="fd-spin-style",b.textContent="@keyframes spin{to{transform:rotate(360deg)}}",document.head.appendChild(b)}const u=o.querySelector("#sh-upload-policy")?.value??"none",g={path:e,is_dir:n,require_account:o.querySelector("#sh-require-account")?.checked??!1,track_stats:o.querySelector("#sh-stats")?.checked??!1,allow_anon_upload:n?u==="anon":!1,allow_auth_upload:n?u==="auth":!1,allow_preview:o.querySelector("#sh-allow-preview")?.checked??!1,allow_cdn_embed:n?!1:o.querySelector("#sh-cdn-embed")?.checked??!1,expires_at:r()};try{let k=function(){navigator.clipboard.writeText(E).then(()=>{c.textContent=t("share_dlg_copied"),c.style.background="#15803d",setTimeout(()=>{c.textContent=t("share_dlg_copy"),c.style.background="#16a34a"},2e3)}).catch(()=>{f.select()})};var h=k;const b=await apiCall("/api/v1/shares","POST",g);if(!o.isConnected)return;const E=`${window.location.origin}/share/${b.token}`;d.style.display="block",f.value=E,c.addEventListener("click",k),k(),a.textContent=t("share_dlg_done"),a.style.background="#16a34a",a.disabled=!1,m=!0}catch(b){if(!o.isConnected)return;a.disabled=!1,a.textContent=t("share_dlg_create"),b.message!=="SESSION_EXPIRED"&&showMessage(t("share_dlg_failed"),b.message)}})}async function openShareManager(){const e=document.createElement("div");e.className="modal-overlay",e.id="share-manager-overlay",e.innerHTML=`
        <div class="modal-content" style="max-width:640px;width:95vw;max-height:80vh;display:flex;flex-direction:column;padding:0;overflow:hidden">
            <div style="display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid #e2e8f0;flex-shrink:0">
                <h3 style="font-size:18px;font-weight:700">${t("shares_manager_title")}</h3>
                <button id="sm-close" style="background:none;border:none;font-size:20px;cursor:pointer;color:#64748b">✕</button>
            </div>
            <div id="sm-body" style="overflow-y:auto;padding:16px 20px;flex:1">
                <p style="color:#64748b;font-size:14px">${t("loading")}</p>
            </div>
        </div>`,document.body.appendChild(e),document.getElementById("sm-close").addEventListener("click",()=>window.fdCloseOverlay(e)),e.addEventListener("click",n=>{n.target===e&&window.fdCloseOverlay(e)}),await loadShareManager()}async function loadShareManager(){const e=document.getElementById("sm-body");if(e){e.innerHTML=Array.from({length:3},()=>`
        <div style="border:1px solid #e2e8f0;border-radius:10px;padding:14px;margin-bottom:10px">
            <div style="display:flex;justify-content:space-between;margin-bottom:10px">
                <div>
                    <span style="display:inline-block;width:160px;height:15px;border-radius:4px;
                        background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%);
                        background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></span><br>
                    <span style="display:inline-block;width:100px;height:11px;border-radius:4px;margin-top:6px;
                        background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%);
                        background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></span>
                </div>
                <div style="display:flex;gap:6px">
                    <span style="display:inline-block;width:60px;height:28px;border-radius:6px;
                        background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%);
                        background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></span>
                    <span style="display:inline-block;width:54px;height:28px;border-radius:6px;
                        background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%);
                        background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></span>
                </div>
            </div>
        </div>`).join("");try{const i=(await apiCall("/api/v1/shares","GET")).shares||[];if(i.length===0){e.innerHTML=`<p style="color:#64748b;font-size:14px">${t("shares_manager_empty")}</p>`;return}e.innerHTML=i.map(o=>renderShareRow(o)).join(""),_initTooltipFlip(),e.querySelectorAll(".sm-delete-btn").forEach(o=>{o.addEventListener("click",async()=>{if(await showConfirmModal({title:t("shares_revoke_confirm_title"),message:t("shares_revoke_confirm_body"),danger:!0}))try{await apiCall(`/api/v1/shares/${o.dataset.token}`,"DELETE"),await loadShareManager()}catch(l){showMessage(t("shares_revoke_failed"),l.message)}})}),e.querySelectorAll(".sm-toggle").forEach(o=>{o.addEventListener("change",async()=>{const p=o.dataset.token,l=o.dataset.field;try{await apiCall(`/api/v1/shares/${p}`,"PATCH",{[l]:o.checked})}catch(r){showMessage(t("shares_update_failed"),r.message),o.checked=!o.checked}})}),e.querySelectorAll(".sm-copy-btn").forEach(o=>{o.addEventListener("click",()=>{navigator.clipboard.writeText(o.dataset.url).then(()=>{const p=o.textContent;o.textContent=t("share_dlg_copied"),o.style.background="#16a34a",setTimeout(()=>{o.textContent=p,o.style.background="#3b82f6"},1500)})})}),e.querySelectorAll(".sm-stats-btn").forEach(o=>{o.addEventListener("click",()=>openShareStats(o.dataset.token,o.dataset.name))}),e.querySelectorAll(".sm-expiry-input").forEach(o=>{const p=async()=>{const l=o.dataset.token,r=o.value,s=r?new Date(r+"T23:59:59").toISOString():null;try{await apiCall(`/api/v1/shares/${l}`,"PATCH",{expires_at:s}),await loadShareManager()}catch(a){showMessage(t("update_failed"),a.message)}};o.addEventListener("change",p)}),e.querySelectorAll(".sm-expiry-clear").forEach(o=>{o.addEventListener("click",async()=>{const p=o.dataset.token;try{await apiCall(`/api/v1/shares/${p}`,"PATCH",{expires_at:null}),await loadShareManager()}catch(l){showMessage(t("update_failed"),l.message)}})})}catch(n){e.innerHTML=`<p style="color:#ef4444;font-size:14px">Failed to load shares: ${n.message}</p>`}}}function _initTooltipFlip(){document.querySelectorAll(".fd-tooltip-wrap").forEach(e=>{e.addEventListener("mouseenter",()=>{const n=e.getBoundingClientRect();e.classList.toggle("fd-tooltip-below",n.top<240)})})}function renderShareRow(e){const n=`${window.location.origin}/share/${e.token}`,i=escapeHtmlAttr(n),o=escapeHtmlAttr(e.path.split("/").pop()||e.path),p=escapeHtmlAttr(e.path),l=e.created_at?new Date(e.created_at).toLocaleDateString():"?";let r=`<span style="color:#94a3b8">${t("shares_info_never")}</span>`,s="";if(e.expires_at){const a=new Date(e.expires_at);r=a<new Date?`<span style="color:#ef4444;font-weight:600">${t("shares_expired_label")} ${a.toLocaleDateString()}</span>`:`<span style="color:#f59e0b;font-weight:600">⏰ ${a.toLocaleDateString()}</span>`,s=a.toISOString().slice(0,10)}return`<div style="border:1px solid #e2e8f0;border-radius:10px;padding:14px;margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
            <div>
                <span style="font-weight:600;font-size:14px">${e.is_dir?"📁":"📄"} ${o}</span>
                <span style="font-size:11px;color:#94a3b8;margin-left:8px">${p}</span>
                <div style="font-size:11px;color:#64748b;margin-top:3px">
                    ${t("shares_info_created")} ${l} · ${t("shares_access_count",{n:e.access_count||0})} · ${t("shares_expires_label")} ${r}
                </div>
            </div>
            <div style="display:flex;gap:6px;flex-shrink:0;margin-left:8px">
                ${e.track_stats?`<button class="sm-stats-btn" data-token="${e.token}" data-name="${o}"
                    style="background:#0ea5e9;color:white;border:none;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px">${t("shares_stats_button")}</button>`:""}
                <button class="sm-copy-btn" data-url="${i}"
                    style="background:#3b82f6;color:white;border:none;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px">${t("shares_copy_link_button")}</button>
                <button class="sm-delete-btn" data-token="${e.token}"
                    style="background:#ef4444;color:white;border:none;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px">${t("shares_revoke_button")}</button>
            </div>
        </div>

        <div style="display:flex;gap:12px 20px;flex-wrap:wrap;align-items:center">
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${e.token}" data-field="require_account" ${e.require_account?"checked":""}>
                ${t("shares_info_account_requirement")}
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${e.token}" data-field="track_stats" ${e.track_stats?"checked":""}>
                ${t("shares_info_stats_tracking")}
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${e.token}" data-field="allow_preview" ${e.allow_preview?"checked":""}>
                ${t("shares_info_preview")}
            </label>
            ${e.is_dir?"":`<label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${e.token}" data-field="allow_cdn_embed" ${e.allow_cdn_embed?"checked":""}>
                ${t("shares_info_cdn_embed")}
            </label>`}
            ${e.is_dir?`
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${e.token}" data-field="allow_anon_upload" ${e.allow_anon_upload?"checked":""}>
                ${t("shares_info_uploads_anyone")}
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${e.token}" data-field="allow_auth_upload" ${e.allow_auth_upload?"checked":""}>
                ${t("shares_info_uploads_auth_only")}
            </label>`:""}
            <div style="display:flex;align-items:center;gap:6px;font-size:13px">
                <span style="white-space:nowrap">${t("shares_info_expiry")}</span>
                <input type="date" class="sm-expiry-input" data-token="${e.token}"
                    value="${s}"
                    style="padding:3px 7px;border:1px solid #e2e8f0;border-radius:6px;font-size:12px;color:#1e293b">
                <button class="sm-expiry-clear" data-token="${e.token}"
                    style="background:none;border:1px solid #e2e8f0;border-radius:6px;padding:3px 7px;cursor:pointer;font-size:11px;color:#94a3b8"
                    title="${t("shares_expiry_remove_title")}">✕</button>
            </div>
        </div>
        ${e.allow_cdn_embed&&!e.is_dir?`
        <div style="margin-top:10px;padding:10px;background:#fefce8;border:1px solid #fde047;border-radius:8px">
            <div style="font-size:11px;color:#854d0e;font-weight:600;margin-bottom:5px">
                ${t("shares_cdn_embed_title")}
                <span class="fd-tooltip-wrap" id="cdn-tip-wrap">
                    <span class="fd-tooltip-icon" style="font-family: Playwrite Norge; font-style: italic;">i</span>
                    <div class="fd-tooltip-bubble">${t("shares_cdn_embed_tooltip")}</div>
                </span>
            </div>
            <div style="display:flex;gap:6px">
                <input type="text" readonly value="${i}" style="flex:1;font-size:11px;padding:4px 7px;border:1px solid #fde047;border-radius:5px;background:white;color:#1e293b">
                <button class="sm-copy-btn" data-url="${i}" style="background:#ca8a04;color:white;border:none;border-radius:5px;padding:4px 10px;cursor:pointer;font-size:11px">${t("shares_copy_button")}</button>
            </div>
        </div>`:""}
    </div>`}function _shareActionLabel(e){const n=e||"view",i="share_action_"+n,o=t(i);return o!==i?o:n}async function openShareStats(e,n){try{const o=(await apiCall(`/api/v1/shares/${e}/stats`,"GET")).logs||[],p=`<span style="color:#94a3b8">${t("shares_stats_anonymous")}</span>`,l=o.length===0?`<tr><td colspan="3" style="padding:12px;color:#94a3b8;text-align:center">${t("shares_stats_no_accesses")}</td></tr>`:o.map(r=>`<tr style="border-top:1px solid #f1f5f9">
                <td style="padding:8px 12px;font-size:13px">${r.accessed_at?new Date(r.accessed_at).toLocaleString():"?"}</td>
                <td style="padding:8px 12px;font-size:13px">${r.username||p}</td>
                <td style="padding:8px 12px;font-size:13px">${escapeHtmlAttr(_shareActionLabel(r.action))}</td>
            </tr>`).join("");showMessage(t("shares_stats_title",{name:n}),`<div style="text-align:left;max-height:300px;overflow-y:auto"><table style="width:100%;border-collapse:collapse"><thead><tr style="background:#f8fafc">
                <th style="padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;text-align:left">${t("shares_stats_col_time")}</th>
                <th style="padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;text-align:left">${t("shares_stats_col_user")}</th>
                <th style="padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;text-align:left">${t("shares_stats_col_action")}</th>
            </tr></thead><tbody>${l}</tbody></table></div>`,!0)}catch(i){showMessage(t("stats_error"),i.message)}}function openUploadQueuePanel(e){document.getElementById("upload-queue-panel")?.remove();const n=document.createElement("div");n.id="upload-queue-panel",n.style.cssText=`
        position:fixed;top:0;left:0;width:100%;height:100%;
        background:rgba(0,0,0,0.55);display:flex;align-items:center;
        justify-content:center;z-index:10000;font-family:Inter,sans-serif;
    `;function i(){const p=window._uploadQueue||[],l=p.length===0?`<p style="color:#94a3b8;text-align:center;padding:1.5rem 0">${t("queue_empty")}</p>`:p.map((r,s)=>`
                <div style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #334155"
                     data-qi="${s}">
                    <span style="font-size:18px">📄</span>
                    <div style="flex:1;min-width:0">
                        <div style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"
                             title="${escapeHtmlAttr(r.file.name)}">${escapeHtml(r.file.name)}</div>
                        <div style="font-size:11px;color:#94a3b8">
                            ${formatBytes(r.file.size)} · ${escapeHtml(r.destRel)}
                        </div>
                    </div>
                    <button class="qp-remove" data-qi="${s}"
                        style="background:#ef4444;color:white;border:none;border-radius:6px;
                               padding:4px 10px;cursor:pointer;font-size:12px;flex-shrink:0">
                        Remove
                    </button>
                </div>`).join("");return`
        <div style="background:#0f172a;border-radius:14px;padding:1.5rem;
                    width:95vw;max-width:560px;max-height:80vh;overflow-y:auto;
                    color:#e2e8f0;position:relative">
            <div style="display:flex;justify-content:space-between;align-items:center;
                        margin-bottom:1rem;border-bottom:1px solid #334155;padding-bottom:.75rem">
                <span style="font-weight:700;font-size:16px">📋 Upload Queue (${p.length} pending)</span>
                <button id="qp-close" style="background:rgba(255,255,255,0.1);border:none;color:white;
                    border-radius:50%;width:28px;height:28px;cursor:pointer;font-size:16px;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <div id="qp-list">${l}</div>
            ${p.length>0?`<div style="margin-top:1rem;text-align:right">
                <button id="qp-clear-all"
                    style="background:#64748b;color:white;border:none;border-radius:7px;
                           padding:6px 14px;cursor:pointer;font-size:12px">Clear all</button>
            </div>`:""}
        </div>`}function o(){n.innerHTML=i(),n.querySelector("#qp-close").addEventListener("click",()=>{n.remove(),e&&e()}),n.querySelector("#qp-clear-all")?.addEventListener("click",()=>{window._uploadQueue=[],o(),e&&e()}),n.querySelectorAll(".qp-remove").forEach(p=>{p.addEventListener("click",()=>{const l=+p.dataset.qi;window._uploadQueue.splice(l,1),o(),e&&e()})}),n.addEventListener("click",p=>{p.target===n&&(n.remove(),e&&e())})}document.body.appendChild(n),o()}function openInterruptedManager(e){document.getElementById("interrupted-manager-panel")?.remove();const n=document.createElement("div");n.id="interrupted-manager-panel",n.className="modal-overlay",n.style.cssText=`
        position:fixed;top:0;left:0;width:100%;height:100%;
        background:rgba(0,0,0,0.55);display:flex;align-items:center;
        justify-content:center;z-index:10000;font-family:Inter,sans-serif;
    `;function i(r){const s=r.length===0?`<p style="color:#94a3b8;text-align:center;padding:1.5rem 0">${t("im_empty")}</p>`:r.map((a,d)=>{const f=a.total>0?Math.min(100,Math.round((a.nextChunkIdx||0)*(a.chunkSize||1)/a.total*100)):0;return`
                <div style="padding:12px 0;border-bottom:1px solid #334155" data-im="${d}">
                    <div style="display:flex;align-items:flex-start;gap:10px">
                        <span style="font-size:22px;margin-top:2px">📄</span>
                        <div style="flex:1;min-width:0">
                            <div style="font-weight:600;white-space:nowrap;overflow:hidden;
                                        text-overflow:ellipsis;margin-bottom:2px"
                                 title="${escapeHtmlAttr(a.filename)}" data-fd-notranslate>${escapeHtml(a.filename)}</div>
                            <div style="font-size:11px;color:#94a3b8;margin-bottom:6px" data-fd-notranslate>
                                ${formatBytes(a.total)} · ${escapeHtml(a.destRel)}
                            </div>
                            <div style="background:#1e293b;border-radius:4px;height:6px;margin-bottom:4px">
                                <div style="background:#22c55e;height:6px;border-radius:4px;width:${f}%"></div>
                            </div>
                            <div style="font-size:11px;color:#64748b">${t("im_progress",{pct:f})}</div>
                        </div>
                        <div style="display:flex;flex-direction:column;gap:5px;flex-shrink:0">
                            <button class="im-resume" data-im="${d}"
                                style="background:#22c55e;color:white;border:none;border-radius:6px;
                                       padding:5px 12px;cursor:pointer;font-size:12px;font-weight:600">
                                ▶ ${t("im_resume")}
                            </button>
                            <button class="im-discard" data-im="${d}"
                                style="background:#ef4444;color:white;border:none;border-radius:6px;
                                       padding:5px 12px;cursor:pointer;font-size:12px">
                                🗑 ${t("im_discard")}
                            </button>
                        </div>
                    </div>
                </div>`}).join("");return`
        <div class="fd-modal-panel-in" style="background:#0f172a;border-radius:14px;padding:1.5rem;
                    width:95vw;max-width:600px;max-height:82vh;overflow-y:auto;
                    color:#e2e8f0;position:relative">
            <div style="display:flex;justify-content:space-between;align-items:center;
                        margin-bottom:1rem;border-bottom:1px solid #334155;padding-bottom:.75rem">
                <span style="font-weight:700;font-size:16px">⟳ ${t("im_title",{n:r.length})}</span>
                <button id="im-close" style="background:rgba(255,255,255,0.1);border:none;color:white;
                    border-radius:50%;width:28px;height:28px;cursor:pointer;font-size:16px;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <p style="font-size:12px;color:#64748b;margin-bottom:12px">
                ${t("im_hint",{resume:`<strong style="color:#22c55e">${t("im_resume")}</strong>`})}
            </p>
            <div id="im-list">${s}</div>
            ${r.length>1?`<div style="margin-top:1rem;text-align:right">
                <button id="im-discard-all"
                    style="background:#64748b;color:white;border:none;border-radius:7px;
                           padding:6px 14px;cursor:pointer;font-size:12px">${t("im_discard_all")}</button>
            </div>`:""}
        </div>`}async function o(r){let s=r.nextChunkIdx||0;try{const d=await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${r.uploadToken}/status`,{method:"GET",headers:authToken?{Authorization:`Bearer ${authToken}`}:{}});if(d.ok){const f=await d.json();if(f.missing_chunks&&f.missing_chunks.length>0)s=f.missing_chunks[0];else if(!f.missing_chunks||f.missing_chunks.length===0){await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${r.uploadToken}/complete`,{method:"POST",headers:authToken?{Authorization:`Bearer ${authToken}`}:{}}),removeInterruptedUpload(r.uploadToken),e&&e(),n.remove(),loadDirectory(currentPath);return}}else{removeInterruptedUpload(r.uploadToken),e&&e(),l(getAllInterruptedUploads()),showMessage(t("im_expired_title"),t("im_expired_body",{name:r.filename}));return}}catch{}const a=document.createElement("input");a.type="file",a.style.display="none",document.body.appendChild(a),a.click(),a.addEventListener("change",async()=>{if(document.body.removeChild(a),!a.files.length)return;const d=a.files[0];if(d.name!==r.filename||d.size!==r.total){showMessage(t("im_mismatch_title"),t("im_mismatch_body",{expected:r.filename,expected_size:formatBytes(r.total),got:d.name,got_size:formatBytes(d.size)}));return}n.remove(),uploadChunked(d,r.destRel,{ownerType:r.ownerType,shareToken:r.shareToken||"",resumeToken:r.uploadToken,resumeFromChunk:s,resumeChunkSize:r.chunkSize,resumeAnonToken:r.anonDeviceToken}).then(()=>{loadDirectory(currentPath),e&&e()}).catch(f=>{f.name!=="PauseSignal"&&f.message!=="Upload cancelled"&&showMessage(t("im_resume_failed"),f.message),e&&e()})})}function p(){_detachModalKeys(),window.fdCloseOverlay(n),e&&e()}function l(r){n.innerHTML=i(r),n.querySelector("#im-close").addEventListener("click",p),n.addEventListener("click",s=>{s.target===n&&p()}),_attachModalKeys(null,p),n.querySelector("#im-discard-all")?.addEventListener("click",()=>{getAllInterruptedUploads().forEach(s=>removeInterruptedUpload(s.uploadToken)),l(getAllInterruptedUploads()),e&&e()}),n.querySelectorAll(".im-resume").forEach(s=>{s.addEventListener("click",async()=>{const d=getAllInterruptedUploads()[+s.dataset.im];d&&await o(d)})}),n.querySelectorAll(".im-discard").forEach(s=>{s.addEventListener("click",()=>{const d=getAllInterruptedUploads()[+s.dataset.im];d&&(removeInterruptedUpload(d.uploadToken),fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${d.uploadToken}/cancel`,{method:"DELETE",headers:authToken?{Authorization:`Bearer ${authToken}`}:{}}).catch(()=>{}),l(getAllInterruptedUploads()),e&&e())})})}document.body.appendChild(n),l(getAllInterruptedUploads())}document.addEventListener("DOMContentLoaded",()=>{if("serviceWorker"in navigator){const d=()=>navigator.serviceWorker.register(_APP_BASE+"/sw.js",{scope:_APP_BASE+"/"}).catch(f=>{console.warn("[FluxDrop] SW registration failed:",f)});document.readyState==="complete"?d():window.addEventListener("load",d,{once:!0})}let e=null,n=!1;function i(){if(document.getElementById("offline-banner"))return;const d=document.createElement("div");d.id="offline-banner",d.style.cssText=["position:fixed;top:0;left:0;width:100%;z-index:99999","background:#1e293b;color:#e2e8f0","display:flex;align-items:center;justify-content:center;gap:10px","padding:10px 16px;font-family:Inter,sans-serif;font-size:14px","font-weight:500;box-shadow:0 2px 8px rgba(0,0,0,0.3)","transform:translateY(-100%);transition:transform 0.3s ease"].join(";"),d.innerHTML=`
            <span style="font-size:18px">📡</span>
            <span id="offline-banner-text">Seems like you're offline. Please connect to the internet to access FluxDrop.</span>
        `,document.body.prepend(d),requestAnimationFrame(()=>requestAnimationFrame(()=>{d.style.transform="translateY(0)"}))}function o(){const d=document.getElementById("offline-banner");d&&(d.style.transform="translateY(-100%)",setTimeout(()=>d.remove(),320))}async function p(){try{const d=await fetch(`${API_BASE_URL}/api/v1/upload_session/config`,{method:"HEAD",cache:"no-store",signal:AbortSignal.timeout(4e3)});return d.ok||d.status<500}catch{return!1}}function l(){e||(e=setInterval(async()=>{if(await p())n=!1,o(),clearInterval(e),e=null;else{const f=document.getElementById("offline-banner-text");f&&(f.textContent="You're offline — retrying connection…")}},5e3))}function r(){n||(n=!0,i(),l())}function s(){p().then(d=>{d&&(n=!1,o(),clearInterval(e),e=null)})}window.addEventListener("offline",r),window.addEventListener("online",s),navigator.onLine||r(),document.addEventListener("keydown",d=>{if(d.key==="Escape"){if(!document.getElementById("preview-modal").classList.contains("hidden"))closePreview();else if(document.getElementById("mv-dialog-overlay"))window.fdCloseOverlay(document.getElementById("mv-dialog-overlay"));else if(document.getElementById("share-dialog-overlay"))window.fdCloseOverlay(document.getElementById("share-dialog-overlay"));else if(document.getElementById("ap-edit-overlay"))window.fdCloseOverlay(document.getElementById("ap-edit-overlay"));else if(document.getElementById("admin-panel-overlay"))window.fdCloseOverlay(document.getElementById("admin-panel-overlay"));else if(document.getElementById("profile-panel-overlay"))window.fdCloseOverlay(document.getElementById("profile-panel-overlay"));else if(document.getElementById("share-manager-overlay"))window.fdCloseOverlay(document.getElementById("share-manager-overlay"));else if(document.getElementById("profile-menu-modal"))window.fdCloseOverlay(document.getElementById("profile-menu-modal"));else if(!document.getElementById("message-modal").classList.contains("hidden"))hideModal("message-modal");else if(document.getElementById("fd-ctx-menu"))_dismissContextMenu();else if(_selectedPaths.size>0&&!document.getElementById("trash-overlay")){const f=document.activeElement;if(f&&(f.tagName==="INPUT"&&f.type!=="checkbox"||f.tagName==="TEXTAREA"||f.isContentEditable))return;_clearSelection(),_updateSelBar()}}}),document.addEventListener("keydown",d=>{if(d.key!=="Delete")return;const f=document.activeElement;f&&(f.tagName==="INPUT"||f.tagName==="TEXTAREA"||f.isContentEditable)||document.getElementById("preview-modal").classList.contains("hidden")&&(document.getElementById("mv-dialog-overlay")||document.getElementById("share-dialog-overlay")||document.getElementById("ap-edit-overlay")||document.getElementById("admin-panel-overlay")||document.getElementById("profile-panel-overlay")||document.getElementById("share-manager-overlay")||document.getElementById("profile-menu-modal")||document.getElementById("trash-overlay")||_selectedPaths.size!==0&&(d.preventDefault(),_trashSelectedPaths([..._selectedPaths])))}),new URLSearchParams(window.location.search).has("verified")&&(showMessage(t("verify_success_title"),t("verify_success_msg")),window.history.replaceState({},document.title,window.location.pathname)),renderApp(),setTimeout(async()=>{if(!("serviceWorker"in navigator)||!navigator.serviceWorker.controller)return;try{if(sessionStorage.getItem("fd_just_updated")==="1"){sessionStorage.removeItem("fd_just_updated");return}}catch{}if(!SCRIPT_VERSION_RAW.includes("@@"))try{if(await new Promise((c,m)=>{const u=new MessageChannel;u.port1.onmessage=g=>g.data?.version?c(g.data.version):m(),navigator.serviceWorker.controller.postMessage({type:"GET_VERSION"},[u.port2]),setTimeout(()=>m(new Error("sw-timeout")),3e3)})===SCRIPT_VERSION)return}catch{}const d=[_APP_BASE+"/index.html",_APP_BASE+"/script.js"];try{const f=await caches.open("fluxdrop-v-0f320bd3");(await Promise.all(d.map(async m=>{try{const u=await fetch(m,{method:"HEAD",cache:"no-store",signal:AbortSignal.timeout(8e3)});if(!u.ok)return!1;const g=await f.match(m,{ignoreMethod:!0});if(!g)return!0;const h=u.headers.get("ETag"),b=g.headers.get("ETag");if(h&&b)return h!==b;const E=u.headers.get("Last-Modified"),k=g.headers.get("Last-Modified");if(E&&k)return E!==k;const w=u.headers.get("Content-Length"),y=g.headers.get("Content-Length");return!!(w&&y&&w!==y)}catch{return!1}}))).some(m=>m)&&_showUpdateBanner()}catch{}},2e3)});function initFooter(){const e=document.createElement("footer");if(e.id="fluxdrop-footer",Object.assign(e.style,{width:"100%",maxWidth:"64rem",marginTop:"auto",paddingTop:"0.75rem",paddingBottom:"0.5rem",color:"#a0aec0",fontSize:"11px",fontFamily:"sans-serif",fontWeight:"300",textAlign:"right",lineHeight:"1.5"}),!document.getElementById("fd-retry-pulse-style")){const l=document.createElement("style");l.id="fd-retry-pulse-style",l.textContent="@keyframes fd-retry-pulse{0%,100%{opacity:1}50%{opacity:.45}}",document.head.appendChild(l)}const n=(l,r)=>`
        <div>FluxDrop Preview Program | <a href="https://github.com/ArsenijN/server/" style="color: #a0a0a0; text-decoration: underline;">GitHub repo</a></div>
        <div>&copy; 2025-2026 by Arsenii Nochevnyi.</div>
        <div><button onclick="showPolicyModal('tos')" style="background:none; border:none; color:#a0a0a0; cursor:pointer; text-decoration:underline; padding:0; font:inherit;">TOS</button> | <button onclick="showPolicyModal('pp')" style="background:none; border:none; color:#a0a0a0; cursor:pointer; text-decoration:underline; padding:0; font:inherit;">Privacy Policy</button></div>
        <div style="opacity:.7">Script v.${SCRIPT_VERSION} · SW v.${l} · Server v.${r||"?"}</div>
    `;let i="...",o="...";const p=()=>{e.innerHTML=n(i,o)};if(e.innerHTML=n(i,o),document.body.appendChild(e),navigator.serviceWorker&&navigator.serviceWorker.controller){const l=new MessageChannel;l.port1.onmessage=r=>{r.data&&r.data.version&&(i=r.data.version,p())},navigator.serviceWorker.controller.postMessage({type:"GET_VERSION"},[l.port2])}else i="N/A",p();fetch(API_BASE_URL+"/api/v1/status.json",{cache:"no-store"}).then(l=>l.ok?l.json():null).then(l=>{l&&l.server_version&&(o=l.server_version,p())}).catch(()=>{o="?",p()})}document.addEventListener("DOMContentLoaded",initFooter);const _NOTICE_SEEN_KEY="fluxdrop_notice_seen",_NOTICE_ACCENT={info:"#38bdf8",ok:"#4ade80",warning:"#fbbf24",critical:"#f87171"};function _noticeSeen(e){try{return localStorage.getItem(_NOTICE_SEEN_KEY)===String(e)}catch{return!1}}function _markNoticeSeen(e){try{localStorage.setItem(_NOTICE_SEEN_KEY,String(e))}catch{}}function _noticeLang(){try{return(localStorage.getItem("fluxdrop_lang")||"en").toLowerCase()}catch{return"en"}}function _noticeText(e){const n=e.i18n||{},i=_noticeLang(),o=n[i]||n[i.split("-")[0]]||{};return{title:o.title||e.title||"",body:o.body||e.body||""}}let _activeNotice=null;function _renderNotice(e){const n=_noticeText(e);document.getElementById("notice-modal-accent").style.background=_NOTICE_ACCENT[e.level]||_NOTICE_ACCENT.info,document.getElementById("notice-modal-title").textContent=n.title;const i=document.getElementById("notice-modal-body");i.textContent=n.body,i.style.display=n.body?"":"none";const o=document.getElementById("notice-modal-meta");if(e.expires_at){const l=new Date(e.expires_at.replace(" ","T")+"Z");o.textContent=isNaN(l)?"":l.toLocaleString()}else o.textContent="";o.style.display=o.textContent?"":"none";const p=document.getElementById("notice-modal-ok");p.textContent=window.t?t("ok"):"OK"}document.addEventListener("fd-locale-change",()=>{_activeNotice&&!document.getElementById("notice-modal")?.classList.contains("hidden")&&_renderNotice(_activeNotice)});async function checkSiteNotice(){let e=null;try{const o=await fetch(`${API_BASE_URL}/api/v1/notice`,{cache:"no-store"});if(!o.ok)return;e=(await o.json()).notice}catch{return}if(!e||!(e.level==="critical")&&_noticeSeen(e.id))return;_activeNotice=e,_renderNotice(e);const i=()=>{_activeNotice=null,_markNoticeSeen(e.id),hideModal("notice-modal")};document.getElementById("notice-modal-ok").onclick=i,showModal("notice-modal"),_attachModalKeys(i,i)}document.addEventListener("DOMContentLoaded",checkSiteNotice);
//# sourceMappingURL=script.js.map
