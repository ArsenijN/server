const API_HTTPS=`https://${window.location.hostname}`,API_HTTP=`http://${window.location.hostname}`,SCRIPT_VERSION_RAW="v-d538d268",SCRIPT_VERSION=SCRIPT_VERSION_RAW.replace(/^(?:fluxdrop-)?(?:v-)?/,"");let API_BASE_URL=window.location.protocol==="https:"?API_HTTPS:API_HTTP;function encodePath(e){return e==="/"?"/":e.split("/").map(encodeURIComponent).join("/")}function escapeHtmlAttr(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;")}function safeJs(e){return JSON.stringify(e).replace(/'/g,"\\'")}async function fetchWithFallback(e,n){let o=null;n&&n.body instanceof ArrayBuffer&&(o=n.body.slice(0));try{return await fetch(e,n)}catch(i){if(console.warn("Fetch failed:",i),window.location.protocol==="http:")try{API_BASE_URL=API_HTTP;const c=e.replace(API_HTTPS,API_HTTP),l=o?{...n,body:o}:n;return await fetch(c,l)}catch(c){throw c}throw i}}"serviceWorker"in navigator&&navigator.serviceWorker.addEventListener("message",e=>{e.data&&e.data.type==="SW_UPDATED"&&_showUpdateBanner()});function _showUpdateBanner(){if(document.getElementById("fd-update-banner"))return;const e=document.createElement("div");e.id="fd-update-banner",e.setAttribute("role","status"),e.style.cssText=["position:fixed","bottom:1rem","left:50%","transform:translateX(-50%)","background:#1e40af","color:#fff","padding:0.6rem 1.2rem","border-radius:0.75rem","font-size:0.9rem","z-index:99999","display:flex","align-items:center","gap:0.75rem","box-shadow:0 4px 12px rgba(0,0,0,0.25)"].join(";"),e.innerHTML=`
        <span>🔄 A new version of FluxDrop is available.</span>
        <button onclick="_fdHardReload()" style="
            background:#fff;color:#1e40af;border:none;border-radius:0.5rem;
            padding:0.3rem 0.8rem;font-weight:600;cursor:pointer;">
            Reload
        </button>
        <button onclick="this.parentElement.remove()" style="
            background:none;border:none;color:#fff;cursor:pointer;font-size:1.1rem;">
            ✕
        </button>`,document.body.appendChild(e)}async function _fdHardReload(){try{"serviceWorker"in navigator&&navigator.serviceWorker.controller&&await new Promise(e=>{const n=new MessageChannel;n.port1.onmessage=e,navigator.serviceWorker.controller.postMessage({type:"SKIP_AND_CLEAR"},[n.port2]),setTimeout(e,5e3)})}catch{}try{sessionStorage.setItem("fd_just_updated","1")}catch{}location.reload()}const appRoot=document.getElementById("app-root"),authControls=document.getElementById("auth-controls");(function(){if(!appRoot||!document.getElementById("fd-boot-loading"))return;const n=new MutationObserver(()=>{const o=document.getElementById("fd-boot-loading");if(!o){n.disconnect();return}for(const i of appRoot.children)if(i!==o){o.remove(),n.disconnect();return}});n.observe(appRoot,{childList:!0})})();let authToken=localStorage.getItem("fluxdrop_token"),currentUsername=localStorage.getItem("fluxdrop_username"),isAdmin=localStorage.getItem("fluxdrop_is_admin")==="1",_canPublish=null;function _syncLangToServer(){const e=window.FDi18n&&window.FDi18n.lang;!e||!authToken||localStorage.getItem("fluxdrop_lang_synced")!==e&&apiCall("/api/v1/me","PATCH",{lang:e}).then(()=>localStorage.setItem("fluxdrop_lang_synced",e)).catch(()=>{})}document.addEventListener("fd-locale-change",_syncLangToServer),window.addEventListener("load",()=>setTimeout(_syncLangToServer,3e3));let currentPath="/",_lastKnownRetentionDays=30,_lastUploadBatchCount=0,_pausedQueueDrain=null,_mobileUploadPending=!1;const _APP_BASE=(()=>{let e=window.location.pathname.replace(/\/index\.html$/,"").replace(/\/files(\/.*)?$/,"");return e.endsWith("/")?e.slice(0,-1):e})();function navigateTo(e){if(e===currentPath)return;window._fdKeepSelectionOnNav||(_selectedPaths.clear(),_lastClickedPath=null,_updateSelBar()),currentPath=e;const n=_APP_BASE+"/files"+(e==="/"?"":encodePath(e));history.pushState({fdPath:e},"",n),loadDirectory(e)}function _resetBrowsePath(){currentPath="/",_selectedPaths.clear(),_lastClickedPath=null,location.pathname.startsWith(_APP_BASE+"/files/")&&history.replaceState({fdPath:"/"},"",_APP_BASE+"/files")}function _syncUrlToPath(e){const n=_APP_BASE+"/files"+(e==="/"?"":encodePath(e));history.replaceState({fdPath:e},"",n)}window.addEventListener("popstate",e=>{const n=e.state&&e.state.fdPath?e.state.fdPath:"/";n!==currentPath&&!window._fdKeepSelectionOnNav&&(_selectedPaths.clear(),_lastClickedPath=null,_updateSelBar()),currentPath=n,loadDirectory(n)});let currentSort=(()=>{try{return JSON.parse(localStorage.getItem("fluxdrop_sort"))||{key:"name",dir:"asc"}}catch{return{key:"name",dir:"asc"}}})(),sortFoldersMixed=(()=>{try{return JSON.parse(localStorage.getItem("fluxdrop_sort_mixed"))||!1}catch{return!1}})();function withMinDelay(e,n=1e3){const o=Date.now();return e.then(i=>{const c=Date.now()-o,l=Math.max(0,n-c);return l===0?i:new Promise(r=>setTimeout(()=>r(i),l))},i=>{const c=Date.now()-o,l=Math.max(0,n-c);if(l===0)throw i;return new Promise((r,s)=>setTimeout(()=>s(i),l))})}function _loadingHtml(e="24px"){if(!document.getElementById("fd-spin-style")){const n=document.createElement("style");n.id="fd-spin-style",n.textContent="@keyframes fd-spin{to{transform:rotate(360deg)}}",document.head.appendChild(n)}return`<div style="display:flex;align-items:center;justify-content:center;gap:10px;padding:${e};color:#94a3b8;font-size:14px"><span style="width:18px;height:18px;border:2px solid #cbd5e1;border-top-color:#3b82f6;border-radius:50%;animation:fd-spin .7s linear infinite;flex-shrink:0"></span>${escapeHtml(t("loading"))}</div>`}function showSpinnerOverlay(e="Loading…",n={}){const o=n.minMs!=null?n.minMs:1e3,i=n.id||"fd-spinner-"+Date.now(),c=document.createElement("div");if(c.id=i,c.setAttribute("role","status"),c.style.cssText=["position:fixed;top:0;left:0;width:100%;height:100%;z-index:10400","background:rgba(15,23,42,.55);display:flex;align-items:center;justify-content:center","animation:fd-fade-in .15s ease"].join(";"),c.innerHTML='<div class="fd-modal-panel-in" style="background:#1e293b;border-radius:1rem;padding:2rem 2.5rem;display:flex;flex-direction:column;align-items:center;gap:1rem;box-shadow:0 16px 48px rgba(0,0,0,.5);min-width:180px;text-align:center"><div style="width:44px;height:44px;border-radius:50%;border:4px solid #334155;border-top-color:#3b82f6;animation:fd-spin .7s linear infinite"></div><div style="color:#e2e8f0;font-size:.93rem;font-weight:500">'+escapeHtml(e)+"</div></div>",!document.getElementById("fd-spin-style")){const r=document.createElement("style");r.id="fd-spin-style",r.textContent="@keyframes fd-spin{to{transform:rotate(360deg)}}",document.head.appendChild(r)}document.body.appendChild(c);const l=Date.now();return function(){const s=Math.max(0,o-(Date.now()-l)),a=function(){const d=document.getElementById(i);d&&window.fdCloseOverlay(d)};s<=0?a():setTimeout(a,s)}}function showModal(e){const n=document.getElementById(e);n.classList.remove("hidden","fd-overlay-closing"),delete n.dataset.fdClosing;const o=n.querySelector(".modal-content");o&&o.classList.remove("fd-panel-closing")}function hideModal(e){const n=document.getElementById(e);if(!n||n.classList.contains("hidden")||n.dataset.fdClosing){_detachModalKeys();return}_detachModalKeys(),n.dataset.fdClosing="1",n.classList.add("fd-overlay-closing");const o=n.querySelector(".modal-content");o&&o.classList.add("fd-panel-closing");let i=!1;const c=()=>{i||(i=!0,n.classList.remove("fd-overlay-closing"),o&&o.classList.remove("fd-panel-closing"),delete n.dataset.fdClosing,n.classList.add("hidden"))};n.addEventListener("animationend",c,{once:!0}),setTimeout(c,200)}let _modalKeyHandler=null;function _attachModalKeys(e,n){_detachModalKeys(),_modalKeyHandler=o=>{o.key==="Enter"?(o.preventDefault(),o.stopPropagation(),_detachModalKeys(),e&&e()):o.key==="Escape"&&(o.preventDefault(),o.stopPropagation(),_detachModalKeys(),n&&n())},document.addEventListener("keydown",_modalKeyHandler,!0)}function _detachModalKeys(){_modalKeyHandler&&(document.removeEventListener("keydown",_modalKeyHandler,!0),_modalKeyHandler=null)}function stripInternalPrefix(e){return e.replace(/^\/FluxDrop\/\d+\//,"/")}const _AVATAR_VERSION_KEY="fd-avatar-v";function _avatarUrl(e){const n=e||localStorage.getItem("fluxdrop_user_id")||"0",o=localStorage.getItem(_AVATAR_VERSION_KEY)||"0";return`${API_BASE_URL}/api/v1/avatar/${encodeURIComponent(n)}?v=${o}`}function _bumpAvatarVersion(){localStorage.setItem(_AVATAR_VERSION_KEY,String(Date.now()))}function escapeHtml(e){return String(e).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}function showMessage(e,n,o=!1){document.getElementById("message-modal-title").textContent=e;const i=document.getElementById("message-modal-content");o?i.innerHTML=n:i.textContent=n,showModal("message-modal"),_attachModalKeys(()=>hideModal("message-modal"),()=>hideModal("message-modal"))}function _getToastStack(){let e=document.getElementById("fd-toast-stack");return e||(e=document.createElement("div"),e.id="fd-toast-stack",e.setAttribute("role","status"),e.className="fd-toast-stack",document.body.appendChild(e)),e}function showToast(e,n={}){const{type:o="success",duration:i=3200,sticky:c=!1,actions:l=[]}=n,r=_getToastStack(),s=document.createElement("div");s.className=`fd-toast fd-toast-${o} fd-tray-in`;const a=o==="progress"?'<span class="fd-toast-spinner"></span>':`<span class="fd-toast-icon">${o==="error"?"⚠":o==="info"?"ℹ":"✓"}</span>`,d=l.length?`<span class="fd-toast-actions">${l.map((f,m)=>`<button type="button" class="fd-toast-action" data-fd-action-idx="${m}">${f.label}</button>`).join("")}</span>`:"";s.innerHTML=`${a}<span class="fd-toast-msg"></span>${d}`,s.querySelector(".fd-toast-msg").textContent=e,r.appendChild(s);let u=!1;const p=()=>{u||!s.isConnected||(u=!0,s.classList.remove("fd-tray-in"),s.classList.add("fd-tray-closing"),s.addEventListener("animationend",()=>s.remove(),{once:!0}))};return l.forEach((f,m)=>{const y=s.querySelector(`[data-fd-action-idx="${m}"]`);y&&y.addEventListener("click",b=>{b.stopPropagation(),f.onClick(p)})}),s.addEventListener("click",p),c||setTimeout(p,i),{dismiss:p,setMessage(f){const m=s.querySelector(".fd-toast-msg");m&&(m.textContent=f)}}}function showPromptModal({title:e,label:n="",placeholder:o="",defaultValue:i="",confirmLabel:c=t("ok"),cancelLabel:l=t("cancel")}={}){return new Promise(r=>{const s=document.createElement("div");s.className="modal-overlay",s.innerHTML=`
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
        `,s.querySelector("h3").textContent=e||"",n&&(s.querySelector("label").textContent=n);const a=s.querySelector("#fd-prompt-input");a.setAttribute("aria-label",n||e||""),a.value=i,a.placeholder=o,s.querySelector("#fd-prompt-cancel").textContent=l,s.querySelector("#fd-prompt-ok").textContent=c,document.body.appendChild(s);let d=!1;function u(p){d||(d=!0,_detachModalKeys(),window.fdCloseOverlay(s),r(p))}s.querySelector("#fd-prompt-ok").addEventListener("click",()=>u(a.value.trim()||null)),s.querySelector("#fd-prompt-cancel").addEventListener("click",()=>u(null)),s.addEventListener("click",p=>{p.target===s&&u(null)}),_attachModalKeys(()=>u(a.value.trim()||null),()=>u(null)),a.focus(),a.select()})}function showConfirmModal({title:e,message:n="",confirmLabel:o=t("yes"),cancelLabel:i=t("no"),danger:c=!0}={}){return new Promise(l=>{const r=document.createElement("div");r.className="modal-overlay",r.innerHTML=`
            <div class="modal-content text-center" style="max-width:380px">
                <h3 style="font-size:1.15rem;font-weight:700;margin-bottom:.6rem;color:#1e293b"></h3>
                <p style="color:#64748b;font-size:13.5px;line-height:1.55;margin-bottom:1.25rem;white-space:pre-line"></p>
                <div style="display:flex;gap:8px;justify-content:center">
                    <button id="fd-confirm-no" class="btn" style="background:#6b7280"></button>
                    <button id="fd-confirm-yes" class="btn"></button>
                </div>
            </div>
        `,r.querySelector("h3").textContent=e||"",r.querySelector("p").textContent=n;const s=r.querySelector("#fd-confirm-no"),a=r.querySelector("#fd-confirm-yes");s.textContent=i,a.textContent=o,c&&(a.style.background="#dc2626"),document.body.appendChild(r);let d=!1;function u(p){d||(d=!0,_detachModalKeys(),window.fdCloseOverlay(r),l(p))}a.addEventListener("click",()=>u(!0)),s.addEventListener("click",()=>u(!1)),r.addEventListener("click",p=>{p.target===r&&u(!1)}),_attachModalKeys(()=>u(!0),()=>u(!1)),a.focus()})}function _startCopyJobTracking(e,n){const i=Math.ceil(2400);let c=0,l=!1,r=!1;const s=showToast(t("copy_progress",{name:n}),{type:"progress",sticky:!0,actions:[{label:t("cancel"),onClick:async()=>{if(!r){r=!0,s.setMessage(t("copy_cancelling",{name:n}));try{await apiCall(`/api/v1/copy/cancel/${e}`,"POST")}catch(d){logging_warn("copy cancel request failed",d)}}}},{label:t("toast_hide"),onClick:d=>{l=!0,d()}}]}),a=async()=>{if(!l){c++;try{const d=await apiCall(`/api/v1/copy/status/${e}`,"GET");if(d.status==="done"){s.dismiss(),showToast(t("copy_done",{name:n})),loadDirectory(currentPath);return}if(d.status==="cancelled"){s.dismiss(),showToast(`Copy of "${n}" cancelled`,{type:"info"});return}if(d.status==="error"){s.dismiss(),showToast(`Copy of "${n}" failed: ${d.error_msg||"unknown error"}`,{type:"error",duration:6e3});return}}catch(d){logging_warn("copy job poll failed, retrying",d)}l||(c<i?setTimeout(a,1500):(s.dismiss(),showToast(`Copy of "${n}" is taking unusually long — check manually`,{type:"info",duration:6e3})))}};setTimeout(a,1500)}async function apiCall(e,n="GET",o=null,i=!0){const c=new Headers({"Content-Type":"application/json"});if(i){if(!authToken)throw new Error("Authentication token not found.");c.set("Authorization",`Bearer ${authToken}`)}const l={method:n,headers:c};o&&(l.body=JSON.stringify(o));try{const r=await fetchWithFallback(`${API_BASE_URL}${e}`,l),s=await r.json();if(!r.ok){if(r.status===401&&i)throw authToken=null,currentUsername=null,localStorage.removeItem("fluxdrop_token"),localStorage.removeItem("fluxdrop_username"),localStorage.removeItem("fluxdrop_user_id"),renderApp("login"),showMessage(t("session_expired"),t("session_expired_msg")),new Error("SESSION_EXPIRED");const a=new Error(s.error||`HTTP error! status: ${r.status}`);throw a.code=s.code,a}return s}catch(r){throw r.message!=="SESSION_EXPIRED"&&console.error("API Call Error:",r),r}}function getTrayDismissDelay(){const e=parseInt(localStorage.getItem("fluxdrop_tray_dismiss_ms")||"0",10);return isNaN(e)?0:e}function _requestNotificationPermission(){"Notification"in window&&Notification.permission==="default"&&Notification.requestPermission()}function _notifyUploadDone(e,n=0){if(_conflictBatchChoice=null,!("Notification"in window)||Notification.permission!=="granted"||document.hasFocus())return;let o,i;n>0&&e===0?(o="FluxDrop — "+t("upload_failed"),i=t("notify_upload_all_failed",{n})):n>0?(o="FluxDrop — "+t("notify_upload_partial_title"),i=t("notify_upload_partial",{ok:e,failed:n})):(o="FluxDrop — "+t("notify_upload_done_title"),i=t("notify_upload_done",{n:e})),new Notification(o,{body:i,icon:"/fluxdrop_pp/icon-128.png",tag:"fluxdrop-upload-done"})}function renderAuthControls(){authToken?(authControls.innerHTML=`
            <div class="flex items-center gap-2" style="min-width:0">
                <span class="font-medium text-blue-900 fd-welcome-text"
                      style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
                             max-width:min(220px,40vw);font-size:14px"
                      title="${escapeHtmlAttr(currentUsername)}">
                    ${t("welcome_text")} ${escapeHtml(currentUsername)}!
                </span>
                <button id="profile-btn" title="Profile & Settings"
                    style="width:36px;height:36px;border-radius:50%;background:#2563eb;border:2px solid #93c5fd;
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
                <button id="show-register-btn" class="btn bg-green-700 hover:bg-green-800 text-sm">${t("register")}</button>
            </div>
        `,document.getElementById("show-login-btn").addEventListener("click",()=>renderApp("login")),document.getElementById("show-register-btn").addEventListener("click",()=>renderApp("register")))}let _renderAppBusy=!1;async function renderApp(e=null){if(!_renderAppBusy){_renderAppBusy=!0;try{if(renderAuthControls(),!authToken){e==="register"?renderRegisterView():e==="login"?renderLoginView():renderLandingView();return}if(!localStorage.getItem("fluxdrop_user_id"))try{const n=await apiCall("/api/v1/me");if(n&&n.id){localStorage.setItem("fluxdrop_user_id",String(n.id));const o=document.getElementById("header-avatar");o&&(o.src=_avatarUrl())}}catch{}_requestNotificationPermission(),checkAndShowPolicies(()=>renderFileBrowserView())}finally{_renderAppBusy=!1}}}function renderLandingView(){appRoot.dataset.fdLanding="1",appRoot.innerHTML=`
        <div style="display:flex;flex-direction:column;gap:2rem;animation:fd-fade-in-up .35s ease both">

            <!-- Hero -->
            <div class="card" style="text-align:center;padding:3rem 2rem">
                <img src="/fluxdrop_pp/icon-72.webp" srcset="/fluxdrop_pp/icon-72.webp 1x, /fluxdrop_pp/icon-128.webp 2x" width="72" height="72" style="width:72px;height:72px;margin:0 auto 1rem" alt="FluxDrop">
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
                    <button class="btn" style="font-size:1rem;padding:0.85rem 2rem;background:#15803d"
                            onclick="renderApp('register')">${t("home_create_account")}</button>
                </div>
            </div>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1.25rem">
                ${[["📁",t("home_card_lable1"),t("home_card_desc1")],["🔗",t("home_card_lable2"),t("home_card_desc2")],["👁",t("home_card_lable3"),t("home_card_desc3")],["⚡",t("home_card_lable4"),t("home_card_desc4")],["🗑",t("home_card_lable5"),t("home_card_desc5")],["🔒",t("home_card_lable6"),t("home_card_desc6")],["👆",t("home_card_lable7_hold"),t("home_card_desc7_hold")]].map(([e,n,o])=>`
                    <div class="card" style="padding:1.5rem">
                        <div style="font-size:2rem;margin-bottom:.5rem">${e}</div>
                        <h3 style="font-weight:700;color:#1e40af;margin-bottom:.4rem">${n}</h3>
                        <p style="color:#64748b;font-size:.92rem;line-height:1.6">${o}</p>
                    </div>
                `).join("")}
            </div>

            <!-- How it works -->
            <div class="card" style="padding:2rem">
                <h3 style="font-size:1.4rem;font-weight:700;color:#1e40af;margin-bottom:1.25rem;text-align:center">
                    ${t("home_card_lable_desc")}
                </h3>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;text-align:center">
                    ${[["1",t("home_card_lable7"),t("home_card_desc7")],["2",t("home_card_lable8"),t("home_card_desc8")],["3",t("home_card_lable9"),t("home_card_desc9")],["4",t("home_card_lable10"),t("home_card_desc10")]].map(([e,n,o])=>`
                        <div>
                            <div style="width:40px;height:40px;border-radius:50%;background:#dbeafe;color:#1d4ed8;
                                        font-weight:800;font-size:1.1rem;display:flex;align-items:center;
                                        justify-content:center;margin:0 auto .6rem">${e}</div>
                            <div style="font-weight:600;color:#1e293b;margin-bottom:.25rem">${n}</div>
                            <div style="font-size:.88rem;color:#64748b">${o}</div>
                        </div>
                    `).join("")}
                </div>
            </div>

            <!-- Footer links -->
            <div style="text-align:center;padding-bottom:1rem;font-size:.85rem;color:#475569">
                <button onclick="showPolicyModal('tos')"
                    style="background:none;border:none;color:inherit;cursor:pointer;text-decoration:underline;font-size:.85rem">
                    ${t("footer_tos")}</button>
                &nbsp;·&nbsp;
                <button onclick="showPolicyModal('pp')"
                    style="background:none;border:none;color:inherit;cursor:pointer;text-decoration:underline;font-size:.85rem">
                    ${t("footer_pp")}</button>
            </div>
        </div>
    `}const POLICY_LABELS={tos:"Terms of Service",pp:"Privacy Policy"},_policyLabel=e=>e==="tos"?t("tos"):e==="pp"?t("footer_pp"):e.toUpperCase();let _policyLang=localStorage.getItem("fluxdrop_policy_lang")||"eng",_versionsCache=null;async function _fetchVersions(){if(_versionsCache)return _versionsCache;try{const e=await fetch("./policies/versions.json",{cache:"no-cache"});e.ok&&(_versionsCache=await e.json())}catch{}return _versionsCache||{}}function _policyUrl(e,n,o){return`./policies/${e==="tos"?"TOS":"PP"}/${n}/v${o}.md`}function _langSelectorHtml(e,n,o,i){if(e.length<=1)return"";const c=e.map(l=>{const r=n&&n[l]||l;return`<option value="${l}"${l===o?" selected":""}>${r}</option>`}).join("");return`<select id="${i}" aria-label="${escapeHtmlAttr(t("language"))}"
        style="font-size:.8rem;padding:3px 6px;border-radius:6px;border:1px solid #cbd5e1;
               color:#475569;background:#f8fafc;cursor:pointer;margin-left:.5rem">
        ${c}
    </select>`}async function showPolicyModal(e){const n=_policyLabel(e),o=await _fetchVersions(),i=o.languages||{},c=o[e]||{},l=Object.keys(c).length?Object.keys(c):["eng"];let r=l.includes(_policyLang)?_policyLang:l[0],s=c[r]||"0.0.0";const a=_policyUrl(e,r,s),d=document.createElement("div");d.setAttribute("role","dialog"),d.setAttribute("aria-modal","true"),d.setAttribute("aria-label",n),d.style.cssText=["position:fixed;top:0;left:0;width:100%;height:100%;z-index:10000","background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;padding:1rem","animation:fd-fade-in .18s ease"].join(";"),d.innerHTML=`
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
                    ${_langSelectorHtml(l,i,r,"pm-lang")}
                </div>
                <button id="pm-close" style="background:none;border:none;font-size:1.4rem;
                        cursor:pointer;color:#64748b;line-height:1">✕</button>
            </div>
            <div id="pm-body" class="fd-md-body" data-fd-notranslate style="padding:1.5rem;overflow-y:auto;flex:1;
                                     font-size:.93rem;line-height:1.7;color:#1e293b">
                ${_loadingHtml("2rem")}
            </div>
        </div>`,document.body.appendChild(d);const u=x=>{x.key==="Escape"&&(x.stopPropagation(),p())};function p(){document.removeEventListener("keydown",u,!0),window.fdCloseOverlay(d)}document.addEventListener("keydown",u,!0),d.querySelector("#pm-close").addEventListener("click",p),d.addEventListener("click",x=>{x.target===d&&p()});const f=await _fetchPolicyHistory();function m(x,k){const g=d.querySelector("#pm-ver-wrap"),w=c[x]||"0.0.0",h=((f[e]||{})[x]||[]).slice();if(h.includes(w)||h.unshift(w),h.length<=1){g.innerHTML=`<span style="font-size:.8rem;color:#94a3b8;font-weight:400">v${escapeHtml(w)}</span>`;return}g.innerHTML=`<select id="pm-ver" title="${escapeHtmlAttr(t("policy_version_label"))}" aria-label="${escapeHtmlAttr(t("policy_version_label"))}"
            style="font-size:.8rem;padding:3px 6px;border-radius:6px;border:1px solid #cbd5e1;
                   color:#475569;background:#f8fafc;cursor:pointer">
            ${h.map(v=>`<option value="${escapeHtmlAttr(v)}"${v===k?" selected":""}>v${escapeHtml(v)}${v===w?" · "+escapeHtml(t("policy_version_current")):""}</option>`).join("")}
        </select>`,g.querySelector("#pm-ver").addEventListener("change",v=>y(x,v.target.value))}async function y(x,k){const g=c[x]||"0.0.0";k=k||g,m(x,k);const w=d.querySelector("#pm-body");w.innerHTML=_loadingHtml("2rem");try{const h=await fetch(_policyUrl(e,x,k),{cache:"no-cache"});if(!h.ok)throw new Error(`HTTP ${h.status}`);const v=await h.text();let _;try{await _loadMarked(),_=_mdParseAndSanitize(v)}catch{_=_mdToHtml(v)}const E=k!==g?`<div style="background:#fef3c7;color:#92400e;border-radius:8px;padding:8px 12px;margin-bottom:1rem;font-size:.85rem">
                       ${escapeHtml(t("policy_old_version_note",{version:k,current:g}))}</div>`:"";w.innerHTML=E+_,w.scrollTop=0}catch(h){w.innerHTML=`<p style="color:#dc2626">${escapeHtml(t("policy_load_failed"))}<br>
                 <small style="color:#94a3b8">${escapeHtml(h.message)}</small></p>`}}const b=d.querySelector("#pm-lang");b&&b.addEventListener("change",()=>{_policyLang=b.value,localStorage.setItem("fluxdrop_policy_lang",_policyLang),y(_policyLang)}),y(r)}let _policyHistoryCache=null;async function _fetchPolicyHistory(){if(_policyHistoryCache)return _policyHistoryCache;try{const e=await fetch(`${API_BASE_URL}/api/v1/policy/history`,{cache:"no-cache"});e.ok&&(_policyHistoryCache=await e.json())}catch{}return _policyHistoryCache||{}}function _mdToHtml(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/^### (.+)$/gm,'<h3 style="font-size:1rem;font-weight:700;color:#1e40af;margin:1.2em 0 .3em">$1</h3>').replace(/^## (.+)$/gm,'<h2 style="font-size:1.15rem;font-weight:700;color:#1e40af;margin:1.4em 0 .4em">$1</h2>').replace(/^# (.+)$/gm,'<h1 style="font-size:1.35rem;font-weight:800;color:#1e40af;margin:1.5em 0 .5em">$1</h1>').replace(/\*\*\*([\s\S]+?)\*\*\*/g,"<strong><em>$1</em></strong>").replace(/___([\s\S]+?)___/g,"<strong><em>$1</em></strong>").replace(/\*\*(.+?)\*\*/g,"<strong>$1</strong>").replace(/__(.+?)__/g,"<strong>$1</strong>").replace(/\*(.+?)\*/g,"<em>$1</em>").replace(/_(.+?)_/g,"<em>$1</em>").replace(/^[-*] (.+)$/gm,'<li style="margin-left:1.5em;margin-bottom:.3em;list-style-type:disc">$1</li>').replace(/^\d+\. (.+)$/gm,'<li style="margin-left:1.5em;margin-bottom:.3em;list-style-type:decimal">$1</li>').replace(/((?:<li[^>]*>.*?<\/li>\n?)+)/g,'<ul style="margin:.4em 0;padding-left:.5em">$1</ul>').replace(/\n{2,}/g,'</p><p style="margin:.6em 0">').replace(/\n/g,"<br>")}async function checkAndShowPolicies(e){let n;try{n=await apiCall("/api/v1/policy/status","GET",null,!0)}catch(c){if(c.message==="SESSION_EXPIRED")return;e();return}const o=[];if(n.token_valid===!1){authToken=null,currentUsername=null,localStorage.removeItem("fluxdrop_token"),localStorage.removeItem("fluxdrop_username"),renderApp("login"),showMessage(t("session_expired"),t("session_expired_msg"));return}if(n.needs_tos&&o.push({type:"tos",version:n.current_tos}),n.needs_pp&&o.push({type:"pp",version:n.current_pp}),o.length===0){e();return}document.getElementById("fd-boot-loading")?.remove();async function i(){if(o.length===0){e();return}const{type:c,version:l}=o.shift();await _showPolicyAgreementModal(c,l,i)}i()}async function _showPolicyAgreementModal(e,n,o,i={}){const c=_policyLabel(e),l=await _fetchVersions(),r=l.languages||{},s=l[e]||{},a=Object.keys(s).length?Object.keys(s):["eng"];let d=a.includes(_policyLang)?_policyLang:a[0];n||(n=s[d]||"");function u(){m.disabled=!1,m.style.opacity="1",m.style.cursor="pointer"}const p=document.createElement("div");p.setAttribute("role","dialog"),p.setAttribute("aria-modal","true"),p.setAttribute("aria-label",c),p.style.cssText=["position:fixed;top:0;left:0;width:100%;height:100%;z-index:10001","background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:1rem","animation:fd-fade-in .18s ease"].join(";"),p.innerHTML=`
        <div class="fd-modal-panel-in" style="background:#fff;border-radius:1rem;width:100%;max-width:720px;
                    max-height:92vh;display:flex;flex-direction:column;overflow:hidden;
                    box-shadow:0 24px 48px rgba(0,0,0,.4)">
            <div style="padding:1.25rem 1.5rem;background:#eff6ff;border-bottom:1px solid #bfdbfe;
                        display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:.5rem">
                <div>
                    <h2 style="font-size:1.1rem;font-weight:700;color:#1e40af;margin:0 0 .25rem;display:flex;align-items:center;gap:.5rem">
                        ${t("policy_review_title_"+e)}
                        ${_langSelectorHtml(a,r,d,"pam-lang")}
                    </h2>
                    <p style="font-size:.85rem;color:#3730a3;margin:0">
                        ${t("policy_version_note",{version:n})}
                    </p>
                </div>
            </div>
            <div id="pam-body" class="fd-md-body" data-fd-notranslate style="padding:1.5rem;overflow-y:auto;flex:1;
                                      font-size:.92rem;line-height:1.7;color:#1e293b">
                <div id="pam-skeleton" style="padding:.5rem 0">
                    ${Array.from({length:18},(g,w)=>`<div style="height:13px;border-radius:4px;margin-bottom:10px;width:${[92,78,85,65,88,70,95,60,82,74,90,55,87,72,80,68,93,63][w]+"%"};background:linear-gradient(90deg,var(--fd-skel-base,#e2e8f0) 25%,var(--fd-skel-shine,#f1f5f9) 50%,var(--fd-skel-base,#e2e8f0) 75%);background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></div>`).join("")}
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
                        ${t("policy_agree_btn_"+e)}
                    </button>
                </div>
            </div>
        </div>`,document.body.appendChild(p);const f=p.querySelector("#pam-body"),m=p.querySelector("#pam-agree-btn"),y=p.querySelector("#pam-scroll-hint");f.addEventListener("scroll",()=>{f.scrollHeight-f.scrollTop-f.clientHeight<40&&(u(),y.textContent=t("policy_scroll_done"))}),m.addEventListener("click",async()=>{if(i.preview){window.fdCloseOverlay(p),showToast("Preview: nothing saved");return}m.disabled=!0,m.textContent=t("policy_saving");const g=showSpinnerOverlay("Saving your agreement…",{minMs:1e3});try{await withMinDelay(apiCall("/api/v1/policy/accept","POST",{[e]:n}),1e3),g(),window.fdCloseOverlay(p),o()}catch(w){if(g(),w.message==="SESSION_EXPIRED"){window.fdCloseOverlay(p);return}m.disabled=!1,m.textContent=t("policy_agree_btn_"+e),showMessage(t("msg_error"),t("policy_save_failed")+": "+w.message)}}),p.querySelector("#pam-decline-btn").addEventListener("click",()=>{if(window.fdCloseOverlay(p),i.preview){showMessage(t("policy_not_accepted"),t("policy_logout_msg"));return}showMessage(t("policy_not_accepted"),t("policy_logout_msg")),handleLogout()});const x=p.querySelector("#pam-lang");x&&x.addEventListener("change",()=>{d=x.value,_policyLang=d,localStorage.setItem("fluxdrop_policy_lang",d),m.disabled=!0,m.style.opacity=".45",m.style.cursor="not-allowed",y.textContent=t("policy_scroll_hint"),k(d)});async function k(g){const w=s[g]||n;f.innerHTML=`<div id="pam-skeleton" style="padding:.5rem 0">
            ${Array.from({length:18},(h,v)=>`<div style="height:13px;border-radius:4px;margin-bottom:10px;width:${[92,78,85,65,88,70,95,60,82,74,90,55,87,72,80,68,93,63][v]+"%"};background:linear-gradient(90deg,var(--fd-skel-base,#e2e8f0) 25%,var(--fd-skel-shine,#f1f5f9) 50%,var(--fd-skel-base,#e2e8f0) 75%);background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></div>`).join("")}
        </div>`,f.scrollTop=0;try{const h=await fetch(_policyUrl(e,g,w),{cache:"no-cache",signal:AbortSignal.timeout(15e3)});if(!h.ok)throw new Error(`HTTP ${h.status}`);const v=await h.text();try{await _loadMarked(),f.innerHTML=_mdParseAndSanitize(v)}catch{f.innerHTML=_mdToHtml(v)}f.scrollHeight<=f.clientHeight+40&&(u(),y.textContent="")}catch(h){const _=h.name==="TimeoutError"||h.name==="AbortError"?t("policy_load_slow"):`${t("policy_load_failed")} (${h.message})`;f.innerHTML=`
                <p style="color:#dc2626">${escapeHtml(_)}</p>
                <p>
                    <button id="pam-retry-btn" class="btn" style="background:#2563eb;margin-right:8px">${escapeHtml(t("retry_btn"))}</button>
                    ${escapeHtml(t("policy_load_retry_hint"))}
                </p>`;const E=f.querySelector("#pam-retry-btn");E&&E.addEventListener("click",()=>k(g)),u(),y.textContent=""}}k(d)}function renderLoginView(){appRoot.dataset.fdLanding||renderLandingView(),_showAuthModal("login")}function renderRegisterView(){appRoot.dataset.fdLanding||renderLandingView(),_showAuthModal("register")}function _showAuthModal(e){document.getElementById("fd-auth-modal")?.remove();const n=document.createElement("div");n.id="fd-auth-modal",n.style.cssText="position:fixed;inset:0;background:rgba(15,23,42,.48);display:flex;align-items:center;justify-content:center;z-index:9500;padding:1rem;backdrop-filter:blur(4px);animation:fd-fade-in .18s ease",n.innerHTML=`
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
        </div>`,document.body.appendChild(n),n.querySelectorAll("#fd-tab-login, #fd-tab-register").forEach(o=>{o.addEventListener("click",()=>{const i=o.id==="fd-tab-login"?"login":"register";["login","register"].forEach(c=>{const l=n.querySelector("#fd-tab-"+c),r=n.querySelector("#fd-"+c+"-form"),s=c===i;l.style.color=s?"#3b82f6":"#94a3b8",l.style.fontWeight=s?"700":"600",l.style.borderBottomColor=s?"#3b82f6":"transparent",r.style.display=s?"flex":"none"})})}),n.addEventListener("click",o=>{o.target===n&&window.fdCloseOverlay(n)}),n.querySelector("#fd-login-form").addEventListener("submit",handleLogin),n.querySelector("#fd-register-form").addEventListener("submit",handleRegister)}function renderFileBrowserView(){appRoot.innerHTML=`
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
                        <button id="btn-browse-cdn" class="btn bg-yellow-300 text-black text-sm" style="padding:.45rem .9rem;${isAdmin?"":"display:none"}">${t("browse_cdn")}</button>
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
                            style="background:#0369a1;flex-shrink:0;padding:.45rem .75rem" title="${t("folder_mode")}">${t("folder_button")}</button>
                        <label class="text-sm" style="flex-shrink:0;white-space:nowrap"><input type="checkbox" id="upload-protected" /> ${t("protected")}</label>
                        <button class="btn" id="btn-upload-submit" type="submit" style="flex-shrink:0;padding:.45rem .9rem">${t("upload")}</button>
                        <span id="upload-spinner" style="display:none;font-size:18px;animation:spin 0.8s linear infinite">⏳</span>
                        <button type="button" id="btn-show-queue"
                            class="btn text-sm hidden"
                            style="background:#4f46e5;flex-shrink:0"
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
                    ⬆ ${escapeHtml(t("drop_hint"))}
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
                       border-radius:50%;background:#2563eb;color:#fff;border:none;
                       align-items:center;justify-content:center;font-size:22px;
                       box-shadow:0 6px 16px rgba(0,0,0,.3);z-index:9100;cursor:pointer">⬆</button>
        </div>
    `,document.getElementById("btn-refresh").addEventListener("click",()=>loadDirectory(currentPath)),document.getElementById("btn-up").addEventListener("click",()=>{if(currentPath==="/"||currentPath==="/cdn")return;let s=currentPath.replace(/\/+$/,""),a=s.lastIndexOf("/");a<=0?s="/":s=s.slice(0,a),navigateTo(s)}),document.getElementById("btn-create-folder").addEventListener("click",promptCreateFolder),document.getElementById("btn-browse-cdn").addEventListener("click",()=>navigateTo("/cdn")),document.getElementById("btn-trash").addEventListener("click",openTrashView),document.getElementById("btn-toolbar-toggle").addEventListener("click",()=>{document.getElementById("fd-toolbar-btns").classList.toggle("fd-toolbar-open")}),document.getElementById("btn-file-choose").addEventListener("click",()=>{document.getElementById("upload-file").click()}),document.getElementById("upload-file").addEventListener("change",function(){const s=this.files?this.files.length:0,a=document.getElementById("upload-file-label");a&&(a.textContent=s===0?t("no_file_selected")!=="no_file_selected"?t("no_file_selected"):"Choose files…":s===1?this.files[0].name:`${s} files selected`),_mobileUploadPending&&(_mobileUploadPending=!1,s>0&&handleUploadForm({preventDefault(){}}))});function e(){const s=document.getElementById("btn-folders-mixed");s&&(s.textContent=sortFoldersMixed?t("folder_sort_mix"):t("folder_sort_first"),s.style.background=sortFoldersMixed?"#6b7280":"#0369a1")}e(),document.getElementById("btn-folders-mixed").addEventListener("click",()=>{sortFoldersMixed=!sortFoldersMixed,localStorage.setItem("fluxdrop_sort_mixed",JSON.stringify(sortFoldersMixed)),e(),loadDirectory(currentPath)}),document.getElementById("upload-form").addEventListener("submit",handleUploadForm);let n=!1;const o=document.getElementById("btn-folder-toggle"),i=document.getElementById("upload-file");o.addEventListener("click",()=>{n=!n,n?(i.setAttribute("webkitdirectory",""),i.setAttribute("mozdirectory",""),i.removeAttribute("multiple"),o.textContent=t("file_button"),o.style.background="#6366f1",o.title=t("files_mode")):(i.removeAttribute("webkitdirectory"),i.removeAttribute("mozdirectory"),i.setAttribute("multiple",""),o.textContent=t("folder_button"),o.style.background="#0369a1",o.title=t("folder_mode")),i.value=""}),(function(){const a=document.getElementById("fd-upload-wrap");if(!a)return;const d=window.matchMedia("(pointer: fine)"),u=window.matchMedia("(hover: hover)");function p(){d.matches||u.matches?a.style.removeProperty("display"):a.style.display="none"}p(),d.addEventListener("change",p),u.addEventListener("change",p)})(),(function(){const a=document.getElementById("fd-mobile-upload-fab");if(!a)return;const d=window.matchMedia("(pointer: fine)"),u=window.matchMedia("(hover: hover)"),p=window.matchMedia("(max-width: 820px)");function f(){const m=!(d.matches||u.matches)||p.matches;a.style.display=m?"flex":"none"}f(),d.addEventListener("change",f),u.addEventListener("change",f),p.addEventListener("change",f),a.addEventListener("click",()=>{_mobileUploadPending=!0,document.getElementById("upload-file").click()})})(),(function(){const a=document.getElementById("fd-drop-zone"),d=document.getElementById("fd-drop-hint");if(!a||!window.matchMedia("(pointer: fine)").matches)return;let u=0;function p(m){u=m?Math.max(u,1):0,a.style.borderColor=m?"var(--fd-accent,#3b82f6)":"transparent",a.style.background=m?"var(--fd-accent-bg,#eff6ff)":"",d&&(d.style.display=m?"block":"none")}a.addEventListener("dragenter",m=>{m.preventDefault(),u++,p(!0)}),a.addEventListener("dragleave",()=>{--u<=0&&p(!1)}),a.addEventListener("dragover",m=>m.preventDefault());async function f(m){const y=[];let b=!1;async function x(g,w){if(g.isFile){const h=await new Promise((v,_)=>g.file(v,_));try{Object.defineProperty(h,"webkitRelativePath",{value:w+g.name,configurable:!0,writable:!1})}catch{}y.push({file:h,rel:w+g.name})}else if(g.isDirectory){b=!0;const h=g.createReader();let v;do{v=await new Promise((_,E)=>h.readEntries(_,E));for(const _ of v)await x(_,w+g.name+"/")}while(v.length>0)}}const k=[];for(let g=0;g<m.length;g++){const w=m[g];if(w.kind!=="file")continue;const h=w.webkitGetAsEntry?.();if(h)k.push(h);else{const v=w.getAsFile();v&&y.push({file:v,rel:v.name})}}return await Promise.all(k.map(g=>x(g,""))),{results:y,hasDir:b}}a.addEventListener("drop",async m=>{m.preventDefault(),p(!1);const{results:y,hasDir:b}=await f(m.dataTransfer.items);if(!y.length)return;b&&!n?(n=!0,o&&(o.textContent=t("file_button")||"📄 Files",o.style.background="#6366f1",o.title=t("files_mode")||"Switch to file mode")):!b&&n&&(n=!1,o&&(o.textContent=t("folder_button")||"📁 Folder",o.style.background="#0369a1",o.title=t("folder_mode")||"Switch to folder mode"));const x=document.getElementById("upload-file-label");x&&(x.textContent=y.length===1?y[0].file.name:`${y.length} items dropped`);const k=document.getElementById("upload-protected")?.checked||!1;if(currentPath.startsWith("/cdn")){showMessage(t("upload_title"),t("cdn_upload_unavailable"));return}const g="user",w=currentPath.endsWith("/")?currentPath:currentPath+"/";window.addEventListener("beforeunload",windowLock);const h=y.map(({file:_,rel:E})=>({file:_,destRel:w+E,ownerType:g,isProtected:k}));if(h.length===1)try{await uploadChunked(h[0].file,h[0].destRel,{ownerType:g}),_notifyUploadDone(1),showMessage(t("upload_successful"),t("upload_success_msg",{name:h[0].file.name})),loadDirectory(currentPath)}catch(_){_.name!=="PauseSignal"&&_.message!=="Upload cancelled"&&showMessage(t("upload_failed"),_.message||String(_))}finally{window.removeEventListener("beforeunload",windowLock)}else{let H=function(){window.removeEventListener("beforeunload",windowLock),_notifyUploadDone(T,B)};var v=H;const[_,...E]=h;window._uploadQueue=[...window._uploadQueue||[],...E];const S=()=>{const A=document.getElementById("btn-show-queue"),q=document.getElementById("queue-count");if(A&&q){const j=window._uploadQueue;j.length>0?(A.classList.remove("hidden"),q.textContent=j.length):A.classList.add("hidden")}};S(),_lastUploadBatchCount+=h.length;let T=0,B=0;async function X(A){for(;A;){try{await uploadChunked(A.file,A.destRel,{ownerType:A.ownerType}),T++,loadDirectory(currentPath)}catch(q){if(q.name==="PauseSignal"){_pausedQueueDrain=()=>{_pausedQueueDrain=null;let j=null;window._uploadQueue?.length>0&&(j=window._uploadQueue.shift(),S()),j?X(j):H()};return}q.message!=="Upload cancelled"&&(B++,showMessage(t("upload_failed"),`${A.file.name}: ${q.message||String(q)}`),window.removeEventListener("beforeunload",windowLock))}window._uploadQueue?.length>0?(A=window._uploadQueue.shift(),S()):A=null}H()}X(_)}})})(),window._uploadQueue=window._uploadQueue||[];function c(){const s=document.getElementById("btn-show-queue"),a=document.getElementById("queue-count");if(!s||!a)return;const d=window._uploadQueue;d.length>0?(s.classList.remove("hidden"),a.textContent=d.length):s.classList.add("hidden")}function l(){const s=document.getElementById("btn-resume-interrupted"),a=document.getElementById("interrupted-count");if(!s||!a)return;const d=getAllInterruptedUploads();d.length>0?(s.classList.remove("hidden"),a.textContent=d.length):s.classList.add("hidden")}c(),l(),document.getElementById("btn-show-queue").addEventListener("click",()=>{openUploadQueuePanel(c)});function r(){l()}document.getElementById("btn-resume-interrupted").addEventListener("click",()=>{openInterruptedManager(l)}),(function(){const a=_APP_BASE.replace(/[.*+?^${}()|[\]\\]/g,"\\$&"),d=window.location.pathname.match(new RegExp("^"+a+"/files(/.*)?$"));if(d)try{currentPath=decodeURIComponent(d[1]||"/")}catch{currentPath=d[1]||"/"}_syncUrlToPath(currentPath)})(),loadDirectory(currentPath)}function apiPathFor(e){return e||(e="/"),e.startsWith("/")||(e="/"+e),`/api/v1/list${encodePath(e)}`}function skeletonRows(e=6){const n=["background:linear-gradient(90deg,var(--fd-skel-base,#e2e8f0) 25%,var(--fd-skel-shine,#f1f5f9) 50%,var(--fd-skel-base,#e2e8f0) 75%)","background-size:200% 100%","animation:fd-shimmer 1.4s infinite","border-radius:4px","display:inline-block"].join(";");if(!document.getElementById("fd-shimmer-style")){const c=document.createElement("style");c.id="fd-shimmer-style",c.textContent="@keyframes fd-shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}",document.head.appendChild(c)}const o=[["55%","8%","14%"],["40%","10%","14%"],["62%","7%","14%"],["48%","9%","14%"],["35%","11%","14%"],["58%","8%","14%"]],i=["55%","40%","65%","48%","35%","60%"];return Array.from({length:e},(c,l)=>{const r=i[l%i.length];return`<tr class="border-t">
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
        </tr>`}).join("")}async function loadDirectory(e){const n=document.getElementById("file-list"),o=document.getElementById("path-breadcrumb");e||(e="/"),e.startsWith("/")||(e="/"+e),currentPath=e,(function(r){const s=r.replace(/\/+$/,"").split("/").filter((u,p)=>p===0?!0:!!u);let a="",d="";s.forEach((u,p)=>{if(p===0)d="/",a+=`<button onclick="navigateTo('/')" style="background:none;border:none;color:#3b82f6;cursor:pointer;font-weight:600;padding:0 2px">${t("fluxdrop_file_manager_path_root")}</button>`;else{d=d.endsWith("/")?d+u:d+"/"+u;const f=d;a+=' <span style="color:#94a3b8">/</span> ',p===s.length-1?a+=`<span style="color:#1e293b;font-weight:600" data-fd-notranslate>${escapeHtml(u)}</span>`:a+=`<button onclick="navigateTo('${escapeHtmlAttr(f)}')" style="background:none;border:none;color:#3b82f6;cursor:pointer;padding:0 2px" data-fd-notranslate>${escapeHtml(u)}</button>`}}),o.innerHTML=a})(e);function i(){const l=[{key:"name",label:"Name",align:"left"},{key:"size",label:"Size",align:"left"},{key:"mtime",label:"Modified",align:"left",cls:"fd-col-mtime"}],r=(d,u)=>`padding:8px;font-size:12px;font-weight:600;color:#64748b;text-align:${d};user-select:none;white-space:nowrap;`,s="background:none;border:none;cursor:pointer;font-size:12px;font-weight:700;color:#64748b;padding:0;display:inline-flex;align-items:center;gap:3px;";return`<thead><tr style="border-bottom:2px solid #e2e8f0">
            ${l.map(d=>{const u=currentSort.key===d.key?currentSort.dir==="asc"?" ▲":" ▼":" ⇅",p=currentSort.key===d.key?"color:#2563eb;":"",f=d.cls?` class="${d.cls}"`:"";return`<th style="${r(d.align)}"${f}>
                <button onclick="window._sortBy('${d.key}')"
                    style="${s}${p}">${d.label}<span style="font-size:10px" aria-hidden="true">${u}</span></button>
            </th>`}).join("")}
            <th style="padding:4px 2px;font-size:14px;font-weight:400;color:#94a3b8;text-align:right;width:1px;white-space:nowrap">⋮</th>
        </tr></thead>`}const c=`<table style="width:100%;table-layout:fixed;border-collapse:collapse">
        <colgroup>
            <col style="width:auto">
            <col style="width:8%">
            <col class="fd-col-mtime" style="width:17%">
            <col style="width:72px">
        </colgroup>`;n.innerHTML=c+i()+`<tbody>${skeletonRows(7)}</tbody></table>`;try{const l=e==="/"?"/api/v1/list/":`/api/v1/list${encodePath(e)}`,s=(await apiCall(l,"GET",null,!0)).entries||[];if(s.length===0){n.innerHTML=`<p class="text-sm text-gray-600" style="padding:1rem">${t("empty_folder")}</p>`,_updateSelBar();return}const d=sortEntries(s).map(u=>renderEntryRow(u)).join("");n.innerHTML=c+i()+`<tbody>${d}</tbody></table>`,attachRowListeners(),_applySelectionVisuals(),_updateSelBar()}catch(l){if(l.message==="SESSION_EXPIRED")return;const r=l.code==="cdn_admin_only"?t("cdn_admin_only"):l.message;n.innerHTML=`<p class="text-sm text-red-600" style="padding:1rem">${escapeHtml(t("load_dir_failed",{msg:r}))}</p>`,_updateSelBar()}}function sortEntries(e){const{key:n,dir:o}=currentSort,i=o==="asc"?1:-1;function c(l,r){if(!sortFoldersMixed&&l.is_dir!==r.is_dir)return l.is_dir?-1:1;let s,a;return n==="size"?(s=l.is_dir?-1:l.size||0,a=r.is_dir?-1:r.size||0,i*(s-a)):n==="mtime"?(s=l.mtime||"",a=r.mtime||"",i*s.localeCompare(a)):i*(l.name||"").localeCompare(r.name||"",void 0,{sensitivity:"base"})}return e.slice().sort(c)}window._sortBy=function(e){currentSort.key===e?currentSort.dir=currentSort.dir==="asc"?"desc":"asc":currentSort={key:e,dir:"asc"},localStorage.setItem("fluxdrop_sort",JSON.stringify(currentSort)),loadDirectory(currentPath)};function _ab(e,n,o,i){const c=Object.entries(i).map(([l,r])=>`data-${l}="${r}"`).join(" ");return`<button class="${n}"
        style="background:${o};color:white;border:none;border-radius:6px;
               padding:3px 8px;font-size:11px;font-weight:600;cursor:pointer;
               white-space:nowrap;line-height:1.6"
        ${c}>${e}</button>`}function renderEntryRow(e){const n=escapeHtml(e.name),o=e.path,i=escapeHtmlAttr(o),c=e.is_dir&&e.size!=null,l=c&&e.file_count!=null?` title="${e.file_count} file${e.file_count!==1?"s":""}"`:"",r=e.is_dir?`<span class="folder-size-cell" data-path="${i}" ${c?'data-warm="1"':""}${l}
               style="color:#94a3b8">${c?formatBytes(e.size):"…"}</span>`:formatBytes(e.size),s='style="padding:9px 8px;vertical-align:middle;overflow:hidden;max-width:0"',a=e.is_dir?`<button class="open-btn fd-entry-name" data-path="${i}"
               style="background:none;border:none;cursor:pointer;font-weight:600;
                      color:var(--fd-accent,#2563eb);font-size:14px;text-align:left;padding:0;
                      white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;display:block"
               data-fd-notranslate title="${i}">📁 ${n}</button>`:`<button class="preview-btn fd-entry-name" data-path="${i}"
               style="background:none;border:none;cursor:pointer;font-weight:500;
                      color:var(--fd-text,#1e293b);font-size:14px;text-align:left;padding:0;
                      white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;display:block"
               data-fd-notranslate title="${i}">📄 ${n}</button>`,d=e.uploader?`<div style="font-size:11px;color:#94a3b8;margin-top:2px">by ${escapeHtml(e.uploader)}</div>`:"",u=`<button class="fd-more-btn" data-path="${i}" data-is-dir="${e.is_dir?"1":"0"}"
        style="background:none;border:1px solid var(--fd-border,#e2e8f0);border-radius:5px;
               padding:2px 7px;cursor:pointer;font-size:16px;line-height:1.3;
               color:var(--fd-muted,#64748b);vertical-align:middle;flex-shrink:0"
        title="Actions">⋮</button>`,p='style="padding:9px 8px;vertical-align:middle;white-space:nowrap"';return`<tr class="border-t fd-file-row"
                data-path="${i}"
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
        <td ${p} class="text-sm text-gray-500">${r}</td>
        <td ${p} class="text-sm text-gray-500 fd-col-mtime"
            style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${escapeHtmlAttr(e.mtime||"")}">${formatMtime(e.mtime)}</td>
        <td style="padding:4px 2px;vertical-align:middle;text-align:right;width:1px;white-space:nowrap">${u}</td>
    </tr>`}window.enterDir=function(e){navigateTo(e)};function formatBytes(e){function n(o){return o>=100?Math.round(o).toString():o>=10?o.toFixed(1):o.toFixed(2)}return e<1024?e+" B":e<1048576?n(e/1024)+" kB":e<1073741824?n(e/1048576)+" MB":n(e/1073741824)+" GB"}function formatMtime(e){if(!e)return"—";const n=new Date(e);if(isNaN(n.getTime()))return e;const o=n.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}),i=new Date,c=(r,s)=>r.getFullYear()===s.getFullYear()&&r.getMonth()===s.getMonth()&&r.getDate()===s.getDate();if(c(n,i))return t("fmt_today_at",{time:o});const l=new Date(i);return l.setDate(i.getDate()-1),c(n,l)?t("fmt_yesterday_at",{time:o}):n.toLocaleDateString([],{day:"numeric",month:"short",year:"numeric"})+" "+t("fmt_at_time",{time:o})}let _streamSaverLoaded=!1;function _loadStreamSaver(){return _streamSaverLoaded?Promise.resolve():new Promise((e,n)=>{const o=document.createElement("script");o.src=_APP_BASE+"/assets/streamsaver/StreamSaver.js",o.onload=()=>{_streamSaverLoaded=!0,typeof streamSaver<"u"&&(streamSaver.mitm=window.location.origin+_APP_BASE+"/assets/streamsaver/mitm.html"),e()},o.onerror=()=>n(new Error("StreamSaver unavailable")),document.head.appendChild(o)})}const _CAN_PICK=typeof window.showSaveFilePicker=="function";window.downloadFile=async function(e,n={}){if(activeDownloads.has(e)){renderDownloadTray();return}const o=n.filename||e.split("/").pop()||"download";let i=null,c;if(typeof window.showSaveFilePicker=="function"){const a=o.split(".").pop()||"",d=_mimeForExt(a);try{i=await window.showSaveFilePicker({suggestedName:o,types:d?[{description:"File",accept:{[d]:["."+a]}}]:void 0}),c="picker"}catch(u){if(u.name==="AbortError")return;logging_warn("showSaveFilePicker failed, falling to native:",u)}}c||(c="native");let l,r;if(n.directUrl)l=n.directUrl,r=n.totalSize||null;else try{const a=await mintDownloadToken(e),d=e.split("/").map(encodeURIComponent).join("/");l=`${API_BASE_URL}/api/v1/download${d}?dl_token=${encodeURIComponent(a.download_token)}`,r=a.total_size||null}catch(a){showMessage(t("download_failed"),a.message);return}if(c==="native"){const a={filename:o,totalSize:r,bytesReceived:0,status:"downloading",speed:null,eta:null,error:null,_writer:null,_abort:new AbortController,_resumeFrom:0,_chunks:[],_mode:"native",_dlUrl:l,_path:e,_fileHandle:null};activeDownloads.set(e,a),renderDownloadTray();const d=document.createElement("a");d.href=l,d.download=o,document.body.appendChild(d),d.click(),document.body.removeChild(d),a.status="done";const u=getTrayDismissDelay();setTimeout(()=>{activeDownloads.delete(e),renderDownloadTray()},Math.max(u,4e3)),renderDownloadTray();return}if(c==="blob"&&r&&r>512*1024*1024&&!confirm(`⚠ Your browser doesn't support streaming downloads to disk.

Downloading ${formatBytes(r)} will be buffered entirely in RAM before saving, which may freeze or crash the tab.

Use Chrome or Edge for large files. Continue anyway?`))return;const s={filename:o,totalSize:r,bytesReceived:0,status:"downloading",speed:null,eta:null,error:null,_writer:null,_abort:new AbortController,_resumeFrom:0,_chunks:[],_mode:c,_dlUrl:l,_path:e,_fileHandle:i};activeDownloads.set(e,s),renderDownloadTray(),await _runDownload(e,s)};async function _runDownload(e,n){if(!n._writer&&n._mode!=="blob")try{if(n._mode==="picker"){const l=n.filename.split(".").pop()||"",r=_mimeForExt(l);if(n._resumeFrom>0)if(n._fileHandle)n._writer=await n._fileHandle.createWritable({keepExistingData:!0}),await n._writer.seek(n._resumeFrom);else{n._resumeFrom=0,n.bytesReceived=0;const a=await window.showSaveFilePicker({suggestedName:n.filename,types:r?[{description:"File",accept:{[r]:["."+l]}}]:void 0});n._fileHandle=a,n._writer=await n._fileHandle.createWritable({keepExistingData:!1})}else{if(!n._fileHandle){const a=await window.showSaveFilePicker({suggestedName:n.filename,types:r?[{description:"File",accept:{[r]:["."+l]}}]:void 0});n._fileHandle=a}n._writer=await n._fileHandle.createWritable({keepExistingData:!1})}}else{const l=streamSaver.createWriteStream(n.filename,{size:n.totalSize||void 0});n._writer=l.getWriter()}}catch(l){if(l.name==="AbortError"){activeDownloads.delete(e),renderDownloadTray();return}n._mode="blob",n._writer=null,logging_warn("showSaveFilePicker/StreamSaver failed, falling back to blob:",l)}n.status="downloading",n._abort=new AbortController,renderDownloadTray();const o={...n._authHeader||{}};authToken&&!o.Authorization&&(o.Authorization=`Bearer ${authToken}`),n._resumeFrom>0&&(o.Range=`bytes=${n._resumeFrom}-`);const i=3,c=2e3;try{let l;for(let p=0;;p++)try{l=await fetchWithFallback(n._dlUrl,{headers:o,signal:n._abort.signal});break}catch(f){if(f.name==="AbortError"||p>=i)throw f;const m=c*Math.pow(2,p);n.status="downloading",n._retrying=!0;for(let y=Math.round(m/1e3);y>0;y--)n.error=`Network error — retrying in ${y}s (${p+1}/${i})`,renderDownloadTray(),await new Promise((b,x)=>{const k=setTimeout(b,1e3);n._abort.signal.addEventListener("abort",()=>{clearTimeout(k),x(new DOMException("Aborted","AbortError"))},{once:!0})});n._retrying=!1,n.error=null,renderDownloadTray()}if(!l.ok&&l.status!==206)throw new Error(`Server returned HTTP ${l.status}`);const r=l.headers.get("Content-Range");if(r){const p=r.match(/bytes \d+-\d+\/(\d+)/);p&&(n.totalSize=parseInt(p[1]))}else if(!n.totalSize){const p=l.headers.get("Content-Length");p&&(n.totalSize=parseInt(p))}renderDownloadTray();const s=l.body.getReader();let a=n.bytesReceived,d=Date.now();try{for(;;){const{done:p,value:f}=await s.read();if(p)break;n._mode==="blob"?n._chunks.push(f):await n._writer.write(f),n.bytesReceived+=f.byteLength,n._resumeFrom+=f.byteLength;const m=Date.now(),y=(m-d)/1e3;y>=.4&&(n.speed=(n.bytesReceived-a)/y,n.eta=n.speed>0&&n.totalSize?(n.totalSize-n.bytesReceived)/n.speed:null,a=n.bytesReceived,d=m),renderDownloadTray()}}catch(p){if(p.name!=="AbortError"&&(p.message?.includes("channel")||p.message?.includes("port1")||p.message?.includes("port2"))){if(n._writer){try{n._writer.abort?.()}catch{}n._writer=null}try{s.cancel("channel closed")}catch{}n._abort.abort(),n.status="cancelled",n._resumeFrom=0,n.bytesReceived=0,n.error="Browser dropped the download. Click Resume to start over.",renderDownloadTray();return}throw p}if(n._mode==="blob"){const p=new Blob(n._chunks);n._chunks=[];const f=document.createElement("a");f.href=URL.createObjectURL(p),f.download=n.filename,f.click(),setTimeout(()=>URL.revokeObjectURL(f.href),6e4)}else await n._writer.close(),n._writer=null;n.status="done",n.speed=null,n.eta=null;const u=getTrayDismissDelay();u>0&&!n._dismissScheduled&&(n._dismissScheduled=!0,setTimeout(()=>{activeDownloads.delete(e),renderDownloadTray()},u)),renderDownloadTray()}catch(l){if(l.name==="AbortError")n.status=n._userCancelled?"cancelled":"paused",n._userCancelled&&(n.error="Download cancelled.",n._userCancelled=!1);else if(n.status="error",n.error=l.message,n._writer){try{await n._writer.abort?.()??n._writer.close()}catch{}n._writer=null}renderDownloadTray()}}window.resumeDownload=async function(e){const n=decodeURIComponent(e),o=activeDownloads.get(n);if(o){if(o.status==="cancelled"&&(o.error=null,o.speed=null,o.eta=null,o._writer=null,o._resumeFrom=0,o.bytesReceived=0,o.totalSize=null,o._chunks=[],o._isZip)){activeDownloads.delete(n),renderDownloadTray();const i=n.startsWith("__zip__")?n.slice(7):n;window.downloadFolderZip(i);return}if(!o._isZip)try{const i=await mintDownloadToken(n),c=n.split("/").map(encodeURIComponent).join("/");o._dlUrl=`${API_BASE_URL}/api/v1/download${c}?dl_token=${encodeURIComponent(i.download_token)}`;const l=i.bytes_confirmed||0;l<o._resumeFrom&&(o._resumeFrom=l)}catch(i){showMessage(t("im_resume_failed"),i.message);return}if(o.error=null,o.speed=null,o.eta=null,o._isZip&&!o._writer&&o._mode==="streamsaver")try{const i=streamSaver.createWriteStream(o.filename);o._writer=i.getWriter()}catch{o._mode="blob",o._writer=null}o._writer=o._isZip?o._writer:null,await _runDownload(n,o)}},window.cancelDownload=function(e){try{e=decodeURIComponent(e)}catch{}const n=activeDownloads.get(e);n&&(n._userCancelled=!0,n._abort?.abort(),n._isZip&&n._jobId&&!n._dlUrl&&fetchWithFallback(`${API_BASE_URL}/api/v1/zip_status/${n._jobId}`,{method:"DELETE",headers:n._authHeader||{}}).catch(()=>{}),n._writer&&(n._writer.abort?.().catch(()=>{}),n._writer=null),n._fileHandle=null),activeDownloads.delete(e),renderDownloadTray()},window.downloadFolderZip=async function(e){const n="__zip__"+e;if(activeDownloads.has(n)){renderDownloadTray();return}const i=(e.split("/").filter(Boolean).pop()||"download")+".zip",c=`${API_BASE_URL}/api/v1/zip_meta${e.split("/").map(encodeURIComponent).join("/")}`,l=authToken?{Authorization:`Bearer ${authToken}`}:{},r={filename:i,totalSize:null,bytesReceived:0,status:"downloading",speed:null,eta:null,error:null,_writer:null,_abort:new AbortController,_resumeFrom:0,_chunks:[],_mode:"native",_dlUrl:null,_path:n,_isZip:!0,_authHeader:l,_needsHashing:!1,_jobId:null};activeDownloads.set(n,r),renderDownloadTray();let s;try{const y=await fetchWithFallback(c,{headers:l,signal:r._abort.signal});if(s=await y.json(),!y.ok)throw new Error(s.error||`HTTP ${y.status}`)}catch(y){r.status=y.name==="AbortError"?r._userCancelled?"cancelled":"paused":"error",r.error=y.name==="AbortError"?null:y.message,renderDownloadTray();return}r._jobId=s.job_id;const a=`${API_BASE_URL}${s.poll_url}`;renderDownloadTray();let d=null;for(;;){if(r._abort.signal.aborted){r.status=r._userCancelled?"cancelled":"paused",renderDownloadTray();return}if(await new Promise(b=>{const x=setTimeout(b,1e3);r._abort.signal.addEventListener("abort",()=>{clearTimeout(x),b()},{once:!0})}),r._abort.signal.aborted){r.status=r._userCancelled?"cancelled":"paused",renderDownloadTray();return}let y;try{const b=await fetchWithFallback(a,{headers:l,signal:r._abort.signal});if(y=await b.json(),!b.ok)throw new Error(y.error||`HTTP ${b.status}`)}catch(b){if(b.name==="AbortError")continue;r.status="error",r.error=b.message,renderDownloadTray();return}if(y.status==="error"){r.status="error",r.error=y.error||"Server error building archive",renderDownloadTray();return}if(y.status==="scanning"){const b=y.progress??0,x=y.total;r._needsHashing=!0,r._scanProgress={prog:b,total:x},renderDownloadTray();continue}if(y.status==="ready"){d=y;break}}r._needsHashing=!!d.needs_hashing,r.totalSize=d.size||null,r.filename=d.filename||r.filename,r.error=d.missing&&d.missing.length>0?t("zip_skipped_tray",{n:d.missing.length}):null;const u=`${API_BASE_URL}${d.url}`,p=authToken?`${u}?token=${encodeURIComponent(authToken)}`:u,f=document.createElement("a");if(f.href=p,f.download=r.filename,f.style.display="none",document.body.appendChild(f),d.missing&&d.missing.length>0){const y=d.missing.map(x=>`<li style="font-family:monospace;font-size:12px">${escapeHtml(x)}</li>`).join(""),b=document.createElement("div");if(b.className="modal-overlay",b.innerHTML=`<div class="modal-content" style="max-width:480px">
            <h3 style="font-size:16px;font-weight:700;margin-bottom:8px">${escapeHtml(t("zip_skipped_title",{n:d.missing.length}))}</h3>
            <p style="font-size:13px;color:#64748b;margin-bottom:10px">${escapeHtml(t("zip_skipped_body"))}</p>
            <ul style="max-height:200px;overflow-y:auto;padding-left:18px;margin-bottom:16px">${y}</ul>
            <div style="display:flex;gap:8px;justify-content:flex-end">
                <button id="zip-missing-cancel" class="btn" style="background:#e2e8f0;color:#1e293b">${escapeHtml(t("cancel"))}</button>
                <button id="zip-missing-ok" class="btn">${escapeHtml(t("zip_download_anyway"))}</button>
            </div>
        </div>`,document.body.appendChild(b),await new Promise(x=>{b.querySelector("#zip-missing-ok").addEventListener("click",()=>{b.remove(),x(!0)}),b.querySelector("#zip-missing-cancel").addEventListener("click",()=>{b.remove(),x(!1),r.status="cancelled",renderDownloadTray()})}).then(x=>{}),r.status==="cancelled")return}f.click(),document.body.removeChild(f),r.status="done",renderDownloadTray(),_watchZipReport(d.session_id,r);const m=getTrayDismissDelay();m>0&&setTimeout(()=>{activeDownloads.delete(n),renderDownloadTray()},m)};function _watchZipReport(e,n){if(!e)return;const o=`${API_BASE_URL}/api/v1/zip_stream/${e}/report`,i=Date.now(),c=async()=>{let l;try{const r=await fetchWithFallback(o,{headers:authToken?{Authorization:`Bearer ${authToken}`}:{}});if(r.status===404||r.status===403)return;l=r.ok?await r.json():null}catch{l=null}if(l&&l.finished){if(l.vanished&&l.vanished.length){n.error=t("zip_vanished_tray",{n:l.vanished.length}),renderDownloadTray();const r=l.vanished.map(s=>`<li style="font-family:monospace;font-size:12px">${escapeHtml(s)}</li>`).join("");showMessage(t("zip_vanished_title",{n:l.vanished.length}),`${escapeHtml(t("zip_vanished_body",{name:n.filename||""}))}
                     <ul tabindex="0" style="max-height:200px;overflow-y:auto;padding-left:18px;margin-top:8px">${r}</ul>`,!0)}return}Date.now()-i<24*3600*1e3&&setTimeout(c,5e3)};setTimeout(c,5e3)}function _mimeForExt(e){return{mp4:"video/mp4",webm:"video/webm",mkv:"video/x-matroska",mp3:"audio/mpeg",flac:"audio/flac",wav:"audio/wav",m4a:"audio/mp4",jpg:"image/jpeg",jpeg:"image/jpeg",png:"image/png",gif:"image/gif",webp:"image/webp",svg:"image/svg+xml",pdf:"application/pdf",zip:"application/zip",tar:"application/x-tar",txt:"text/plain",md:"text/markdown",json:"application/json",js:"text/javascript",css:"text/css",html:"text/html"}[e.toLowerCase()]||null}function logging_warn(...e){console.warn("[FluxDrop]",...e)}const activeDownloads=new Map;async function mintDownloadToken(e){return await apiCall("/api/v1/download_token","POST",{path:e})}function renderDownloadTray(){let e=document.getElementById("dl-tray");if(e||(e=document.createElement("div"),e.id="dl-tray",e.style.cssText=`
            position:fixed; bottom:0; right:1rem; width:340px; max-height:60vh;
            overflow-y:auto; background:#1e293b; border-radius:12px 12px 0 0;
            box-shadow:0 -4px 24px rgba(0,0,0,0.4); z-index:9000;
            font-family:Inter,sans-serif; font-size:13px; color:#e2e8f0;
        `,document.body.appendChild(e),e.classList.add("fd-tray-in"),e.addEventListener("animationend",()=>e.classList.remove("fd-tray-in"),{once:!0})),activeDownloads.size===0){e.innerHTML.trim()!==""&&window.fdCollapseTray(e).then(()=>{activeDownloads.size===0&&(e.innerHTML="")});return}e.classList.remove("fd-tray-closing");let n=e.querySelector(".dl-tray-header");n||(n=document.createElement("div"),n.className="dl-tray-header",n.style.cssText="padding:10px 14px 6px;font-weight:700;font-size:14px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center;",n.innerHTML='<span class="dl-count"></span><span style="cursor:pointer;opacity:.6" id="dl-tray-close">✕</span>',e.prepend(n),n.querySelector("#dl-tray-close").addEventListener("click",async()=>{await window.fdCollapseTray(e),e.innerHTML=""})),n.querySelector(".dl-count").textContent=t("tray_downloads",{n:activeDownloads.size}),e.querySelectorAll(".dl-row").forEach(o=>{activeDownloads.has(o.dataset.dlPath)||o.remove()});for(const[o,i]of activeDownloads){const c=i.totalSize?Math.round(i.bytesReceived/i.totalSize*100):0,l=formatBytes(i.bytesReceived),r=i.totalSize?formatBytes(i.totalSize):"?",s=i.filename||o.split("/").pop(),a=o.replace(/\\/g,"\\\\").replace(/"/g,'\\"');let d=e.querySelector(`.dl-row[data-dl-path="${CSS.escape(o)}"]`);if(!d){d=document.createElement("div"),d.className="dl-row",d.dataset.dlPath=o,d.style.cssText="padding:10px 14px;border-bottom:1px solid #1e293b",d.innerHTML=`
                <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                    <span class="dl-name" title="${escapeHtml(s)}"
                        style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px"></span>
                    <span class="dl-bytes" style="color:#94a3b8"></span>
                </div>
                <div style="background:#334155;border-radius:4px;height:6px;margin-bottom:6px">
                    <div class="dl-bar"
                        style="background:#2563eb;height:6px;border-radius:4px;width:0%;transition:width .3s"></div>
                </div>
                <div style="display:flex;justify-content:space-between;align-items:center">
                    <span class="dl-status" style="color:#64748b"></span>
                    <div class="dl-actions"></div>
                </div>`,e.appendChild(d),requestAnimationFrame(()=>{e.scrollTop=e.scrollHeight});const g=d.querySelector(".dl-actions"),w=document.createElement("button");w.textContent=t("cancel"),w.style.cssText="background:#dc2626;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px",w.addEventListener("click",()=>cancelDownload(o));const h=document.createElement("button");h.textContent=t("dl_resume"),h.style.cssText="background:#2563eb;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px",h.addEventListener("click",()=>resumeDownload(encodeURIComponent(o)));const v=document.createElement("button");v.textContent=t("cancel"),v.style.cssText="background:#64748b;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px;margin-left:4px",v.addEventListener("click",()=>cancelDownload(o));const _=document.createElement("button");_.textContent=t("dl_dismiss"),_.style.cssText="background:#64748b;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px",_.addEventListener("click",()=>{activeDownloads.delete(o),renderDownloadTray()}),d._btns={cancelBtn:w,resumeBtn:h,abortBtn:v,dismissBtn:_,actionsDiv:g}}const u={downloading:"⬇",paused:"⏸",error:"⚠",done:"✅",cancelled:"🚫"};d.querySelector(".dl-name").textContent=(u[i.status]||"")+" "+s,d.querySelector(".dl-bytes").textContent=`${l} / ${r}`;const p=d.querySelector(".dl-bar");p.style.width=c+"%",p.style.background=i._retrying?"#f59e0b":"#3b82f6",p.style.animation=i._retrying?"fd-retry-pulse 1s ease-in-out infinite":"";let f=i.status;if(i.status==="downloading"){const g=[];if(i.speed!=null&&g.push(formatSpeed(i.speed)),i.eta!=null&&g.push(t("tray_eta",{t:formatEta(i.eta)})),g.length)f=g.join(" · ");else if(i._retrying&&i.error)f="🔄 "+i.error;else if(i._isZip&&!i._dlUrl){const w=i._scanProgress,h=w&&w.total?t("dl_scan_hint",{done:w.prog,total:w.total}):"";f=(i._needsHashing?t("dl_hashing"):t("dl_building"))+h}else i._mode==="native"?f=t("dl_via_browser"):f=""}else i.status==="error"?f="⚠ "+(i.error||t("tray_failed")):i.status==="cancelled"?f=i.error||t("dl_cancelled"):i.status==="paused"?f=t("dl_paused"):i.status==="done"&&(f=t("tray_done"));d.querySelector(".dl-status").textContent=f;const{actionsDiv:m,cancelBtn:y,resumeBtn:b,abortBtn:x,dismissBtn:k}=d._btns;m.innerHTML="",i.status==="downloading"?m.appendChild(y):i.status==="paused"||i.status==="error"?(m.appendChild(b),m.appendChild(x)):i.status==="cancelled"?(m.appendChild(b),m.appendChild(k)):i.status==="done"&&m.appendChild(k)}}const EXT_IMAGE=new Set(["jpg","jpeg","png","gif","webp","bmp","svg","ico","avif","tiff","tif"]),EXT_IMAGE_HEIC=new Set(["heic","heif"]),EXT_VIDEO=new Set(["mp4","webm","ogg","ogv","mov","m4v","mkv","avi"]),EXT_AUDIO=new Set(["mp3","wav","flac","aac","ogg","oga","m4a","opus","weba"]),EXT_TEXT=new Set(["txt","js","ts","jsx","tsx","py","sh","bash","json","xml","yaml","yml","toml","ini","cfg","conf","html","htm","css","scss","less","csv","log","env","rs","go","c","cpp","h","java","rb","php","swift","kt","sql","r","lua"]),EXT_MARKDOWN=new Set(["md","markdown","mdown","mkd"]),EXT_ARCHIVE=new Set(["zip","tar","gz","tgz","bz2","tbz2","xz","txz","7z","rar","zst","lz4","lzma","cab","iso","dmg","pkg","deb","rpm"]),EXT_PDF=new Set(["pdf"]);function fileCategory(e){const n=(e.split(".").pop()||"").toLowerCase();return EXT_IMAGE.has(n)?"image":EXT_IMAGE_HEIC.has(n)?"heic":EXT_VIDEO.has(n)?"video":EXT_AUDIO.has(n)?"audio":EXT_MARKDOWN.has(n)?"markdown":EXT_PDF.has(n)?"pdf":EXT_TEXT.has(n)?"text":EXT_ARCHIVE.has(n)?"archive":"binary"}let _heic2anyLoaded=!1;function _loadHeic2any(){return _heic2anyLoaded?Promise.resolve():new Promise((e,n)=>{const o=document.createElement("script");o.src="/fluxdrop_pp/assets/heic2any.min.js",o.onload=()=>{_heic2anyLoaded=!0,e()},o.onerror=()=>n(new Error("Failed to load heic2any")),document.head.appendChild(o)})}let _jszipLoaded=!1;function _loadJSZip(){return _jszipLoaded?Promise.resolve():new Promise((e,n)=>{const o=document.createElement("script");o.src="/fluxdrop_pp/assets/jszip.min.js",o.onload=()=>{_jszipLoaded=!0,e()},o.onerror=()=>n(new Error("Failed to load JSZip")),document.head.appendChild(o)})}let _untarLoaded=!1;function _loadUntar(){return _untarLoaded?Promise.resolve():new Promise((e,n)=>{const o=document.createElement("script");o.src="/fluxdrop_pp/assets/untar.min.js",o.onload=()=>{_untarLoaded=!0,e()},o.onerror=()=>n(new Error("Failed to load js-untar")),document.head.appendChild(o)})}let _markedLoaded=!1;function _loadMarked(){return _markedLoaded?Promise.resolve():new Promise((e,n)=>{const o=document.createElement("script");o.src="/fluxdrop_pp/assets/marked.min.js",o.onload=()=>{_markedLoaded=!0,e()},o.onerror=()=>n(new Error("Failed to load marked.js")),document.head.appendChild(o)})}function _mdParseAndSanitize(e){const n=/^(\s{0,3})(#{1,6}\s|```|~~~|>|[-*_]{3,}[ \t]*$|<\/?[a-zA-Z]|[-*+]\s|\d+[.)]\s|\|)/,o=/^(\s{0,3})(>|[-*+]\s|\d+[.)]\s)/,i=e.split(`
`),c=[];let l=!1;for(let m=0;m<i.length;m++){const y=i[m],b=i[m+1];/^\s{0,3}(`{3,}|~{3,})/.test(y)&&(l=!l),c.push(y),!l&&y.trim()!==""&&b!==void 0&&b.trim()!==""&&(!n.test(y)||o.test(y))&&!n.test(b)&&!y.endsWith("  ")&&!y.endsWith("\\")&&(i[m+1]=y+" "+b,c[c.length-1]="")}const r=c.join(`
`);marked.use({gfm:!0,breaks:!1});const s=marked.parse(r),a=new Set(["p","br","hr","h1","h2","h3","h4","h5","h6","strong","em","del","code","pre","blockquote","ul","ol","li","table","thead","tbody","tr","th","td","a","img","input"]),d={a:new Set(["href","title"]),img:new Set(["src","alt","title","width","height"]),input:new Set(["type","checked","disabled"]),th:new Set(["align"]),td:new Set(["align"]),code:new Set(["class"]),pre:new Set(["class"])},u=/^(https?:|mailto:|#|\/)/i,p=document.createElement("div");p.innerHTML=s;function f(m){if(m.nodeType===Node.TEXT_NODE)return;if(m.nodeType!==Node.ELEMENT_NODE){m.remove();return}const y=m.tagName.toLowerCase();if(!a.has(y)){m.replaceWith(...m.childNodes);return}const b=d[y]||new Set;for(const x of[...m.attributes]){if(!b.has(x.name)){m.removeAttribute(x.name);continue}(x.name==="href"||x.name==="src")&&!u.test(x.value)&&m.removeAttribute(x.name)}y==="a"&&(m.setAttribute("target","_blank"),m.setAttribute("rel","noopener noreferrer")),y==="input"&&m.setAttribute("disabled",""),m.childNodes.forEach(f)}return p.childNodes.forEach(f),p.innerHTML}function _renderMarkdown(e,n){e.classList.add("fd-md-body"),e.innerHTML="";const o=document.createElement("div");if(o.className="md-preview",o.setAttribute("data-fd-notranslate",""),o.style.cssText="color:#e2e8f0;font-size:15px;line-height:1.75;padding:1.25rem 1.5rem;overflow-y:auto;max-height:70vh",o.innerHTML=_mdParseAndSanitize(n),!document.getElementById("md-preview-style")){const i=document.createElement("style");i.id="md-preview-style",i.textContent=`
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
        `,document.head.appendChild(i)}e.appendChild(o)}let _previewAbortCtrl=null;async function _fetchBlobWithProgress(e,n,o){const i=e.headers.get("Content-Length"),c=i?parseInt(i):0;if(!c||!e.body)return e.blob();const l="fd-preview-progress-"+Date.now();o.innerHTML=`
        <div style="width:100%;max-width:700px;margin:0 auto">
            <div style="width:100%;aspect-ratio:16/10;border-radius:8px;
                background:linear-gradient(90deg,#1e293b 25%,#334155 50%,#1e293b 75%);
                background-size:200% 100%;animation:fd-shimmer 1.4s infinite;margin-bottom:12px"></div>
            <div style="background:#334155;border-radius:4px;height:5px;overflow:hidden">
                <div id="${l}" style="height:100%;border-radius:4px;background:#2563eb;width:0%;transition:width .15s"></div>
            </div>
            <div id="${l}-label" style="text-align:center;font-size:12px;color:#64748b;margin-top:6px">0%</div>
        </div>`;const r=e.body.getReader(),s=[];let a=0;for(;;){const{done:p,value:f}=await r.read();if(n&&n.aborted)throw new DOMException("Aborted","AbortError");if(p)break;s.push(f),a+=f.byteLength;const m=Math.min(100,Math.round(a/c*100)),y=document.getElementById(l),b=document.getElementById(l+"-label");y&&(y.style.width=m+"%"),b&&(b.textContent=m+"%  ("+formatBytes(a)+" / "+formatBytes(c)+")")}const d=new Uint8Array(a);let u=0;for(const p of s)d.set(p,u),u+=p.byteLength;return new Blob([d],{type:e.headers.get("Content-Type")||"application/octet-stream"})}async function _previewTrashFile(e,n,o){_previewAbortCtrl&&_previewAbortCtrl.abort(),_previewAbortCtrl=new AbortController;const i=_previewAbortCtrl.signal,c=document.getElementById("preview-modal"),l=document.getElementById("preview-title"),r=document.getElementById("preview-body"),s=document.getElementById("preview-download-btn");l.textContent=n,r.innerHTML=_loadingHtml("2rem"),s.style.display="none",c.classList.remove("hidden");const a=`${API_BASE_URL}/api/v1/trash/${e}/file`+(o?`?path=${encodeURIComponent(o)}`:"");try{const d=fileCategory(n);if(["image","heic","pdf","text","markdown","audio","video"].includes(d)){const u=await fetchWithFallback(a,{signal:i,headers:authToken?{Authorization:`Bearer ${authToken}`}:{}});if(!u.ok)throw new Error(`HTTP ${u.status}`);r.innerHTML=`<div style="width:100%;max-width:700px;margin:0 auto;
                aspect-ratio:16/10;border-radius:8px;
                background:linear-gradient(90deg,#1e293b 25%,#334155 50%,#1e293b 75%);
                background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></div>`;const p=await u.blob();if(i.aborted){URL.revokeObjectURL(URL.createObjectURL(p));return}const f=URL.createObjectURL(p),m=()=>{URL.revokeObjectURL(f)};if(d==="image"||d==="heic")r.innerHTML=`<img src="${f}" alt="${escapeHtml(n)}"
                    style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto">`;else if(d==="video")r.innerHTML=`<video controls autoplay style="max-width:100%;max-height:70vh;
                    border-radius:8px;display:block;margin:0 auto;background:#000">
                    <source src="${f}">Your browser doesn't support this video format.</video>`;else if(d==="audio")r.innerHTML=`<div style="padding:2rem 1rem;text-align:center">
                    <div style="font-size:4rem;margin-bottom:1rem">🎵</div>
                    <div style="color:#94a3b8;margin-bottom:1.5rem;font-size:15px">${escapeHtml(n)}</div>
                    <audio controls autoplay style="width:100%"><source src="${f}"></audio></div>`;else if(d==="pdf")r.innerHTML=`<iframe src="${f}"
                    style="width:100%;height:65vh;border:none;border-radius:8px;background:#1e293b;opacity:0;transition:opacity .2s"
                    title="${escapeHtml(n)}"></iframe>`,_fadeInWhenLoaded(r.querySelector("iframe"));else{const b=await p.text();if(d==="markdown")await _loadMarked(),_renderMarkdown(r,b);else{const x=(n.split(".").pop()||"").toLowerCase();r.innerHTML=`<pre class="lang-${x}">${escapeHtml(b.slice(0,5e4))}${b.length>5e4?`

… (truncated)`:""}</pre>`}}const y=window.closePreview;window.closePreview=function(){m(),window.closePreview=y,y()},s.style.display="none"}else r.innerHTML=`<div style="padding:3rem 1rem;text-align:center">
                <div style="font-size:3.5rem;margin-bottom:1rem">📄</div>
                <div style="color:#94a3b8;margin-bottom:1rem">${escapeHtml(n)}</div>
                <p style="color:#64748b;font-size:14px">No preview available. Restore the file to download it.</p>
            </div>`}catch(d){if(d.name==="AbortError")return;r.innerHTML=`<p style="color:#ef4444;padding:2rem;text-align:center">Preview failed: ${escapeHtml(String(d))}</p>`}}window.closePreview=function(){const e=document.getElementById("preview-modal");if(e.classList.contains("hidden")||e.dataset.fdClosing)return;_previewAbortCtrl&&(_previewAbortCtrl.abort(),_previewAbortCtrl=null),e.dataset.fdClosing="1",e.classList.add("fd-overlay-closing");const n=e.querySelector(".preview-modal-content");n&&n.classList.add("fd-panel-closing");let o=!1;const i=()=>{if(o)return;o=!0,e.classList.remove("fd-overlay-closing"),n&&n.classList.remove("fd-panel-closing"),delete e.dataset.fdClosing,e.classList.add("hidden");const c=document.getElementById("preview-body");c.querySelectorAll("video,audio").forEach(l=>{l.pause(),Array.from(l.querySelectorAll("source")).forEach(r=>r.remove()),l.removeAttribute("src"),l.load()}),c.innerHTML="",document.getElementById("preview-download-btn").style.display="none"};e.addEventListener("animationend",i,{once:!0}),setTimeout(i,200)};function _renderArchiveTree(e,n,o){if(!n.length){e.innerHTML=`<div style="padding:2rem;text-align:center;color:#94a3b8">${t("archive_empty")}</div>`;return}function i(a){const d={children:Object.create(null),files:[]};for(const u of a){const p=u.name.replace(/\\/g,"/").replace(/\/$/,"").split("/");if(u.isDir||p.length>1){let f=d;const m=u.isDir?p:p.slice(0,-1);for(const y of m)f.children[y]||(f.children[y]={children:Object.create(null),files:[]}),f=f.children[y];u.isDir||f.files.push({name:p[p.length-1],size:u.size})}else d.files.push({name:u.name,size:u.size})}return d}function c(a,d){let u="";const p=d*16;for(const[f,m]of Object.entries(a.children).sort(([y],[b])=>y.localeCompare(b)))u+=`<div style="display:flex;align-items:center;gap:6px;padding:3px 8px 3px ${8+p}px;
                         border-radius:5px;cursor:default" class="arc-dir-row"
                         onmouseenter="this.style.background='rgba(255,255,255,.05)'"
                         onmouseleave="this.style.background=''">
                <span style="font-size:13px;flex-shrink:0">📁</span>
                <span style="font-size:13px;color:#93c5fd;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(f)}</span>
            </div>
            ${c(m,d+1)}`;for(const f of a.files.sort((m,y)=>m.name.localeCompare(y.name))){const m=f.size!=null?`<span style="font-size:11px;color:#64748b;flex-shrink:0;margin-left:auto;padding-left:8px">${formatBytes(f.size)}</span>`:"";u+=`<div style="display:flex;align-items:center;gap:6px;padding:3px 8px 3px ${8+p}px;
                         border-radius:5px;cursor:default"
                         onmouseenter="this.style.background='rgba(255,255,255,.05)'"
                         onmouseleave="this.style.background=''">
                <span style="font-size:13px;flex-shrink:0">📄</span>
                <span style="font-size:13px;color:#e2e8f0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(f.name)}</span>
                ${m}
            </div>`}return u}const l=i(n),r=n.filter(a=>!a.isDir).length,s=n.filter(a=>a.isDir).length;e.innerHTML=`
        <div style="padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.08);
                    display:flex;align-items:center;justify-content:space-between">
            <span style="font-size:12px;color:#94a3b8">
                ${escapeHtml(t("arc_counts",{files:r,dirs:s}))}
            </span>
            <span style="font-size:11px;color:#475569">${escapeHtml(t("file_modal_info_archive_file_table"))}</span>
        </div>
        <div style="overflow:auto;max-height:60vh;padding:6px 4px;font-family:ui-monospace,monospace">
            ${c(l,0)}
        </div>`}function _fadeInWhenLoaded(e){if(!e)return;const n=()=>{e.style.opacity="1"};e.addEventListener("load",n,{once:!0}),setTimeout(n,1500)}window.previewFile=async function(e){_previewAbortCtrl&&_previewAbortCtrl.abort(),_previewAbortCtrl=new AbortController;const n=_previewAbortCtrl.signal,o=e.split("/").pop(),i=fileCategory(e),c=document.getElementById("preview-modal"),l=document.getElementById("preview-title"),r=document.getElementById("preview-body"),s=document.getElementById("preview-download-btn");l.textContent=o,r.innerHTML='<p style="color:#64748b;padding:2rem;text-align:center">Connecting…</p>',s.style.display="none",c.classList.remove("hidden");try{const a=await mintDownloadToken(e),d=`/api/v1/download${encodePath(e)}`,u=`${API_BASE_URL}${d}?dl_token=${encodeURIComponent(a.download_token)}`;if(i==="image"){r.innerHTML=`<div style="width:100%;max-width:700px;margin:0 auto;
                aspect-ratio:16/10;border-radius:8px;
                background:linear-gradient(90deg,#1e293b 25%,#334155 50%,#1e293b 75%);
                background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></div>`,r.innerHTML='<p style="color:#64748b;padding:2rem;text-align:center">Fetching an image…</p>';const p=await fetchWithFallback(u,{signal:n,...authToken?{headers:{Authorization:`Bearer ${authToken}`}}:{}});if(!p.ok)throw new Error(`HTTP ${p.status}`);const f=await _fetchBlobWithProgress(p,n,r),m=URL.createObjectURL(f);if(n.aborted){URL.revokeObjectURL(m);return}r.innerHTML=`<img src="${m}" alt="${escapeHtml(o)}"
                style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto">`;const y=window.closePreview;window.closePreview=function(){URL.revokeObjectURL(m),window.closePreview=y,y()},s.style.display="inline-flex",s.onclick=()=>downloadFile(e)}else if(i==="heic"){r.innerHTML='<p style="color:#94a3b8;padding:2rem;text-align:center">Decoding HEIC…</p>',await _loadHeic2any();const p=await fetchWithFallback(u,{signal:n,...authToken?{headers:{Authorization:`Bearer ${authToken}`}}:{}});if(!p.ok)throw new Error(`HTTP ${p.status}`);const f=await p.blob(),m=await heic2any({blob:f,toType:"image/jpeg",quality:.85}),y=URL.createObjectURL(m);r.innerHTML=`<img src="${y}" alt="${escapeHtml(o)}"
                style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto">`;const b=window.closePreview;window.closePreview=function(){URL.revokeObjectURL(y),window.closePreview=b,b()},s.style.display="inline-flex",s.onclick=()=>downloadFile(e)}else if(i==="video")r.innerHTML=`<video controls autoplay style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto;background:#000"><source src="${u}">Your browser doesn't support this video format.</video>`,s.style.display="inline-flex",s.onclick=()=>downloadFile(e);else if(i==="audio")r.innerHTML=`<div style="padding:2rem 1rem;text-align:center"><div style="font-size:4rem;margin-bottom:1rem">🎵</div><div style="color:#94a3b8;margin-bottom:1.5rem;font-size:15px">${escapeHtml(o)}</div><audio controls autoplay style="width:100%"><source src="${u}">Your browser doesn't support audio playback.</audio></div>`,s.style.display="inline-flex",s.onclick=()=>downloadFile(e);else if(i==="markdown"){r.innerHTML='<p style="color:#94a3b8;padding:2rem;text-align:center">Rendering…</p>',await _loadMarked();const p=await fetchWithFallback(u,{signal:n,...authToken?{headers:{Authorization:`Bearer ${authToken}`}}:{}});if(!p.ok)throw new Error(`HTTP ${p.status}`);const f=await p.text();_renderMarkdown(r,f),s.style.display="inline-flex",s.onclick=()=>downloadFile(e)}else if(i==="text"){const p=await fetchWithFallback(u,{signal:n,...authToken?{headers:{Authorization:`Bearer ${authToken}`}}:{}});if(!p.ok)throw new Error(`HTTP ${p.status}`);const f=await p.text(),m=(e.split(".").pop()||"").toLowerCase();r.innerHTML=`<pre class="lang-${m}">${escapeHtml(f.slice(0,5e4))}${f.length>5e4?`

… (truncated)`:""}</pre>`,s.style.display="inline-flex",s.onclick=()=>downloadFile(e)}else if(i==="pdf"){r.innerHTML='<p style="color:#64748b;padding:2rem;text-align:center">Fetching a PDF…</p>';const p=await fetchWithFallback(u,{signal:n,...authToken?{headers:{Authorization:`Bearer ${authToken}`}}:{}});if(!p.ok)throw new Error(`HTTP ${p.status}`);const f=await p.blob();if(n.aborted)return;const m=new Blob([f],{type:"application/pdf"}),y=URL.createObjectURL(m);r.innerHTML=`<iframe
                src="${y}"
                style="width:100%;height:65vh;border:none;border-radius:8px;background:#1e293b;opacity:0;transition:opacity .2s"
                title="${escapeHtml(o)}">
                <p style="color:#94a3b8;padding:2rem;text-align:center">
                    Your browser cannot display PDFs inline.
                </p>
            </iframe>`,_fadeInWhenLoaded(r.querySelector("iframe"));const b=window.closePreview;window.closePreview=function(){URL.revokeObjectURL(y),window.closePreview=b,b()},s.style.display="inline-flex",s.onclick=()=>{closePreview(),downloadFile(e)}}else if(i==="archive"){const p=(e.split(".").pop()||"").toLowerCase();r.innerHTML='<p style="color:#94a3b8;padding:2rem;text-align:center">Reading archive…</p>';const f=p==="zip",m=["tar","gz","tgz"].includes(p),y=["bz2","tbz2","xz","txz","7z","rar","zst","lz4","lzma","cab","iso","dmg","pkg","deb","rpm"].includes(p),b={bz2:"bzip2",tbz2:"bzip2 tar",xz:"XZ",txz:"XZ tar","7z":"7-Zip",rar:"RAR",zst:"Zstandard",lz4:"LZ4",lzma:"LZMA",cab:"Windows Cabinet",iso:"Disc Image",dmg:"macOS Disk Image",pkg:"Package",deb:"Debian Package",rpm:"RPM Package"};if(y){const x=b[p]||"."+p.toUpperCase();r.innerHTML=`<div style="padding:3rem 1rem;text-align:center">
                    <div style="font-size:3rem;margin-bottom:1rem">🗜</div>
                    <div style="color:#94a3b8;font-weight:600;margin-bottom:4px">${escapeHtml(o)}</div>
                    <div style="color:#64748b;font-size:12px;margin-bottom:12px">${x} archive</div>
                    <p style="color:#64748b;font-size:14px">
                        In-browser preview is not available for this format.<br>
                        Download the file and extract it locally.
                    </p></div>`,s.style.display="inline-flex",s.onclick=()=>{closePreview(),downloadFile(e)}}else if(f||m)try{const x=a.download_token,k=e.split("/").map(encodeURIComponent).join("/"),g=`${API_BASE_URL}/api/v1/archive_tree${k}?dl_token=${encodeURIComponent(x)}`;let w;for(;;){const v=await fetchWithFallback(g,{signal:n,headers:authToken?{Authorization:`Bearer ${authToken}`}:{}});if(v.status===202){const _=await v.json().catch(()=>({})),E=_.total?Math.min(99,Math.floor(_.done/_.total*100)):0;let S=r.querySelector("#fd-arc-progress");if(S||(r.innerHTML=_loadingHtml("2rem")+`<p style="text-align:center;color:#94a3b8;font-size:13px;margin-top:-8px">
                                        <span id="fd-arc-progress"></span><br>
                                        <span style="font-size:12px">${escapeHtml(t("arc_reading_hint"))}</span></p>`,S=r.querySelector("#fd-arc-progress")),S.textContent=_.queued?t("arc_waiting"):t("arc_reading",{pct:E}),await new Promise(T=>setTimeout(T,1500)),n.aborted)return;continue}if(!v.ok){const _=await v.json().catch(()=>({}));throw new Error(_.error||`HTTP ${v.status}`)}w=await v.json();break}const h=w.entries.map(v=>({name:v.name,size:v.size,isDir:v.is_dir}));_renderArchiveTree(r,h,o),w.truncated&&r.insertAdjacentHTML("afterbegin",`<p style="margin:0 0 8px;padding:6px 10px;border-radius:6px;background:#fef3c7;color:#92400e;font-size:12px">
                                ${escapeHtml(t("arc_truncated",{n:h.length,reason:w.truncated_reason||t("arc_limit_reached")}))}</p>`)}catch(x){r.innerHTML=`<p style="color:#ef4444;padding:2rem;text-align:center">
                        Archive preview failed: ${escapeHtml(String(x))}</p>`}else r.innerHTML=`<div style="padding:3rem 1rem;text-align:center">
                    <div style="font-size:3.5rem;margin-bottom:1rem">📦</div>
                    <div style="color:#94a3b8;margin-bottom:1rem">${escapeHtml(o)}</div>
                    <p style="color:#64748b;font-size:14px">No preview available for this archive type yet.</p>
                </div>`,s.style.display="inline-flex",s.onclick=()=>{closePreview(),downloadFile(e)};s.style.display="inline-flex",s.onclick=()=>downloadFile(e)}else r.innerHTML=`<div style="padding:3rem 1rem;text-align:center"><div style="font-size:3.5rem;margin-bottom:1rem">📄</div><div style="color:#94a3b8;margin-bottom:1rem">${escapeHtml(o)}</div><p style="color:#64748b;font-size:14px">No preview available for this file type yet.</p></div>`,s.style.display="inline-flex",s.onclick=()=>{closePreview(),downloadFile(e)}}catch(a){if(a.name==="AbortError")return;r.innerHTML=`<p style="color:#ef4444;padding:2rem;text-align:center">Preview failed: ${escapeHtml(String(a))}</p>`}},window.previewText=window.previewFile;let _selectedPaths=new Set,_lastClickedPath=null;window._fdKeepSelectionOnNav=!1;function _selBarGhost(){return`
    <span style="visibility:hidden;pointer-events:none;flex-shrink:0">${t("sel_bar_count",{n:0})}</span>
    <button class="btn" style="visibility:hidden;pointer-events:none;padding:3px 10px;font-size:12px" disabled>⬇ ${t("download")}</button>
    <button class="btn" style="visibility:hidden;pointer-events:none;padding:3px 10px;font-size:12px;background:#dc2626" disabled>🗑 ${t("trash")}</button>
    <button class="btn" style="visibility:hidden;pointer-events:none;padding:3px 10px;font-size:12px;background:#6b7280;margin-left:auto" disabled>✕ ${t("sel_bar_clear")}</button>`}async function _trashSelectedPaths(e){if(!e.length)return;const n=e.length;if(!await showConfirmModal({title:t("sel_bar_delete_title",{n}),message:t("sel_bar_delete_msg",{n,days:_lastKnownRetentionDays})}))return;_clearSelection(),_updateSelBar();let i=_lastKnownRetentionDays,c=0;for(const r of e){const s=await deleteItem(r,{skipConfirm:!0,silent:!0});s===!1?c++:s&&(i=s)}const l=e.length-c;l>0&&(_showTrashBatchNotice(l,i),showToast(t("trash_moved_toast",{n:l}))),c>0&&showToast(t("trash_delete_failed")+` (${c})`,{type:"error"}),loadDirectory(currentPath)}window.addEventListener("pointermove",e=>{e.pointerType==="mouse"&&!window._fdSawMouse&&(window._fdSawMouse=!0,_updateSelBar())},{passive:!0});function _updateSelBar(){const e=_selectedPaths.size,n=document.getElementById("fd-sel-bar");if(!n)return;const o=!window._fdSawMouse&&window.matchMedia("(pointer: coarse)").matches&&!window.matchMedia("(hover: hover)").matches;if(n.style.display=o?"none":"flex",o)return;if(e===0){n.classList.remove("fd-sel-bar-visible"),n.innerHTML=_selBarGhost(),n.onclick=null;return}n.classList.add("fd-sel-bar-visible");const i=window.matchMedia("(pointer: fine)").matches||window.matchMedia("(hover: hover)").matches;n.innerHTML=`
        <span style="color:var(--fd-accent,#3b82f6);font-weight:600;flex-shrink:0">${t("sel_bar_count",{n:e})}</span>
        ${i?`
        <label style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--fd-muted,#64748b);
                       cursor:pointer;flex-shrink:0;user-select:none" title="${t("sel_bar_keep_tooltip")}">
            <input type="checkbox" id="fd-sel-keep-chk" ${window._fdKeepSelectionOnNav?"checked":""}
                   style="width:13px;height:13px">
            📌 ${t("sel_bar_keep_label")}
        </label>`:""}
        <button data-fdsel="download" class="btn" style="padding:3px 10px;font-size:12px">⬇ ${t("download")}</button>
        <button data-fdsel="trash"    class="btn" style="padding:3px 10px;font-size:12px;background:#dc2626 !important">🗑 ${t("trash")}</button>
        <button data-fdsel="clear"    class="btn" style="padding:3px 10px;font-size:12px;background:#4b5563 !important;margin-left:auto">✕ ${t("sel_bar_clear")}</button>
    `,i&&n.querySelector("#fd-sel-keep-chk").addEventListener("change",function(){window._fdKeepSelectionOnNav=this.checked}),n.onclick=c=>{const l=c.target.closest("[data-fdsel]");if(!l)return;const r=l.dataset.fdsel;if(r==="clear"){_clearSelection(),_updateSelBar();return}if(r==="trash"){_trashSelectedPaths([..._selectedPaths]);return}if(r==="download"){_getFileRows().filter(a=>_selectedPaths.has(a.dataset.path)).forEach(a=>{a.dataset.isDir==="1"?downloadFolderZip(a.dataset.path):downloadFile(a.dataset.path)});return}}}function _doRowSelect(e,n,o){_removeContextMenu();const i=document.getElementById("fd-info-panel");i&&window.fdCloseFloatingPanel(i);const c=_getFileRows(),l=_lastClickedPath?c.findIndex(r=>r.dataset.path===_lastClickedPath):-1;if(o.shiftKey&&l>=0){const r=Math.min(l,n),s=Math.max(l,n);_selectedPaths.clear(),c.forEach((a,d)=>{const u=d>=r&&d<=s;_updateRowSelVisual(a,u),u&&_selectedPaths.add(a.dataset.path)})}else o.ctrlKey||o.metaKey?(_toggleSelect(e),_lastClickedPath=e.dataset.path):(_clearSelection(),_toggleSelect(e,!0),_lastClickedPath=e.dataset.path);_updateSelBar()}function attachRowListeners(){const e=document.getElementById("file-list");e&&(e.querySelectorAll(".fd-more-btn").forEach(n=>{n.addEventListener("click",o=>{o.stopPropagation();const i=n.closest(".fd-file-row"),c=n.getBoundingClientRect();_showContextMenu(c.left,c.bottom+4,i)})}),e.querySelectorAll(".fd-file-row").forEach((n,o)=>{n.addEventListener("click",i=>{i.target.closest("button")||_doRowSelect(n,o,i)}),n.querySelectorAll(".preview-btn, .open-btn").forEach(i=>{i.addEventListener("click",c=>{if(c.stopPropagation(),c.shiftKey||c.ctrlKey||c.metaKey){_doRowSelect(n,o,c);return}i.classList.contains("open-btn")?enterDir(i.dataset.path):previewFile(i.dataset.path)})}),n.addEventListener("dblclick",i=>{i.target.closest("button")||(_clearSelection(),_updateSelBar(),n.dataset.isDir==="1"?enterDir(n.dataset.path):previewFile(n.dataset.path))}),n.addEventListener("contextmenu",i=>{i.preventDefault(),_selectedPaths.has(n.dataset.path)||(_clearSelection(),_toggleSelect(n,!0),_lastClickedPath=n.dataset.path,_updateSelBar()),_showContextMenu(i.clientX,i.clientY,n)})}),document.body._fdSelClearBound||(document.body._fdSelClearBound=!0,document.body.addEventListener("click",n=>{n.target.closest(".fd-file-row, #fd-sel-bar, #fd-ctx-menu, .modal-overlay, .fd-profile-overlay")||_selectedPaths.size>0&&(_clearSelection(),_updateSelBar())})),e.querySelectorAll(".folder-size-cell:not([data-warm])").forEach((n,o)=>{setTimeout(()=>loadFolderSize(n),o*80)}))}function _getFileRows(){return Array.from(document.querySelectorAll("#file-list .fd-file-row"))}function _cancelPendingDotCleanup(e){e._fdSelTimeout&&(clearTimeout(e._fdSelTimeout),e._fdSelTimeout=null),e._fdSelFinish&&(e.removeEventListener("animationend",e._fdSelFinish),e._fdSelFinish=null)}function _updateRowSelVisual(e,n){const o=e.querySelector(".fd-sel-dot");if(o)if(_cancelPendingDotCleanup(o),n)o.style.display="inline-flex",o.style.background="var(--fd-accent,#3b82f6)",o.textContent="✓",o.style.color="#fff",o.classList.remove("fd-sel-dot-out"),o.offsetWidth,o.classList.add("fd-sel-dot-in"),e.style.background="var(--fd-accent-bg,#eff6ff)";else{if(o.style.display==="none")return;o.classList.remove("fd-sel-dot-in"),o.classList.add("fd-sel-dot-out"),e.style.background="";const i=()=>{o.style.display="none",o.style.background="transparent",o.textContent="",o.classList.remove("fd-sel-dot-out"),o._fdSelFinish=null,o._fdSelTimeout=null};o._fdSelFinish=i,o.addEventListener("animationend",i,{once:!0}),o._fdSelTimeout=setTimeout(i,180)}}function _toggleSelect(e,n){const o=e.dataset.path,i=n!==void 0?n:!_selectedPaths.has(o);i?_selectedPaths.add(o):_selectedPaths.delete(o),_updateRowSelVisual(e,i)}function _setRowIndeterminate(e,n){const o=e.querySelector(".fd-sel-dot");if(o)if(_cancelPendingDotCleanup(o),n)o.style.display="inline-flex",o.style.background="var(--fd-accent-dim,#93c5fd)",o.textContent="–",o.style.color="#fff",o.classList.remove("fd-sel-dot-out"),o.offsetWidth,o.classList.add("fd-sel-dot-in");else{if(o.textContent!=="–")return;o.classList.remove("fd-sel-dot-in"),o.classList.add("fd-sel-dot-out");const i=()=>{o.style.display="none",o.style.background="transparent",o.textContent="",o.classList.remove("fd-sel-dot-out"),o._fdSelFinish=null,o._fdSelTimeout=null};o._fdSelFinish=i,o.addEventListener("animationend",i,{once:!0}),o._fdSelTimeout=setTimeout(i,180)}}function _hasSelectedDescendant(e){const n=e.endsWith("/")?e:e+"/";for(const o of _selectedPaths)if(o!==e&&o.startsWith(n))return!0;return!1}function _applySelectionVisuals(){_getFileRows().forEach(e=>{const n=e.dataset.path;_selectedPaths.has(n)?_updateRowSelVisual(e,!0):e.dataset.isDir==="1"&&_hasSelectedDescendant(n)&&_setRowIndeterminate(e,!0)})}function _clearSelection(){_getFileRows().forEach(e=>_updateRowSelVisual(e,!1)),_selectedPaths.clear(),_lastClickedPath=null}function _dropSelectedUnder(e){const n=e.endsWith("/")?e:e+"/";for(const o of[..._selectedPaths])(o===e||o.startsWith(n))&&_selectedPaths.delete(o);(_lastClickedPath===e||_lastClickedPath?.startsWith(n))&&(_lastClickedPath=null)}function _removeContextMenu(){document.removeEventListener("scroll",_ctxMenuScroll),document.getElementById("fd-ctx-menu")?.remove()}function _dismissContextMenu(){document.removeEventListener("scroll",_ctxMenuScroll);const e=document.getElementById("fd-ctx-menu");e&&window.fdCloseFloatingPanel(e)}let _ctxMenuScrollY=0;function _ctxMenuScroll(){Math.abs(window.scrollY-_ctxMenuScrollY)>24&&_dismissContextMenu()}function _showContextMenu(e,n,o){_removeContextMenu();const i=o.dataset.path,c=o.dataset.isDir==="1",l=_selectedPaths.size,r=l>1&&_selectedPaths.has(i),s=document.createElement("div");s.id="fd-ctx-menu",s.style.cssText=`position:fixed;left:${e}px;top:${n}px;background:var(--fd-surface,#fff);border:1px solid var(--fd-border,#e2e8f0);border-radius:8px;box-shadow:0 6px 24px rgba(0,0,0,0.15);z-index:50000;min-width:190px;padding:4px 0;font-size:13px;overflow:hidden`;const a=(u,p,f,m)=>`<button class="fd-ctx-item" data-action="${f}"
            style="display:block;width:100%;padding:7px 14px;text-align:left;
                   background:none;border:none;cursor:pointer;
                   color:${m?"var(--fd-danger,#dc2626)":"var(--fd-text,#1e293b)"};
                   white-space:nowrap;font-size:13px"
        >${u} ${p}</button>`,d='<div style="border-top:1px solid var(--fd-border,#e2e8f0);margin:4px 0"></div>';if(r){const u=_getFileRows().filter(y=>_selectedPaths.has(y.dataset.path)),p=u.filter(y=>y.dataset.isDir==="1").length,f=u.length-p;let m;p===0?m=t("ctx_download_files",{n:f}):f===0?m=t("ctx_download_folders_zip",{n:p}):m=t("ctx_download_mixed",{nf:f,nd:p}),s.innerHTML=[a("⬇",m,"download-multi"),d,a("🗑",t("ctx_trash_multi",{n:l}),"trash-multi",!0)].join("")}else s.innerHTML=[c?a("📂",t("ctx_open"),"open"):a("👁",t("ctx_preview"),"preview"),c?a("⬇",t("ctx_download_zip"),"zip"):a("⬇",t("ctx_download"),"download"),a("🔗",t("ctx_share"),"share"),a("✂",t("ctx_move_rename"),"move"),a("ℹ",t("ctx_info"),"info"),d,a("🗑",t("ctx_trash"),"trash",!0)].join("");document.body.appendChild(s),s.classList.add("fd-ctx-menu-in"),setTimeout(()=>{document.addEventListener("click",_dismissContextMenu,{once:!0,capture:!0}),_ctxMenuScrollY=window.scrollY,document.addEventListener("scroll",_ctxMenuScroll,{passive:!0})},0),s.querySelectorAll(".fd-ctx-item").forEach(u=>{u.addEventListener("mouseenter",()=>u.style.background="var(--fd-surface3,#f1f5f9)"),u.addEventListener("mouseleave",()=>u.style.background="none"),u.addEventListener("click",()=>{_dismissContextMenu();const p=o.dataset.path,f=o.dataset.isDir==="1";switch(u.dataset.action){case"open":enterDir(p);break;case"preview":previewFile(p);break;case"download":downloadFile(p);break;case"zip":downloadFolderZip(p);break;case"share":openShareDialog(p,f);break;case"move":openMoveDialog(p);break;case"info":_showFileInfo(o);break;case"trash":deleteItem(p);break;case"download-multi":{_getFileRows().filter(m=>_selectedPaths.has(m.dataset.path)).forEach(m=>{m.dataset.isDir==="1"?downloadFolderZip(m.dataset.path):downloadFile(m.dataset.path)});break}case"trash-multi":{_trashSelectedPaths([..._selectedPaths]);break}}})}),requestAnimationFrame(()=>{const u=s.getBoundingClientRect();u.right>window.innerWidth&&(s.style.left=Math.max(4,window.innerWidth-u.width-8)+"px"),u.bottom>window.innerHeight&&(s.style.top=Math.max(4,n-u.height)+"px")})}let _fdInfoInspectorCleanup=()=>{};function _showFileInfo(e){_fdInfoInspectorCleanup(),document.getElementById("fd-info-panel")?.remove();const n=e.dataset.name||"—",o=e.dataset.path||"—",i=e.dataset.isDir==="1",c=e.dataset.mtime||"",l=e.dataset.uploader||"",r=parseInt(e.dataset.size,10),s=i?e.querySelector(".folder-size-cell")?.textContent?.trim()||"…":isNaN(r)?"—":formatBytes(r),a=!i&&n.includes(".")?n.split(".").pop().toUpperCase():null,d=i?"Folder":a?`${a} file`:"File",u=document.createElement("div");if(u.id="fd-info-panel",u.setAttribute("role","dialog"),u.setAttribute("aria-label",t("file_info_title")),u.style.cssText="position:fixed;right:12px;top:70px;width:280px;z-index:20000;background:var(--fd-surface,#fff);border:1px solid var(--fd-border,#e2e8f0);border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,0.14);padding:0;overflow:hidden;font-size:13px;animation:fd-info-in .18s ease",!document.getElementById("fd-info-kf")){const y=document.createElement("style");y.id="fd-info-kf",y.textContent="@keyframes fd-info-in{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:none}}",document.head.appendChild(y)}const p=(y,b,x)=>`<div style="display:flex;justify-content:space-between;padding:5px 14px;
                     border-bottom:1px solid var(--fd-border,#e2e8f0)">
            <span style="color:var(--fd-muted,#64748b);flex-shrink:0;margin-right:8px;white-space:nowrap">${y}</span>
            <span style="color:var(--fd-text,#1e293b);text-align:right;word-break:break-all;font-family:${y==="CRC-32"?"monospace":"inherit"}">${x?b:escapeHtml(b)}</span>
         </div>`;u.innerHTML=`<div style="background:var(--fd-surface3,#f1f5f9);padding:10px 14px;
                     display:flex;justify-content:space-between;align-items:center;
                     border-bottom:1px solid var(--fd-border,#e2e8f0)">
            <span style="font-weight:600;color:var(--fd-text,#1e293b);font-size:14px">
                ℹ️ ${escapeHtml(t("file_info_title"))}
            </span>
            <button id="fd-info-close" style="background:none;border:none;cursor:pointer;
                font-size:18px;color:var(--fd-muted,#64748b);padding:0 2px;line-height:1">✕</button>
        </div>`+p(t("file_info_name"),n)+p(t("file_info_path"),o)+p(t("file_info_type"),d)+p(t("file_info_size"),s)+p(t("file_info_modified"),c?formatMtime(c):"—")+(l?p(t("file_info_uploaded_by"),l):"")+(i?"":`<div id="fd-info-cs-wrap">
            <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 14px;border-bottom:1px solid var(--fd-border,#e2e8f0);gap:8px">
                <span style="color:var(--fd-muted,#64748b);flex-shrink:0;white-space:nowrap">CRC-32</span>
                <span id="fd-cs-val-crc32" style="display:flex;align-items:center;gap:4px;min-width:0"><span style="color:#94a3b8;font-size:12px">${escapeHtml(t("loading"))}</span></span>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 14px;border-bottom:1px solid var(--fd-border,#e2e8f0);gap:8px">
                <span style="color:var(--fd-muted,#64748b);flex-shrink:0;white-space:nowrap">SHA-256</span>
                <span id="fd-cs-val-sha256" style="display:flex;align-items:center;gap:4px;min-width:0"><span style="color:#94a3b8;font-size:12px">${escapeHtml(t("loading"))}</span></span>
            </div>
        </div>`)+(i?"":`<div style="padding:8px 14px;border-bottom:1px solid var(--fd-border,#e2e8f0)">
            <button id="fd-info-dl" class="btn"
                style="width:100%;padding:5px;font-size:12px;text-align:center">
                ⬇ ${escapeHtml(t("download"))}
            </button></div>`),document.body.appendChild(u);let f=!1;try{f=localStorage.getItem("fd_pin_info_panel")==="1"}catch{}document.getElementById("fd-info-close").addEventListener("click",()=>{_fdInfoInspectorCleanup(),window.fdCloseFloatingPanel(u)});const m=document.getElementById("fd-info-dl");if(m&&m.addEventListener("click",()=>{_fdInfoInspectorCleanup(),u.remove(),downloadFile(o)}),i||_initChecksumSection(o,u),f){const y=b=>{if(u.contains(b.target)||b.target.closest&&b.target.closest(".fd-more-btn"))return;const x=b.target.closest&&b.target.closest(".fd-file-row");x&&(b.preventDefault(),b.stopPropagation(),_showFileInfo(x))};setTimeout(()=>document.addEventListener("click",y,!0),10),_fdInfoInspectorCleanup=()=>{document.removeEventListener("click",y,!0),_fdInfoInspectorCleanup=()=>{}}}else{const y=b=>{u.contains(b.target)||(window.fdCloseFloatingPanel(u),document.removeEventListener("click",y,!0))};setTimeout(()=>document.addEventListener("click",y,!0),10)}}function _initChecksumSection(e,n){let o=null;function i(a,d){const u=n.querySelector(`#fd-cs-val-${a}`);u&&(u.innerHTML='<span style="color:#d97706;font-size:12px"></span>',u.firstChild.textContent="⧗ "+t(d?"cs_calculating_upload":"cs_calculating"),d&&(u.firstChild.title=t("cs_calculating_upload_tip")))}function c(a,d){const u=n.querySelector(`#fd-cs-val-${a}`);if(!u)return;const p=a==="sha256"?d.slice(0,16)+"…":d;u.innerHTML=`<span style="font-family:monospace;font-size:11px;color:var(--fd-text,#1e293b);word-break:break-all;text-align:right" title="${escapeHtmlAttr(d)}">${escapeHtml(p)}</span><button id="fd-cs-copy-${a}" title="Copy ${a.toUpperCase()}" style="border:none;background:none;cursor:pointer;color:#94a3b8;font-size:13px;padding:0 0 0 3px;flex-shrink:0;line-height:1">⧉</button>`,n.querySelector(`#fd-cs-copy-${a}`)?.addEventListener("click",f=>{f.stopPropagation(),navigator.clipboard?.writeText(d);const m=n.querySelector(`#fd-cs-copy-${a}`);m&&(m.textContent="✓",setTimeout(()=>{m&&(m.textContent="⧉")},1500))})}function l(a,d,u){const p=n.querySelector(`#fd-cs-val-${a}`);if(!p)return;const f=u?` title="${escapeHtmlAttr(u)}"`:"",m=u?"⚠️ error":"—";p.innerHTML=`<span style="color:#94a3b8;font-size:12px"${f}>${m}</span><button id="fd-cs-calc-${a}" style="border:none;background:#f1f5f9;color:#3b82f6;cursor:pointer;padding:2px 7px;border-radius:6px;font-size:11px;font-weight:600;margin-left:4px;flex-shrink:0">${u?t("retry_btn"):t("cs_calc_btn")}</button>`,n.querySelector(`#fd-cs-calc-${a}`)?.addEventListener("click",async y=>{y.stopPropagation();for(const b of d)i(b);try{await apiCall("/api/v1/checksums/compute","POST",{path:e,algos:d},!0)}catch(b){l(a,d,b.message||"Request failed");return}r()})}function r(a=1800){n.isConnected&&(clearTimeout(o),o=setTimeout(s,a))}async function s(){if(!n.isConnected){clearTimeout(o);return}let a;try{a=await apiCall(`/api/v1/fileinfo${encodePath(e)}`,"GET",null,!0)}catch{const x='<span style="color:#94a3b8;font-size:12px">—</span>';["crc32","sha256"].forEach(k=>{const g=n.querySelector(`#fd-cs-val-${k}`);g&&(g.innerHTML=x)});return}if(!n.isConnected)return;if(a.integrity_issue&&!n.querySelector("#fd-info-integrity")){const x=document.createElement("div");x.id="fd-info-integrity",x.style.cssText="padding:8px 14px;background:#fef2f2;color:#b91c1c;font-size:12px;border-bottom:1px solid var(--fd-border,#e2e8f0)",x.textContent=t("info_integrity_warning",{date:formatMtime(String(a.integrity_issue.detected_at).replace(" ","T")+"Z")}),n.querySelector("#fd-info-cs-wrap")?.before(x)}const d=a.job,u=d&&(d.status==="pending"||d.status==="running"),p=d&&d.status==="error",f=p?d.error||"Computation failed":null,m=d&&d.algos||"",y=!!(d&&d.after_upload),b=[];a.crc32||b.push("crc32"),a.sha256||b.push("sha256"),a.crc32?c("crc32",a.crc32.toLowerCase()):u&&m.includes("crc32")?i("crc32",y):l("crc32",b.length?b:["crc32"],p&&m.includes("crc32")?f:null),a.sha256?c("sha256",a.sha256.toLowerCase()):u&&m.includes("sha256")?i("sha256",y):l("sha256",b.length?b:["sha256"],p&&m.includes("sha256")?f:null),u&&n.isConnected&&r(y?5e3:1800)}s()}async function loadFolderSize(e){const n=e.dataset.path;if(!(!n||!authToken))try{const o=`/api/v1/foldersize${encodePath(n)}`,i=await apiCall(o,"GET",null,!0);e.isConnected&&(e.textContent=formatBytes(i.size),e.title=`${i.file_count} file${i.file_count!==1?"s":""}`,e.style.color="")}catch{e.isConnected&&(e.textContent="—",e.style.color="#94a3b8")}}window.deleteItem=async function(e,n={}){const o=typeof n=="boolean"?{skipConfirm:n}:n||{},i=!!o.skipConfirm,c=!!o.silent,l=stripInternalPrefix(e);if(!i&&!await showConfirmModal({title:t("trash_single_title",{name:l}),message:t("sel_bar_delete_msg",{n:1,days:_lastKnownRetentionDays})}))return!1;try{const s=(await apiCall("/api/v1/trash","POST",{path:e})).retention_days||30;return _lastKnownRetentionDays=s,_selectedPaths.delete(e),c||(_updateSelBar(),showToast(t("trash_single_toast",{name:l,days:s}))),loadDirectory(currentPath),s}catch(r){return showMessage(t("trash_delete_failed"),r.message),!1}};const _TRASH_BATCH_NOTICE_KEY="fd-trash-batch-notice-v1";function _showTrashBatchNotice(e,n){const o=n||30;localStorage.getItem(_TRASH_BATCH_NOTICE_KEY)||(localStorage.setItem(_TRASH_BATCH_NOTICE_KEY,"1"),showMessage(t("trash_moved_toast",{n:e}),t("trash_batch_notice_body",{days:o})))}(function(){if(document.getElementById("_fd-spin-style"))return;const e=document.createElement("style");e.id="_fd-spin-style",e.textContent="@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}",document.head.appendChild(e)})();async function openTrashView(){document.getElementById("trash-overlay")?.remove();const e=document.createElement("div");e.id="trash-overlay",e.className="modal-overlay",e.innerHTML=`
        <div class="modal-content" style="max-width:680px;width:95vw;padding:0;overflow:hidden;border-radius:14px">
            <div style="background:linear-gradient(135deg,#dc2626,#b91c1c);padding:16px 20px;
                        display:flex;align-items:center;justify-content:space-between">
                <div>
                    <div id="trash-title" style="color:white;font-weight:700;font-size:16px">🗑 Trash</div>
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
                    style="background:#dc2626;color:white;border:none;border-radius:7px;
                           padding:6px 14px;cursor:pointer;font-size:12px;font-weight:600;
                           white-space:nowrap">
                    ${t("trash_empty_btn")!=="trash_empty_btn"?t("trash_empty_btn"):"Empty Trash"}
                </button>
            </div>
            <div id="trash-body" style="max-height:55vh;overflow-y:auto;padding:8px 0">
                ${_loadingHtml()}
            </div>
        </div>`,document.body.appendChild(e),e.addEventListener("click",n=>{n.target===e&&window.fdCloseOverlay(e)}),await _refreshTrashView(),document.getElementById("trash-empty-btn").addEventListener("click",async()=>{if(await showConfirmModal({title:"Empty Trash?",message:"Everything in the Trash will be permanently deleted. This cannot be undone."}))try{await apiCall("/api/v1/trash","DELETE"),await _refreshTrashView()}catch(o){alert("Failed to empty trash: "+o.message)}})}async function _refreshTrashView(){const e=document.getElementById("trash-body"),n=document.getElementById("trash-subtitle"),o=document.getElementById("trash-notice");if(!e)return;e.innerHTML=_loadingHtml();let i;try{i=await apiCall("/api/v1/trash","GET")}catch(a){e.innerHTML=`<div style="padding:24px;text-align:center;color:#ef4444">Failed: ${escapeHtml(a.message)}</div>`;return}const c=i.items||[];if(i.retention_days&&(_lastKnownRetentionDays=i.retention_days),n.textContent=c.length===1?t("trash_1_item")!=="trash_1_item"?t("trash_1_item"):"1 item":t("trash_n_items")!=="trash_n_items"?t("trash_n_items",{n:c.length}):`${c.length} items`,i.retention_days===7&&o?(o.textContent="⚠ "+t("trash_retention_reduced_notice",{days:i.retention_days}),o.style.display="block"):o&&(o.style.display="none"),!c.length){e.innerHTML='<div style="padding:40px;text-align:center;color:#94a3b8;font-size:15px">🗑 Trash is empty</div>';return}function l(a){return a?new Date(a*1e3).toLocaleString():"—"}function r(a){return a<1024?a+" B":a<1048576?(a/1024).toFixed(1)+" KB":a<1073741824?(a/1048576).toFixed(1)+" MB":(a/1073741824).toFixed(2)+" GB"}function s(a){const d=Math.ceil((a-Date.now()/1e3)/86400);return d<=0?`<span style="color:#ef4444">${t("trash_days_expiring")!=="trash_days_expiring"?t("trash_days_expiring"):"Expiring soon"}</span>`:d===1?`<span style="color:#f59e0b">${t("trash_days_1")!=="trash_days_1"?t("trash_days_1"):"1 day left"}</span>`:d<=3?`<span style="color:#f59e0b">${t("trash_days_n")!=="trash_days_n"?t("trash_days_n",{n:d}):`${d} days left`}</span>`:`<span style="color:#64748b">${t("trash_days_n")!=="trash_days_n"?t("trash_days_n",{n:d}):`${d} days left`}</span>`}e.innerHTML=c.map(a=>`
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
                           style="background:#4f46e5;color:white;border:none;border-radius:6px;
                                  padding:4px 10px;cursor:pointer;font-size:12px">
                           ${t("trash_browse")}
                       </button>`:`<button class="trash-preview-btn" data-id="${a.id}" data-name="${escapeHtmlAttr(a.name)}"
                           style="background:#4f46e5;color:white;border:none;border-radius:6px;
                                  padding:4px 10px;cursor:pointer;font-size:12px">
                           ${t("trash_preview")}
                       </button>`}
                <button class="trash-restore-btn" data-id="${a.id}"
                    style="background:#15803d;color:white;border:none;border-radius:6px;
                           padding:4px 10px;cursor:pointer;font-size:12px;font-weight:600">
                    ${t("trash_restore")}
                </button>
                <button class="trash-del-btn" data-id="${a.id}" data-name="${escapeHtmlAttr(a.name)}"
                    style="background:#dc2626;color:white;border:none;border-radius:6px;
                           padding:4px 10px;cursor:pointer;font-size:12px">
                    ${t("trash_delete")}
                </button>
            </div>
        </div>`).join(""),e.querySelectorAll(".trash-restore-btn").forEach(a=>{a.addEventListener("click",async()=>{const d=+a.dataset.id;try{const u=await apiCall(`/api/v1/trash/${d}/restore`,"POST");loadDirectory(currentPath),await _refreshTrashView()}catch(u){alert("Restore failed: "+u.message)}})}),e.querySelectorAll(".trash-del-btn").forEach(a=>{a.addEventListener("click",async()=>{const d=+a.dataset.id,u=a.dataset.name||"";if(await showConfirmModal({title:t("trash_perm_delete_title",{name:u}),message:t("trash_perm_delete_body")}))try{await apiCall(`/api/v1/trash/${d}`,"DELETE"),await _refreshTrashView()}catch(f){showToast(t("trash_delete_failed")+": "+f.message,{type:"error"})}})}),e.querySelectorAll(".trash-preview-btn").forEach(a=>{a.addEventListener("click",()=>{_previewTrashFile(+a.dataset.id,a.dataset.name)})})}window.promptRename=function(e){openMoveDialog(e)};async function openMoveDialog(e){const n=e.split("/").pop()||e,o=e.includes("/")&&e.slice(0,e.lastIndexOf("/"))||"/";if(!document.getElementById("fd-move-style")){const h=document.createElement("style");h.id="fd-move-style",h.textContent=`
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
            .mv-tab.mv-active{background:#2563eb;color:#fff}
            .mv-tab:not(.mv-active):hover{background:#f1f5f9;color:#1e293b}
            [data-theme="dark"] .mv-tab{color:#94a3b8}
            [data-theme="dark"] .mv-tab:not(.mv-active):hover{background:#2d3f52;color:#e2e8f0}
            [data-theme="dark"] .mv-tab.mv-active{color:#fff}
            [data-theme="dark"] .mv-tree-row:hover{background:#2d3f52}
            [data-theme="dark"] .mv-tree-row.mv-selected{background:#1e3a5f}
            [data-theme="dark"] .mv-tree-row.mv-selected:hover{background:#25476f}
        `,document.head.appendChild(h)}const i=document.createElement("div");i.className="modal-overlay",i.id="mv-dialog-overlay",i.innerHTML=`
        <div class="modal-content" style="max-width:560px;width:95vw;padding:0;overflow:hidden;border-radius:14px">
            <!-- Header -->
            <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:16px 20px;display:flex;align-items:center;justify-content:space-between">
                <div>
                    <div id="mv-dialog-title" style="color:white;font-weight:700;font-size:16px">📁 ${escapeHtml(t("move_rename_copy"))}</div>
                    <div style="color:rgba(255,255,255,.75);font-size:12px;margin-top:2px;max-width:380px;
                        overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtmlAttr(e)}">${escapeHtml(e)}</div>
                </div>
                <button id="mv-close" style="background:rgba(255,255,255,.2);border:none;border-radius:50%;
                    width:30px;height:30px;color:white;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center">✕</button>
            </div>

            <!-- Tabs -->
            <div style="display:flex;gap:6px;padding:14px 20px 0">
                <button class="mv-tab mv-active" data-tab="move">✂️ ${escapeHtml(t("move"))}</button>
                <button class="mv-tab" data-tab="rename">✏️ ${escapeHtml(t("rename"))}</button>
                <button class="mv-tab" data-tab="copy">📋 ${escapeHtml(t("copy"))}</button>
            </div>

            <!-- Move/Copy tab body -->
            <div id="mv-tab-move" style="padding:14px 20px 20px">
                <div style="font-size:13px;color:#64748b;margin-bottom:8px">
                    ${escapeHtml(t("mv_select_dest"))}
                </div>
                <!-- New folder shortcut -->
                <div style="display:flex;gap:6px;margin-bottom:8px">
                    <input id="mv-new-folder-input" placeholder="${escapeHtmlAttr(t("mv_new_subfolder_ph"))}" style="flex:1;padding:5px 9px;border:1px solid #e2e8f0;border-radius:7px;font-size:13px;font-family:Inter,sans-serif;outline:none">
                    <button id="mv-new-folder-btn" style="background:#0369a1;color:white;border:none;border-radius:7px;padding:5px 12px;font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap">${escapeHtml(t("mv_new_folder_btn"))}</button>
                </div>
                <!-- Tree -->
                <div id="mv-tree" style="border:1px solid #e2e8f0;border-radius:8px;background:#f8fafc;
                    height:240px;overflow-y:auto;padding:6px 4px"></div>
                <!-- Selected path display -->
                <div style="margin-top:8px;font-size:12px;color:#64748b">
                    ${escapeHtml(t("destination"))} <span id="mv-dest-label" style="font-weight:600;color:#1e293b">/</span>
                </div>
            </div>

            <!-- Rename tab body -->
            <div id="mv-tab-rename" style="display:none;padding:14px 20px 20px">
                <label style="display:block;font-size:13px;color:#64748b;margin-bottom:6px">${escapeHtml(t("mv_new_name_label"))}</label>
                <input id="mv-name-input" type="text" value="${escapeHtmlAttr(n)}" spellcheck="false" autocomplete="off">
                <div style="font-size:12px;color:#94a3b8;margin-top:6px">${escapeHtml(t("mv_rename_hint"))}</div>
            </div>

            <!-- Footer -->
            <div style="padding:12px 20px 18px;display:flex;gap:8px;justify-content:flex-end;border-top:1px solid #f1f5f9">
                <button id="mv-cancel-btn" class="btn" style="background:#e2e8f0;color:#1e293b">${escapeHtml(t("cancel"))}</button>
                <button id="mv-confirm-btn" class="btn" style="background:#2563eb;min-width:110px">${escapeHtml(t("mv_move_here"))}</button>
            </div>
        </div>`,document.body.appendChild(i);let c="move",l=o;const r=new Map,s=h=>i.querySelector("#"+h),a=i.querySelector(".modal-content");function d(h){if(!a){h();return}const v=a.getBoundingClientRect().height;h();const _=a.getBoundingClientRect().height;if(Math.abs(v-_)<2)return;const E=a.style.overflow;a.style.overflow="hidden",a.style.height=v+"px",a.offsetHeight,a.style.transition="height .22s cubic-bezier(.4,0,.2,1)",a.style.height=_+"px";const S=T=>{T&&T.type==="transitionend"&&T.propertyName!=="height"||(a.style.transition="",a.style.height="",a.style.overflow=E,a.removeEventListener("transitionend",S))};a.addEventListener("transitionend",S),setTimeout(S,300)}function u(h){c=h,i.querySelectorAll(".mv-tab").forEach(_=>{_.classList.toggle("mv-active",_.dataset.tab===h)}),d(()=>{s("mv-tab-move").style.display=h==="move"||h==="copy"?"":"none",s("mv-tab-rename").style.display=h==="rename"?"":"none"});const v=s("mv-confirm-btn");h==="move"&&(v.textContent=t("mv_move_here"),v.style.background="#3b82f6"),h==="copy"&&(v.textContent=t("mv_copy_here"),v.style.background="#0369a1"),h==="rename"&&(v.textContent=t("mv_rename_btn"),v.style.background="#8b5cf6")}function p(){s("mv-dest-label").textContent=l||"/"}function f(h){return r.has(h)||r.set(h,{children:[],loaded:!1,expanded:!1,loading:!1}),r.get(h)}async function m(h){const v=f(h);if(!(v.loaded||v.loading)){v.loading=!0;try{const _=h==="/"?"/api/v1/list/":`/api/v1/list${encodePath(h)}`,E=await apiCall(_,"GET",null,!0);v.children=(E.entries||[]).filter(S=>S.is_dir).map(S=>S.path).sort((S,T)=>S.localeCompare(T,void 0,{sensitivity:"base"})),v.loaded=!0}catch{v.children=[],v.loaded=!0}v.loading=!1}}function y(h,v){return h.map(_=>{const E=f(_),S=_.split("/").pop()||_,T=_===l,B=E.loaded?E.children.length>0:!0,H=E.loading?"⟳":!B&&E.loaded?"·":E.expanded?"▾":"▸";return`<div class="mv-tree-row${T?" mv-selected":""}"
                        data-path="${escapeHtmlAttr(_)}"
                        style="padding-left:${8+v*16}px">
                    <button class="mv-expand-btn" data-expand="${escapeHtmlAttr(_)}">${H}</button>
                    <span class="mv-tree-label" title="${escapeHtmlAttr(_)}">📁 ${escapeHtml(S)}</span>
                </div>
                ${E.expanded&&E.children.length>0?y(E.children,v+1):""}`}).join("")}async function b(){const h=s("mv-tree");if(!h)return;const v=f("/");v.loaded||(h.innerHTML=_loadingHtml("12px"),await m("/"),v.expanded=!0),h.innerHTML=`
            <div class="mv-tree-row${l==="/"?" mv-selected":""}" data-path="/"
                style="padding-left:8px;font-weight:600">
                <button class="mv-expand-btn" data-expand="/">▾</button>
                <span class="mv-tree-label">🏠 / (root)</span>
            </div>
            ${y(v.children,1)}`,x()}function x(){const h=s("mv-tree");h&&(h.querySelectorAll(".mv-tree-row").forEach(v=>{v.addEventListener("click",_=>{_.target.classList.contains("mv-expand-btn")||(l=v.dataset.path,p(),b())})}),h.querySelectorAll(".mv-expand-btn").forEach(v=>{v.addEventListener("click",async _=>{_.stopPropagation();const E=v.dataset.expand,S=f(E);S.loaded?S.expanded=!S.expanded:(await m(E),S.expanded=!0),b()})}))}s("mv-new-folder-btn").addEventListener("click",async()=>{const h=s("mv-new-folder-input"),v=h.value.trim();if(!v)return;const _=(l.endsWith("/")?l:l+"/")+v;try{await apiCall("/api/v1/mkdir","POST",{path:_},!0),h.value="";const E=f(l);E.loaded=!1,E.expanded=!0,await m(l),l=_,p(),b()}catch(E){showMessage(t("create_folder_failed"),E.message)}}),s("mv-new-folder-input").addEventListener("keydown",h=>{h.key==="Enter"&&s("mv-new-folder-btn").click()}),i.querySelectorAll(".mv-tab").forEach(h=>{h.addEventListener("click",()=>u(h.dataset.tab))}),s("mv-confirm-btn").addEventListener("click",async()=>{const h=s("mv-confirm-btn");if(!i.isConnected)return;if(c==="rename"){const _=s("mv-name-input").value.trim();if(!_||_.includes("/")){showMessage(t("mv_invalid_name_title"),t("mv_invalid_name_body"));return}const E=o==="/"?"/"+_:o+"/"+_;h.disabled=!0,h.textContent=t("mv_renaming");const S=showSpinnerOverlay(t("mv_renaming"),{minMs:1e3});try{await withMinDelay(apiCall("/api/v1/rename","POST",{old:e,new:E}),1e3),S(),i.remove(),_dropSelectedUnder(e),_updateSelBar(),loadDirectory(currentPath)}catch(T){S(),h.disabled=!1,h.textContent=t("mv_rename_btn"),T.message!=="SESSION_EXPIRED"&&showMessage(t("mv_rename_failed_title"),T.message)}return}if(!l){showMessage(t("mv_no_destination_title"),t("mv_no_destination_body"));return}const v=(l.endsWith("/")?l:l+"/")+n;if(c==="move"){if(v===e){showMessage(t("mv_same_location_title"),t("mv_same_location_body"));return}h.disabled=!0,h.textContent=t("mv_moving");const _=showSpinnerOverlay(t("mv_moving"),{minMs:1e3});try{await withMinDelay(apiCall("/api/v1/rename","POST",{old:e,new:v}),1e3),_(),i.remove(),_dropSelectedUnder(e),_updateSelBar(),loadDirectory(currentPath)}catch(E){_(),h.disabled=!1,h.textContent=t("mv_move_here"),E.message!=="SESSION_EXPIRED"&&showMessage(t("mv_move_failed_title"),E.message)}}else{if(v===e){showMessage(t("mv_same_location_title"),t("mv_same_location_body"));return}h.disabled=!0,h.textContent=t("mv_copying");try{const _=await apiCall("/api/v1/copy","POST",{src:e,dest:v});i.remove();const E=e.split("/").filter(Boolean).pop()||e;_startCopyJobTracking(_.job_id,E)}catch(_){h.disabled=!1,h.textContent=t("mv_copy_here"),_.message!=="SESSION_EXPIRED"&&showMessage(t("mv_copy_failed_title"),_.message)}}});const k=()=>{window.fdCloseOverlay(i),_detachModalKeys()};s("mv-cancel-btn").addEventListener("click",k),s("mv-close").addEventListener("click",k);function g(){_attachModalKeys(()=>{i.isConnected&&s("mv-confirm-btn").click()},k)}i.querySelectorAll(".mv-tab").forEach(h=>{h.addEventListener("click",()=>g())}),g(),s("mv-name-input").addEventListener("keydown",h=>{h.key==="Enter"&&(h.preventDefault(),h.stopPropagation(),s("mv-confirm-btn").click())}),i.addEventListener("click",h=>{h.target===i&&k()}),p();async function w(h){const v=h.split("/").filter(Boolean);let _="/";f("/").expanded=!0,await m("/");for(const E of v){_=_==="/"?"/"+E:_+"/"+E;const S=f(_);S.expanded=!0,await m(_)}}w(o).then(()=>b())}async function promptCreateFolder(){const e=await showPromptModal({title:t("create_folder_title"),label:t("folder_name_label"),defaultValue:"NewFolder",confirmLabel:t("create")});if(e)try{let n=currentPath.endsWith("/")?currentPath+e:currentPath+"/"+e;await apiCall("/api/v1/mkdir","POST",{path:n},!0),showToast(t("folder_created_toast",{name:e})),loadDirectory(currentPath)}catch(n){try{const o=new FormData;o.append("fileToUpload",new Blob([""]),".placeholder");let i=currentPath.endsWith("/")?currentPath+e:currentPath+"/"+e;const c="/api/v1/upload/"+encodePath(i);await uploadFormData(c,o),showToast(t("folder_created_toast",{name:e})),loadDirectory(currentPath)}catch(o){showMessage(t("create_folder_failed"),n.message||String(o))}}}const ANON_TOKEN_KEY_PREFIX="fluxdrop_anon_upload_";function saveAnonDeviceToken(e,n){try{localStorage.setItem(ANON_TOKEN_KEY_PREFIX+e,n)}catch{}}function loadAnonDeviceToken(e){try{return localStorage.getItem(ANON_TOKEN_KEY_PREFIX+e)||null}catch{return null}}function removeAnonDeviceToken(e){try{localStorage.removeItem(ANON_TOKEN_KEY_PREFIX+e)}catch{}}const INTERRUPTED_KEY_PREFIX="fluxdrop_interrupted_";function saveInterruptedUpload(e,n){try{localStorage.setItem(INTERRUPTED_KEY_PREFIX+e,JSON.stringify(n))}catch{}}function loadInterruptedUpload(e){try{const n=localStorage.getItem(INTERRUPTED_KEY_PREFIX+e);return n?JSON.parse(n):null}catch{return null}}function removeInterruptedUpload(e){try{localStorage.removeItem(INTERRUPTED_KEY_PREFIX+e)}catch{}}function getAllInterruptedUploads(){const e=[];try{for(let n=0;n<localStorage.length;n++){const o=localStorage.key(n);if(o&&o.startsWith(INTERRUPTED_KEY_PREFIX))try{e.push(JSON.parse(localStorage.getItem(o)))}catch{}}}catch{}return e}function _concurrencyForSpeed(e){if(!e||e<=0)return 3;const n=e/1024;return n<100?1:n<500?2:n<2e3?3:n<5e3?4:6}function _Sha256(){const e=_Sha256.K||(_Sha256.K=new Uint32Array([1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298])),n=new Uint32Array([1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225]),o=new Uint32Array(64),i=new Uint8Array(64);let c=0,l=0;function r(s,a){for(let k=0;k<16;k++,a+=4)o[k]=s[a]<<24|s[a+1]<<16|s[a+2]<<8|s[a+3];for(let k=16;k<64;k++){const g=o[k-15],w=o[k-2];o[k]=((g>>>7|g<<25)^(g>>>18|g<<14)^g>>>3)+((w>>>17|w<<15)^(w>>>19|w<<13)^w>>>10)+o[k-7]+o[k-16]}let d=n[0],u=n[1],p=n[2],f=n[3],m=n[4],y=n[5],b=n[6],x=n[7];for(let k=0;k<64;k++){const g=x+((m>>>6|m<<26)^(m>>>11|m<<21)^(m>>>25|m<<7))+(m&y^~m&b)+e[k]+o[k]|0,w=((d>>>2|d<<30)^(d>>>13|d<<19)^(d>>>22|d<<10))+(d&u^d&p^u&p)|0;x=b,b=y,y=m,m=f+g|0,f=p,p=u,u=d,d=g+w|0}n[0]+=d,n[1]+=u,n[2]+=p,n[3]+=f,n[4]+=m,n[5]+=y,n[6]+=b,n[7]+=x}return{update(s){let a=0;if(l+=s.length,c){for(;c<64&&a<s.length;)i[c++]=s[a++];if(c<64)return;r(i,0),c=0}for(;a+64<=s.length;a+=64)r(s,a);for(;a<s.length;)i[c++]=s[a++]},hex(){const s=l*8,a=new Uint8Array((c<56?56:120)-c+8);a[0]=128;const d=Math.floor(s/4294967296),u=s>>>0,p=a.length;return a[p-8]=d>>>24,a[p-7]=d>>>16,a[p-6]=d>>>8,a[p-5]=d,a[p-4]=u>>>24,a[p-3]=u>>>16,a[p-2]=u>>>8,a[p-1]=u,this.update(a),Array.from(n,f=>f.toString(16).padStart(8,"0")).join("")}}}const _CONFLICT_PREF_KEY="fluxdrop_upload_conflict";let _conflictBatchChoice=null;function _uploadConflictPref(){const e=localStorage.getItem(_CONFLICT_PREF_KEY);return e==="rename"||e==="replace"?e:"ask"}async function _sha256OfFile(e,n,o){const i=_Sha256(),c=4*1024*1024;for(let l=0;l<e.size;l+=c){if(o&&o())return null;i.update(new Uint8Array(await e.slice(l,l+c).arrayBuffer())),n&&n(Math.min(l+c,e.size)/e.size)}return i.hex()}async function _serverSha256(e,n){let o=!1;for(let i=0;i<400;i++){if(n&&n())return null;const c=await apiCall(`/api/v1/fileinfo${encodePath(e)}`,"GET",null,!0);if(c.sha256)return c.sha256.toLowerCase();const l=c.job;if(l&&l.status==="error")throw new Error(l.error||"checksum failed");!o&&!(l&&(l.status==="pending"||l.status==="running"))&&(await apiCall("/api/v1/checksums/compute","POST",{path:e,algos:["sha256"]},!0),o=!0),await new Promise(r=>setTimeout(r,1500))}throw new Error("timed out")}function _askUploadConflict(e,n,o){return new Promise(i=>{const c=o.existing||{},l=(window._uploadQueue||[]).length;let r=!1;const s=document.createElement("div");s.className="modal-overlay",s.id="fd-conflict-overlay";const a="padding:6px 10px;border-bottom:1px solid var(--fd-border,#e2e8f0)",d=c.size===e.size;s.innerHTML=`
            <div class="modal-content" style="max-width:520px;width:95vw">
                <h3 style="margin:0 0 6px;font-size:17px">${escapeHtml(t("conflict_title"))}</h3>
                <p style="margin:0 0 12px;font-size:13px;color:#64748b">${escapeHtml(t("conflict_body",{name:c.name||e.name}))}</p>
                <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:10px">
                    <tr><td style="${a}"></td>
                        <th style="${a};text-align:left">${escapeHtml(t("conflict_existing"))}</th>
                        <th style="${a};text-align:left">${escapeHtml(t("conflict_new"))}</th></tr>
                    <tr><td style="${a};color:#64748b">${escapeHtml(t("file_info_size"))}</td>
                        <td style="${a}">${formatBytes(c.size||0)}</td>
                        <td style="${a}${d?"":";font-weight:600"}">${formatBytes(e.size)}</td></tr>
                    <tr><td style="${a};color:#64748b">${escapeHtml(t("file_info_modified"))}</td>
                        <td style="${a}">${escapeHtml(formatMtime(c.mtime?c.mtime*1e3:0))}</td>
                        <td style="${a}">${escapeHtml(formatMtime(e.lastModified))}</td></tr>
                </table>
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;font-size:13px">
                    <button id="fd-cf-compare" class="btn" style="background:#e2e8f0;color:#1e293b;padding:4px 10px;font-size:12px">${escapeHtml(t("conflict_compare"))}</button>
                    <span id="fd-cf-result" style="color:#64748b"></span>
                </div>
                ${l?`<label style="display:flex;gap:6px;align-items:center;font-size:13px;margin-bottom:12px">
                    <input type="checkbox" id="fd-cf-all"> ${escapeHtml(t("conflict_apply_all",{n:l}))}</label>`:""}
                <div style="display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end">
                    <button id="fd-cf-skip" class="btn" style="background:#e2e8f0;color:#1e293b">${escapeHtml(t("conflict_skip"))}</button>
                    <button id="fd-cf-rename" class="btn" style="background:#0369a1"
                        title="${escapeHtmlAttr(o.suggested_name||"")}">${escapeHtml(t("conflict_keep_both"))}</button>
                    <button id="fd-cf-replace" class="btn" style="background:#b45309"
                        title="${escapeHtmlAttr(t("conflict_replace_hint"))}">${escapeHtml(t("conflict_replace"))}</button>
                </div>
            </div>`,document.body.appendChild(s);const u=f=>{r=!0,_detachModalKeys();const m=!!s.querySelector("#fd-cf-all")?.checked;window.fdCloseOverlay?window.fdCloseOverlay(s):s.remove(),i({choice:f,all:m})};s.querySelector("#fd-cf-skip").addEventListener("click",()=>u("skip")),s.querySelector("#fd-cf-rename").addEventListener("click",()=>u("rename")),s.querySelector("#fd-cf-replace").addEventListener("click",()=>u("replace")),_attachModalKeys(()=>u("rename"),()=>u("skip"));const p=s.querySelector("#fd-cf-result");s.querySelector("#fd-cf-compare").addEventListener("click",async f=>{if(f.currentTarget.disabled=!0,!d){p.textContent=t("conflict_differ_size");return}try{p.textContent=t("conflict_hashing",{pct:0});const[m,y]=await Promise.all([_sha256OfFile(e,b=>{r||(p.textContent=t("conflict_hashing",{pct:Math.floor(b*100)}))},()=>r),_serverSha256(n,()=>r)]);if(r||!m||!y)return;p.textContent=m===y?t("conflict_identical"):t("conflict_differ"),p.style.color=m===y?"#16a34a":"#dc2626"}catch(m){r||(p.textContent=t("conflict_compare_failed",{error:m.message||String(m)}))}})})}let _lastUploadSpeed=null;async function uploadChunked(e,n,o={}){const i=o.ownerType||"user",c=o.shareToken||"";function l($){const L={};return authToken&&(L.Authorization=`Bearer ${authToken}`),$&&(L["X-Anon-Device-Token"]=$),L}let r,s,a,d,u,p=null,f=null;if(o.resumeToken)r=o.resumeToken,s=o.resumeAnonToken||loadAnonDeviceToken(r)||null,a=o.resumeChunkSize||1*1024*1024,d=e.size===0?0:Math.ceil(e.size/a)||1,u=o.resumeFromChunk||0;else{const z=e.size<26214400,C=_lastUploadSpeed&&Date.now()-_lastUploadSpeed.at<10*6e4?_lastUploadSpeed.bps:null,[M,O]=await Promise.allSettled([fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/config`,{headers:l(null)}).then(F=>F.ok?F.json():null).catch(()=>null),(async()=>{if(z)return C;const F=new Uint8Array(524288),Q=performance.now(),ae=await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/speed_probe`,{method:"POST",headers:{"Content-Type":"application/octet-stream","Content-Length":String(524288),...l(null)},body:F}),ge=(performance.now()-Q)/1e3;return ae.ok&&ge>0?524288/ge:null})()]),I=M.status==="fulfilled"?M.value:null,D=O.status==="fulfilled"?O.value:null;let U=I&&I.chunk_size?I.chunk_size:1*1024*1024;const ie=20,P=32*1024,R=I&&I.max_chunk_size?I.max_chunk_size:U,ke=_concurrencyForSpeed(D),ue=D?D/ke:null;let Z=null;ue&&(Z=Math.round(Math.max(P,Math.min(ue*ie,R)))),!Z&&z&&(Z=Math.min(1*1024*1024,R));const $e=Z||U,Ee=e.size===0?0:Math.ceil(e.size/$e)||1,fe={filename:e.name,dest_path:n,total_size:e.size,total_chunks:Ee,preferred_chunk_size:Z,sha256:null,owner_type:i,share_token:c,on_conflict:_conflictBatchChoice==="skip"?"ask":_conflictBatchChoice||_uploadConflictPref()},me=()=>fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/init`,{method:"POST",headers:{"Content-Type":"application/json",...l(null)},body:JSON.stringify(fe)});let W=await me();if(W.ok){const F=await W.clone().json().catch(()=>({}));if(F.conflict){const{choice:Q,all:ae}=_conflictBatchChoice==="skip"?{choice:"skip",all:!0}:await _askUploadConflict(e,n,F);if(ae&&(_conflictBatchChoice=Q),Q==="skip")throw new Error("Upload cancelled");fe.on_conflict=Q,W=await me()}}if(!W.ok){const F=await W.json().catch(()=>({}));throw new Error(F.error||`Init failed: HTTP ${W.status}`)}const ee=await W.json();r=ee.upload_token,f=ee.filename||null,a=ee.chunk_size||U,d=e.size===0?0:Math.ceil(e.size/a)||1,u=0,s=ee.anon_device_token||null,s&&saveAnonDeviceToken(r,s),p=D}let m=[];for(let $=u;$<d;$++)m.push($);if(o.resumeToken){for(const $ of activeUploads.values())if($.uploadToken===r){$.status="connecting",renderUploadTray();break}try{const $=await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${r}/status`,{headers:l(s),signal:AbortSignal.timeout(15e3)});if($.ok){const L=await $.json();Array.isArray(L.missing_chunks)&&(m=L.missing_chunks.filter(z=>z<d).sort((z,C)=>z-C))}}catch{}}const y=$=>Math.max(0,Math.min(a,e.size-$*a)),b=e.size-m.reduce(($,L)=>$+y(L),0);let x=o.reuseId;if(x==null&&o.resumeToken){for(const[$,L]of activeUploads)if(L.uploadToken===o.resumeToken){x=$;break}}const k=x??++uploadIdCounter,g=activeUploads.get(k)||{filename:f||e.name,loaded:b,total:e.size,status:"uploading",speed:null,eta:null,error:null,measuredSpeed:p,paused:!1,cancelled:!1,abortController:null,uploadToken:r,anonDeviceToken:s,chunkSize:a,totalChunks:d,nextChunk:u,destRel:n,ownerType:i,shareToken:c,file:e};g.status="uploading",g.paused=!1,g.cancelled=!1,g.uploadToken=r,g.anonDeviceToken=s,g.chunkSize=a,g.totalChunks=d,g.nextChunk=m.length?m[0]:d,g.loaded=b,p&&(g.measuredSpeed=p),activeUploads.set(k,g);const w=g.runId=(g.runId||0)+1,h=()=>g.runId!==w;i==="user"&&saveInterruptedUpload(r,{uploadToken:r,filename:e.name,destRel:n,totalChunks:d,chunkSize:a,nextChunkIdx:g.nextChunk,ownerType:i,shareToken:c,anonDeviceToken:null,total:e.size}),g.measuredSpeed&&g.measuredSpeed>0&&(g.speed=g.measuredSpeed),renderUploadTray();const v=1,_=6;let E=_concurrencyForSpeed(g.measuredSpeed),S=0,T=null,B=g.speed||0,H=null;function X(){H||(H=setInterval(()=>{if(g.cancelled||N){clearInterval(H),H=null;return}if(g.paused)return;const $=g.speed||0;if(B>0&&$>0){const L=$/B;L<.85&&E>v?E=Math.max(v,E-1):L>=.95&&E<_&&S<E+1&&m.length>0&&(E++,T&&T())}B=$},3e3))}const A=new Map;let q=b,j=Date.now(),re=q;const se=.25,ye=800;function te($){q=Math.max(0,Math.min(e.size,q+$)),g.loaded=q;const L=Date.now(),z=L-j;if(z>=ye){const C=(q-re)/(z/1e3);C>0&&(g.speed=g.speed!=null?se*C+(1-se)*g.speed:C,g.eta=(e.size-q)/g.speed),re=q,j=L}renderUploadTray()}async function be($){const L=await $.arrayBuffer(),z=await crypto.subtle.digest("SHA-256",L);return Array.from(new Uint8Array(z)).map(C=>C.toString(16).padStart(2,"0")).join("")}async function le($){const L=$*a,z=e.slice(L,L+a);let C=null;try{C=await be(z)}catch{}if(g.paused||g.cancelled||h()){const M=new Error("Upload cancelled");throw M.name="AbortError",M}return new Promise((M,O)=>{const I=new XMLHttpRequest;A.set($,I),g.abortController={abort:()=>{A.forEach(P=>P.abort())}};let D=0;function U(){D>0&&(te(-D),D=0)}I.upload.onprogress=P=>{if(!P.lengthComputable)return;const R=P.loaded-D;D=P.loaded,R>0&&te(R)},I.onload=()=>{if(A.delete($),I.status>=200&&I.status<300){const P=z.size-D;P>0&&te(P),renderUploadTray(),M()}else{U(),renderUploadTray();let P=`Chunk ${$} failed: HTTP ${I.status}`;try{const R=JSON.parse(I.responseText);R.error&&(P=R.error)}catch{}O(new Error(P))}},I.onerror=()=>{A.delete($),U(),renderUploadTray(),O(new Error(`Chunk ${$} network error`))},I.onabort=()=>{A.delete($),U(),renderUploadTray();const P=new Error("Upload cancelled");P.name="AbortError",O(P)},I.open("POST",`${API_BASE_URL}/api/v1/upload_session/${r}/chunk/${$}`),I.setRequestHeader("Content-Type","application/octet-stream"),C&&I.setRequestHeader("X-Chunk-SHA256",C);const ie=l(s);for(const[P,R]of Object.entries(ie))I.setRequestHeader(P,R);I.timeout=9e4,I.ontimeout=()=>{A.delete($),U(),renderUploadTray(),O(new Error(`Chunk ${$} timed out`))},I.send(z)})}let N=null;const K=new Set;function he($){K.delete($),m.includes($)||(m.push($),m.sort((L,z)=>L-z))}function xe(){let $=m.length?m[0]:d;return K.forEach(L=>{L<$&&($=L)}),$}function ne(){g.nextChunk=xe(),i==="user"&&saveInterruptedUpload(r,{uploadToken:r,filename:e.name,destRel:n,totalChunks:d,chunkSize:a,nextChunkIdx:g.nextChunk,ownerType:i,shareToken:c,anonDeviceToken:null,total:e.size})}function G($){return!g.paused&&!h()?!1:(he($),!0)}async function ve(){for(;;){if(g.cancelled||g.paused||N||h()||!m.length)return;const $=m.shift();K.add($),ne();try{await le($),K.delete($)}catch(L){if(L.name==="AbortError"){G($)||(g.cancelled=!0);return}if(g.cancelled||G($))return;const z=3;let C=L;for(let M=1;M<=z;M++){if(g.cancelled)return;const O=1500*M;g.status="uploading",g._retrying=!0;for(let I=Math.round(O/1e3);I>0;I--){if(g.cancelled)return;if(G($)){g._retrying=!1,g.error=null;return}g.error=`Chunk ${$} failed. Retry ${M}/${z} in ${I}s…`,renderUploadTray(),await new Promise(D=>setTimeout(D,1e3))}if(g._retrying=!1,g.cancelled)return;if(G($)){g.error=null;return}try{await le($),K.delete($),C=null,g.error=null,g._retrying=!1;break}catch(I){if(C=I,I.name==="AbortError"){G($)||(g.cancelled=!0);return}}}if(C){N=C,g.error=C.message,ne();return}}}}function _e(){return X(),new Promise($=>{let L=!1;function z(){!L&&S===0&&(L=!0,clearInterval(H),H=null,$())}T=function(){if(g.cancelled||N||!m.length){z();return}S++,ve().finally(()=>{S--,z()})};const C=Math.min(E,m.length);for(let M=0;M<C;M++)T();C===0&&z()})}for(let $=0;await _e(),!(h()||g.paused||g.cancelled||N||$>=2||d===0);$++){let L=[];try{const z=await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${r}/status`,{headers:l(s)});if(z.ok){const C=await z.json();Array.isArray(C.missing_chunks)&&(L=C.missing_chunks)}}catch{}if(!L.length)break;console.warn(`Upload ${r.slice(0,12)}…: server is missing chunks ${L.slice(0,10)}, re-sending`),m=L.filter(z=>z<d).sort((z,C)=>z-C),K.clear(),q=Math.max(0,q-m.reduce((z,C)=>z+y(C),0)),g.loaded=q}if(h()){const $=new Error("Upload paused");throw $.name="PauseSignal",$}if(g.paused&&!g.cancelled){ne();const $=new Error("Upload paused");throw $.name="PauseSignal",$}if(g.cancelled){g.status="cancelling",renderUploadTray();try{await Promise.race([fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${r}/cancel`,{method:"DELETE",headers:l(s)}),new Promise($=>setTimeout($,5e3))])}catch{}throw g.status="cancelled",removeInterruptedUpload(r),s&&removeAnonDeviceToken(r),renderUploadTray(),new Error("Upload cancelled")}if(N)throw g.status="error",g.error=N.message,renderUploadTray(),s&&removeAnonDeviceToken(r),N;g.speed>0&&(_lastUploadSpeed={bps:g.speed,at:Date.now()}),g.status="verifying",g.speed=null,g.eta=null,g.verifyPct=0,g.verifyEta=null,g.verifyBytes=0,g.verifyTotal=e.size,renderUploadTray();let V=null,Y=null,oe=0,de=Date.now();const ce=.3;function we(){V||(V=setInterval(async()=>{try{const $=await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${r}/assembly_progress`,{headers:l(s)});if(!$.ok)return;const L=await $.json();if(L.error){clearInterval(V);return}g.verifyPct=L.pct||0,g.verifyBytes=L.bytes_hashed||0,g.verifyTotal=L.total_bytes||e.size;const z=Date.now(),C=(z-de)/1e3;if(C>=.5&&g.verifyBytes>oe){const M=(g.verifyBytes-oe)/C;Y=Y!=null?ce*M+(1-ce)*Y:M,g.verifyEta=Y>0?(g.verifyTotal-g.verifyBytes)/Y:null,oe=g.verifyBytes,de=z}renderUploadTray(),L.done&&(clearInterval(V),V=null)}catch{}},500))}we();const J=await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${r}/complete`,{method:"POST",headers:l(s)});if(clearInterval(V),!J.ok){const $=await J.json().catch(()=>({}));throw g.status="error",g.error=$.error||`Complete failed: HTTP ${J.status}`,renderUploadTray(),s&&removeAnonDeviceToken(r),new Error(g.error)}g.loaded=e.size,g.status="done";const pe=getTrayDismissDelay();return pe>0&&!g._dismissScheduled&&(g._dismissScheduled=!0,setTimeout(()=>{activeUploads.delete(k),renderUploadTray()},pe)),g.speed=null,g.eta=null,renderUploadTray(),removeInterruptedUpload(r),s&&removeAnonDeviceToken(r),await J.json()}function windowLock(){event.preventDefault(),event.returnValue=""}async function handleUploadForm(e){e.preventDefault(),window.addEventListener("beforeunload",windowLock);const n=document.getElementById("upload-file");if(!n.files.length){showMessage(t("upload_title"),t("upload_no_file"));return}const o=Array.from(n.files),i=document.getElementById("upload-protected").checked;if(currentPath.startsWith("/cdn")){window.removeEventListener("beforeunload",windowLock),showMessage(t("upload_title"),t("cdn_upload_unavailable"));return}const c="user",l=document.getElementById("btn-upload-submit"),r=document.getElementById("upload-spinner");function s(){l&&(l.disabled=!0,l.style.opacity="0.6"),r&&(r.style.display="inline")}function a(){l&&(l.disabled=!1,l.style.opacity=""),r&&(r.style.display="none")}s();const d=currentPath.endsWith("/")?currentPath:currentPath+"/",u=o.map(f=>{const m=f.webkitRelativePath||f.name;return{file:f,destRel:d+m,ownerType:c,isProtected:i}});if(u.length===1)try{const f=uploadChunked(u[0].file,u[0].destRel,{ownerType:c});setTimeout(a,600),await f,a(),_notifyUploadDone(1),showMessage(t("upload_successful"),t("upload_success_msg",{name:u[0].file.name})),window.removeEventListener("beforeunload",windowLock),loadDirectory(currentPath)}catch(f){if(a(),f.name==="PauseSignal"||f.message==="Upload cancelled")return;showMessage(t("upload_failed"),f.message||String(f))}else{let k=function(){_notifyUploadDone(b,x),_lastUploadBatchCount=0,window.removeEventListener("beforeunload",windowLock)};var p=k;const[f,...m]=u;window._uploadQueue=[...window._uploadQueue||[],...m];const y=()=>{const w=document.getElementById("btn-show-queue"),h=document.getElementById("queue-count");if(w&&h){const v=window._uploadQueue;v.length>0?(w.classList.remove("hidden"),h.textContent=v.length):w.classList.add("hidden")}};y(),setTimeout(a,400),_lastUploadBatchCount+=u.length;let b=0,x=0;async function g(w){let h=w;for(;h;){try{await uploadChunked(h.file,h.destRel,{ownerType:h.ownerType}),b++,loadDirectory(currentPath)}catch(v){if(v.name==="PauseSignal"){_pausedQueueDrain=()=>{_pausedQueueDrain=null;let _=null;window._uploadQueue&&window._uploadQueue.length>0&&(_=window._uploadQueue.shift(),y()),_?g(_):k()};return}v.message!=="Upload cancelled"&&(x++,showMessage(t("upload_failed"),`${h.file.name}: ${v.message||String(v)}`),window.removeEventListener("beforeunload",windowLock))}window._uploadQueue&&window._uploadQueue.length>0?(h=window._uploadQueue.shift(),y()):(h=null,k())}}g(f),showMessage(t("queued"),t("upload_queued_msg",{n:o.length}))}n.value=""}const activeUploads=new Map;let uploadIdCounter=0;function formatSpeed(e){return e<1024?e.toFixed(0)+" B/s":e<1048576?(e/1024).toFixed(1)+" KB/s":e<1073741824?(e/1048576).toFixed(1)+" MB/s":(e/1073741824).toFixed(2)+" GB/s"}function formatEta(e){if(!isFinite(e)||e<0)return"…";const n=t("unit_s"),o=t("unit_m"),i=t("unit_h");return e<60?Math.ceil(e)+n:e<3600?Math.floor(e/60)+o+" "+Math.ceil(e%60)+n:Math.floor(e/3600)+i+" "+Math.floor(e%3600/60)+o}function renderUploadTray(){let e=document.getElementById("ul-tray");if(e||(e=document.createElement("div"),e.id="ul-tray",e.style.cssText=`
            position:fixed; bottom:0; left:1rem; width:340px; max-height:60vh;
            overflow-y:auto; background:#1e293b; border-radius:12px 12px 0 0;
            box-shadow:0 -4px 24px rgba(0,0,0,0.4); z-index:9000;
            font-family:Inter,sans-serif; font-size:13px; color:#e2e8f0;
        `,document.body.appendChild(e),e.classList.add("fd-tray-in"),e.addEventListener("animationend",()=>e.classList.remove("fd-tray-in"),{once:!0})),activeUploads.size===0){e.innerHTML.trim()!==""&&window.fdCollapseTray(e).then(()=>{activeUploads.size===0&&(e.innerHTML="")});return}e.classList.remove("fd-tray-closing");let n=e.querySelector(".ul-tray-header");n||(n=document.createElement("div"),n.className="ul-tray-header",n.style.cssText="padding:10px 14px 6px;font-weight:700;font-size:14px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center;",n.innerHTML='<span class="ul-count"></span><span style="cursor:pointer;opacity:.6" id="ul-tray-close">✕</span>',e.prepend(n),n.querySelector("#ul-tray-close").addEventListener("click",async()=>{await window.fdCollapseTray(e),e.innerHTML=""})),n.querySelector(".ul-count").textContent=t("tray_uploads",{n:activeUploads.size}),e.querySelectorAll(".ul-row").forEach(o=>{activeUploads.has(+o.dataset.ulId)||o.remove()});for(const[o,i]of activeUploads){const c=i.total?Math.round(i.loaded/i.total*100):0,l=formatBytes(i.loaded),r=i.total?formatBytes(i.total):"?";let s=e.querySelector(`.ul-row[data-ul-id="${+o}"]`);if(!s){s=document.createElement("div"),s.className="ul-row",s.dataset.ulId=o,s.style.cssText="padding:10px 14px;border-bottom:1px solid #1e293b",s.innerHTML=`
                <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                    <span class="ul-name" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:160px"></span>
                    <span class="ul-bytes" style="color:#94a3b8"></span>
                </div>
                <div style="background:#334155;border-radius:4px;height:6px;margin-bottom:6px">
                    <div class="ul-bar" style="background:#15803d;height:6px;border-radius:4px;width:0%;transition:width .2s"></div>
                </div>
                <div style="display:flex;justify-content:space-between;align-items:center">
                    <span class="ul-status" style="color:#64748b"></span>
                    <div class="ul-actions"></div>
                </div>`,e.appendChild(s),requestAnimationFrame(()=>{e.scrollTop=e.scrollHeight});const b=s.querySelector(".ul-actions"),x=document.createElement("button");x.textContent=t("dl_dismiss"),x.style.cssText="background:#64748b;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px",x.addEventListener("click",()=>{activeUploads.delete(o),renderUploadTray()});const k=document.createElement("button");k.textContent="⏸ "+t("ul_pause"),k.style.cssText="background:#f59e0b;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px",k.addEventListener("click",()=>{i.paused=!0,i.status="paused",i.abortController&&i.abortController.abort(),renderUploadTray()});const g=document.createElement("button");g.textContent="▶ "+t("im_resume"),g.style.cssText="background:#15803d;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px",g.addEventListener("click",()=>{i.paused=!1,i.cancelled=!1,i.status="uploading",renderUploadTray(),uploadChunked(i.file,i.destRel,{ownerType:i.ownerType,shareToken:i.shareToken,resumeToken:i.uploadToken,resumeFromChunk:i.nextChunk,resumeChunkSize:i.chunkSize,resumeAnonToken:i.anonDeviceToken,reuseId:o}).then(()=>{loadDirectory(currentPath),_pausedQueueDrain&&_pausedQueueDrain()}).catch(h=>{if(h.name!=="PauseSignal"){if(h.message==="Upload cancelled"){_pausedQueueDrain&&_pausedQueueDrain();return}showMessage(t("upload_failed"),h.message),_pausedQueueDrain&&_pausedQueueDrain()}})});const w=document.createElement("button");w.textContent="✕ "+t("ul_cancel"),w.style.cssText="background:#dc2626;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px;margin-left:4px",w.addEventListener("click",()=>{const h=i.paused;if(i.status="cancelling",renderUploadTray(),i.cancelled=!0,i.paused=!1,i.abortController&&i.abortController.abort(),!h)return;const v={};authToken&&(v.Authorization=`Bearer ${authToken}`),i.anonDeviceToken&&(v["X-Anon-Device-Token"]=i.anonDeviceToken),Promise.race([fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${i.uploadToken}/cancel`,{method:"DELETE",headers:v}),new Promise(_=>setTimeout(_,5e3))]).catch(()=>{}).then(_=>{i.status=_&&_.status===409?"done":"cancelled",removeInterruptedUpload(i.uploadToken),i.anonDeviceToken&&removeAnonDeviceToken(i.uploadToken),renderUploadTray(),_pausedQueueDrain&&_pausedQueueDrain()})}),b.appendChild(k),b.appendChild(g),b.appendChild(w),b.appendChild(x),s._dismissBtn=x,s._pauseBtn=k,s._resumeBtn=g,s._cancelBtn=w,s._actionsDiv=b}const a={uploading:"⬆",connecting:"⏳",verifying:"🔍",done:"✅",error:"⚠",paused:"⏸",cancelling:"⏳",cancelled:"🚫"};s.querySelector(".ul-name").textContent=(a[i.status]||"")+" "+i.filename,s.querySelector(".ul-bytes").textContent=`${l} / ${r}`;const d=s.querySelector(".ul-bar"),u=i.status==="verifying"&&i.verifyPct!=null&&i.verifyPct>0?i.verifyPct:c;d.style.width=u+"%",d.style.background=i._retrying||i.status==="paused"||i.status==="cancelling"?"#f59e0b":i.status==="error"||i.status==="cancelled"?"#ef4444":i.status==="verifying"?"#a78bfa":"#22c55e",d.style.animation=i._retrying?"fd-retry-pulse 1s ease-in-out infinite":"";let p=i.status;if(i.status==="uploading"){const b=[];i.speed!=null&&b.push(formatSpeed(i.speed)),i.eta!=null&&b.push(t("tray_eta",{t:formatEta(i.eta)})),b.length?p=b.join(" · "):i._retrying&&i.error&&(p="🔄 "+i.error)}else if(i.status==="verifying")if(i.verifyPct!=null&&i.verifyPct>0){const b=[t("ul_verifying_pct",{pct:i.verifyPct.toFixed(0)})];i.verifyEta!=null&&b.push(t("tray_eta",{t:formatEta(i.verifyEta)})),i.verifyBytes&&i.verifyTotal&&b.push(`${formatBytes(i.verifyBytes)} / ${formatBytes(i.verifyTotal)}`),p=b.join(" · ")}else p=t("ul_verifying");else i.status==="connecting"?p=t("ul_connecting"):i.status==="paused"?p=t("ul_paused_hint"):i.status==="cancelling"?p=t("ul_cancelling"):i.status==="error"?p="⚠ "+(i.error||t("tray_failed")):i.status==="cancelled"?p=t("ul_cancelled"):i.status==="done"&&(p=t("tray_done"));s.querySelector(".ul-status").textContent=p;const f=i.status==="uploading"||i.status==="verifying",m=i.status==="paused",y=i.status==="done"||i.status==="error"||i.status==="cancelled";s._pauseBtn.style.display=f?"":"none",s._resumeBtn.style.display=m?"":"none",s._cancelBtn.style.display=f||m?"":"none",s._dismissBtn.style.display=y?"":"none"}}function uploadFormData(e,n){return new Promise((o,i)=>{const c=++uploadIdCounter,r={filename:(()=>{for(const[,p]of n.entries())if(p instanceof File)return p.name;return"file"})(),loaded:0,total:0,status:"uploading",speed:null,eta:null,error:null};activeUploads.set(c,r),renderUploadTray();const s=new XMLHttpRequest;let a=Date.now(),d=0,u=a;s.upload.addEventListener("progress",p=>{r.loaded=p.loaded,r.total=p.total||0;const f=Date.now(),m=(f-u)/1e3;if(m>=.5){const y=p.loaded-d;r.speed=y/m,r.eta=r.speed>0&&r.total?(r.total-p.loaded)/r.speed:null,d=p.loaded,u=f}renderUploadTray()}),s.addEventListener("load",()=>{if(s.status>=200&&s.status<300){r.loaded=r.total,r.status="done";const p=getTrayDismissDelay();p>0&&!r._dismissScheduled&&(r._dismissScheduled=!0,setTimeout(()=>{activeUploads.delete(c),renderUploadTray()},p)),r.speed=null,r.eta=null,renderUploadTray();try{o(JSON.parse(s.responseText))}catch{o(s.responseText)}}else r.status="error",r.error=`HTTP ${s.status}`,renderUploadTray(),i(new Error(`Upload failed: ${s.status}`))}),s.addEventListener("error",()=>{const p=new XMLHttpRequest;p.upload.addEventListener("progress",f=>{r.loaded=f.loaded,r.total=f.total||0,renderUploadTray()}),p.addEventListener("load",()=>{if(p.status>=200&&p.status<300){r.loaded=r.total,r.status="done";const f=getTrayDismissDelay();f>0&&!r._dismissScheduled&&(r._dismissScheduled=!0,setTimeout(()=>{activeUploads.delete(c),renderUploadTray()},f)),r.speed=null,r.eta=null,renderUploadTray();try{o(JSON.parse(p.responseText))}catch{o(p.responseText)}}else r.status="error",r.error=`HTTP ${p.status}`,renderUploadTray(),i(new Error(`Upload failed: ${p.status}`))}),p.addEventListener("error",()=>{r.status="error",r.error="Network error",renderUploadTray(),i(new Error("Upload failed: network error"))}),authToken&&p.setRequestHeader("Authorization",`Bearer ${authToken}`),p.open("POST",`${API_HTTP}${e}`),authToken&&p.setRequestHeader("Authorization",`Bearer ${authToken}`),p.send(n)}),s.open("POST",`${API_BASE_URL}${e}`),authToken&&s.setRequestHeader("Authorization",`Bearer ${authToken}`),s.send(n)})}async function handleRegister(e){e.preventDefault();const n=document.getElementById("reg-username").value,o=document.getElementById("reg-nickname").value,i=document.getElementById("reg-email").value,c=document.getElementById("reg-password").value,l=e.target.querySelector('button[type="submit"]'),r=l?l.textContent:"";l&&(l.disabled=!0,l.innerHTML=`<span class="fd-btn-spin" aria-hidden="true"></span>${t("registering")}`);const s=showSpinnerOverlay(t("registering"),{minMs:600});try{await apiCall("/auth/register","POST",{username:n,nickname:o,email:i,password:c},!1),s(),showMessage(t("register_success_title"),t("register_success_body"));const a=document.getElementById("fd-auth-modal");a?a.querySelector("#fd-tab-login")?.click():renderApp("login")}catch(a){s(),showMessage(t("register_failed_title"),a.message)}finally{l&&(l.disabled=!1,l.textContent=r)}}async function handleLogin(e){e.preventDefault();const n=document.getElementById("username").value,o=document.getElementById("password").value;try{const i=await apiCall("/auth/login","POST",{username:n,password:o},!1);authToken=i.token,currentUsername=i.username,localStorage.getItem("fluxdrop_last_user")!==i.username&&_resetBrowsePath(),localStorage.setItem("fluxdrop_last_user",i.username),isAdmin=!!i.is_admin,_canPublish=null,localStorage.removeItem("fluxdrop_lang_synced");{const r=document.getElementById("btn-browse-cdn");r&&(r.style.display=isAdmin?"":"none")}localStorage.setItem("fluxdrop_token",authToken),localStorage.setItem("fluxdrop_is_admin",i.is_admin?"1":"0"),localStorage.setItem("fluxdrop_username",currentUsername),_syncLangToServer(),i.id?localStorage.setItem("fluxdrop_user_id",String(i.id)):localStorage.removeItem("fluxdrop_user_id");const c=document.getElementById("fd-auth-modal");c&&window.fdCloseOverlay(c),delete appRoot.dataset.fdLanding;const l=`fluxdrop_welcomed_${currentUsername}`;localStorage.getItem(l)?renderApp():(localStorage.setItem(l,"1"),renderApp(),_showWelcomeScreen())}catch(i){showMessage(t("login_failed"),i.message)}}function _showWelcomeScreen(){const e=()=>{if(document.querySelector('[id^="pam-"]')?.closest('[style*="z-index:10001"]')){setTimeout(e,400);return}_doShowWelcome()};setTimeout(e,300)}function _doShowWelcome(){const e=document.createElement("div");e.id="fd-welcome-overlay",e.style.cssText=["position:fixed;top:0;left:0;width:100%;height:100%;z-index:10200","background:rgba(15,23,42,.72);display:flex;align-items:center;justify-content:center;padding:1rem","animation:fadeIn .25s ease"].join(";");const n=[["📁",t("welcomer_card_lable1"),t("welcomer_card_desc1")],["⬆",t("welcomer_card_lable2"),t("welcomer_card_desc2")],["📁➡📄",t("welcomer_card_lable3"),t("welcomer_card_desc3")],["👁",t("welcomer_card_lable4"),t("welcomer_card_desc4")],["🔗",t("welcomer_card_lable5"),t("welcomer_card_desc5")],["🗑",t("welcomer_card_lable6"),t("welcomer_card_desc6",{days:_lastKnownRetentionDays})],["⬇",t("welcomer_card_lable7"),t("welcomer_card_desc7")],["🔒",t("welcomer_card_lable8"),t("welcomer_card_desc8")],["👤",t("welcomer_card_lable9"),t("welcomer_card_desc9")],...isAdmin?[["📡",t("welcomer_card_lable10"),t("welcomer_card_desc10")]]:[]];if(e.setAttribute("role","dialog"),e.setAttribute("aria-modal","true"),e.setAttribute("aria-labelledby","fd-welcome-title"),e.innerHTML=`
        <div style="background:#fff;border-radius:1.25rem;width:100%;max-width:740px;
                    max-height:92vh;display:flex;flex-direction:column;overflow:hidden;
                    box-shadow:0 32px 64px rgba(0,0,0,.45)">
            <!-- Header -->
            <div style="background:linear-gradient(135deg,#1e40af,#4f46e5);padding:1.75rem 2rem 1.5rem;flex-shrink:0">
                <div style="display:flex;align-items:center;gap:.9rem;margin-bottom:.5rem">
                    <img src="/fluxdrop_pp/icon-128.png" width="44" height="44" style="width:44px;height:44px" alt="">
                    <h2 id="fd-welcome-title" style="color:white;font-size:1.55rem;font-weight:800;margin:0">${t("welcomer_lable")}</h2>
                </div>
                <p style="color:rgba(255,255,255,.82);margin:0;font-size:.95rem;line-height:1.6">
                    ${t("welcomer_desc")}
                </p>
            </div>
            <!-- Feature grid -->
            <div tabindex="0" style="overflow-y:auto;flex:1;padding:1.5rem 2rem">
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem">
                    ${n.map(([o,i,c])=>`
                        <div style="display:flex;gap:.75rem;padding:.9rem 1rem;background:#f8fafc;
                                    border-radius:.75rem;border:1px solid #e2e8f0;align-items:flex-start">
                            <div aria-hidden="true" style="font-size:1.4rem;flex-shrink:0;line-height:1;margin-top:.1rem">${o}</div>
                            <div>
                                <div style="font-weight:700;color:#1e293b;font-size:.95rem;margin-bottom:.25rem">${i}</div>
                                <div style="color:#475569;font-size:.85rem;line-height:1.55">${c}</div>
                            </div>
                        </div>`).join("")}
                </div>
                <div style="margin-top:1.25rem;padding:1rem 1.25rem;background:#eff6ff;border-radius:.75rem;
                            border:1px solid #bfdbfe;font-size:.88rem;color:#1e40af;line-height:1.6">
                    ${t("welcomer_tip")}
                </div>
            </div>
            <!-- Footer -->
            <div style="padding:1rem 2rem;border-top:1px solid #e2e8f0;display:flex;justify-content:flex-end;flex-shrink:0">
                <button id="fd-welcome-ok" class="btn" style="padding:.7rem 2rem;font-size:.95rem">
                    ${t("welcomer_btn")}
                </button>
            </div>
        </div>`,e.querySelectorAll("a[data-policy]").forEach(o=>{o.href="#",o.style.cssText="color:inherit;text-decoration:underline",o.addEventListener("click",i=>{i.preventDefault(),e.remove(),showPolicyModal(o.dataset.policy)})}),!document.getElementById("fd-fadein-style")){const o=document.createElement("style");o.id="fd-fadein-style",o.textContent="@keyframes fadeIn{from{opacity:0}to{opacity:1}}",document.head.appendChild(o)}document.body.appendChild(e),e.querySelector("#fd-welcome-ok").addEventListener("click",()=>e.remove()),e.addEventListener("click",o=>{o.target===e&&e.remove()})}async function handleLogout(){try{await apiCall("/auth/logout","POST")}catch(e){console.error("Logout failed on server, but logging out client-side anyway.",e)}finally{authToken=null,currentUsername=null,isAdmin=!1,localStorage.removeItem("fluxdrop_token"),localStorage.removeItem("fluxdrop_is_admin"),localStorage.removeItem("fluxdrop_username"),localStorage.removeItem("fluxdrop_user_id"),_resetBrowsePath(),renderApp()}}function _showAvatarEditor(e,n){const l=document.createElement("div");l.style.cssText="position:fixed;inset:0;background:rgba(0,0,0,.78);display:flex;align-items:center;justify-content:center;z-index:20000;font-family:Inter,sans-serif",l.innerHTML=`
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
                        style="background:#2563eb;color:#fff;border:none;border-radius:7px;
                               padding:7px 18px;cursor:pointer;font-size:13px;font-weight:600">
                        ${t("avatar_set_photo")}
                    </button>
                </div>
            </div>
        </div>`,document.body.appendChild(l);const r=l.querySelector("#aed-cv"),s=r.getContext("2d"),a=new Image;let d=URL.createObjectURL(e),u=0,p=0,f=1,m=1;function y(){s.clearRect(0,0,300,300),s.save(),s.translate(300/2+u,300/2+p),s.scale(f,f),s.drawImage(a,-a.naturalWidth/2,-a.naturalHeight/2),s.restore(),s.save(),s.fillStyle="rgba(0,0,0,0.52)",s.beginPath(),s.rect(0,0,300,300),s.arc(300/2,300/2,130,0,Math.PI*2,!0),s.fill("evenodd"),s.strokeStyle="rgba(96,165,250,0.85)",s.lineWidth=2,s.beginPath(),s.arc(300/2,300/2,130,0,Math.PI*2),s.stroke(),s.restore()}function b(){const E=a.naturalWidth*f/2,S=a.naturalHeight*f/2,T=Math.max(0,E-130),B=Math.max(0,S-130);u=Math.max(-T,Math.min(T,u)),p=Math.max(-B,Math.min(B,p))}a.onload=()=>{m=Math.max(260/a.naturalWidth,260/a.naturalHeight),f=m,u=0,p=0,y()},a.src=d;let x=null;r.addEventListener("mousedown",E=>{x={sx:E.clientX,sy:E.clientY,ox:u,oy:p},r.style.cursor="grabbing"});const k=E=>{x&&(u=x.ox+(E.clientX-x.sx),p=x.oy+(E.clientY-x.sy),b(),y())},g=()=>{x=null,r.style.cursor="grab"};window.addEventListener("mousemove",k),window.addEventListener("mouseup",g),r.addEventListener("wheel",E=>{E.preventDefault(),f=Math.max(m,Math.min(f*(E.deltaY<0?1.1:.9),m*10)),b(),y()},{passive:!1});const w={};let h=null,v=null;r.addEventListener("touchstart",E=>{E.preventDefault(),[...E.changedTouches].forEach(T=>{w[T.identifier]={x:T.clientX,y:T.clientY}});const S=Object.keys(w);if(S.length===2){const[T,B]=S.map(H=>w[H]);h=Math.hypot(B.x-T.x,B.y-T.y),v=f}if(S.length===1){const T=E.changedTouches[0];x={sx:T.clientX,sy:T.clientY,ox:u,oy:p}}},{passive:!1}),r.addEventListener("touchmove",E=>{E.preventDefault(),[...E.changedTouches].forEach(T=>{w[T.identifier]={x:T.clientX,y:T.clientY}});const S=Object.keys(w);if(S.length===2&&h){const[T,B]=S.map(X=>w[X]),H=Math.hypot(B.x-T.x,B.y-T.y);f=Math.max(m,Math.min(v*H/h,m*10))}else if(S.length===1&&x){const T=E.changedTouches[0];u=x.ox+(T.clientX-x.sx),p=x.oy+(T.clientY-x.sy)}b(),y()},{passive:!1}),r.addEventListener("touchend",E=>{[...E.changedTouches].forEach(S=>{delete w[S.identifier]}),Object.keys(w).length<2&&(h=null,v=null),Object.keys(w).length===0&&(x=null)});function _(){window.removeEventListener("mousemove",k),window.removeEventListener("mouseup",g),URL.revokeObjectURL(d),l.remove()}l.querySelector("#aed-x").addEventListener("click",_),l.querySelector("#aed-cancel").addEventListener("click",_),l.querySelector("#aed-reset").addEventListener("click",()=>{f=m,u=0,p=0,y()}),l.querySelector("#aed-ok").addEventListener("click",()=>{const E=document.createElement("canvas");E.width=E.height=600;const S=E.getContext("2d"),T=600/260;S.translate((130+u)*T,(130+p)*T),S.scale(f*T,f*T),S.drawImage(a,-a.naturalWidth/2,-a.naturalHeight/2),E.toBlob(B=>{_(),B&&n(B)},"image/jpeg",.88)})}function openProfileMenu(){const e=document.getElementById("profile-menu-modal");if(e){e.remove();return}const n=document.getElementById("fd-info-panel");n&&window.fdCloseFloatingPanel(n);const o=document.createElement("div");o.id="profile-menu-modal",o.setAttribute("role","dialog"),o.setAttribute("aria-label",t("profile")),o.className="fd-profile-overlay",o.style.cssText="position:fixed;inset:0;z-index:8000;display:flex;align-items:flex-start;justify-content:flex-end;padding:70px 1rem 0 0",o.innerHTML=`
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
                    <div id="pm-quota-fill" style="height:100%;border-radius:4px;background:#2563eb;width:0%;transition:width .4s"></div>
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
        @keyframes fadeSlideDown{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}`,o.appendChild(i),document.body.appendChild(o),o.addEventListener("click",c=>{c.target===o&&window.fdCloseOverlay(o)}),document.getElementById("pm-profile").addEventListener("click",()=>{o.remove(),openProfilePanel()}),document.getElementById("pm-quota-bar").style.cursor="pointer",document.getElementById("pm-quota-bar").title=t("pp_open_space_analyzer"),document.getElementById("pm-quota-bar").addEventListener("click",()=>{window.fdCloseOverlay(o),openSpaceAnalyzer()}),document.getElementById("pm-shares").addEventListener("click",()=>{o.remove(),openShareManager()}),document.getElementById("pm-beacon").addEventListener("click",()=>{o.remove(),window.location.href="/beacon/ui"}),document.getElementById("pm-status").addEventListener("click",()=>{o.remove(),window.location.href="/status"}),document.getElementById("pm-logout").addEventListener("click",()=>{o.remove(),handleLogout()}),isAdmin&&document.getElementById("pm-admin")?.addEventListener("click",()=>{o.remove(),openAdminPanel()}),apiCall("/api/v1/me","GET").then(c=>{const l=document.getElementById("pm-quota-bar"),r=document.getElementById("pm-quota-fill");if(!l||!r)return;const s=c.usage_bytes||0,a=c.quota_bytes||1,d=Math.min(100,s/a*100),u=d>=95?"#ef4444":d>=75?"#f59e0b":"#3b82f6",p=f=>f>=1073741824?(f/1073741824).toFixed(1)+" GB":f>=1048576?(f/1048576).toFixed(1)+" MB":(f/1024).toFixed(0)+" KB";l.querySelector("div").textContent=`${t("menu_account_info_storage")} ${p(s)} ${t("quota_of_word")} ${p(a)} (${d.toFixed(0)}%)`,r.style.width=d.toFixed(1)+"%",r.style.background=u}).catch(()=>{const c=document.getElementById("pm-quota-bar");c&&(c.querySelector("div").textContent=t("menu_account_info_storage")+" unavailable")})}async function openProfilePanel(){const e=document.getElementById("profile-panel-overlay");if(e){e.remove();return}const n=document.createElement("div");n.className="modal-overlay",n.id="profile-panel-overlay",n.style.zIndex="9000",n.innerHTML=`
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
                    ${_loadingHtml("4px 0")}
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
                        <button id="pp-change-pw" class="btn" style="justify-self:end;padding:.5rem 1.25rem;background:#4f46e5">${t("change_password")}</button>
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
                    <label style="display:block;margin-top:12px;font-size:13px;font-weight:600;color:#374151">
                        ${t("conflict_setting")}
                        <select id="pp-upload-conflict" style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                            border:1px solid #e2e8f0;border-radius:8px;font-size:14px;font-family:Inter,sans-serif">
                            <option value="ask">${t("conflict_setting_ask")}</option>
                            <option value="rename">${t("conflict_setting_rename")}</option>
                            <option value="replace">${t("conflict_setting_replace")}</option>
                        </select>
                    </label>
                </div>

                <!-- Account info footer -->
                <div id="pp-account-info" style="font-size:12px;color:#94a3b8;padding-bottom:4px">${_loadingHtml("0")}</div>
            </div>
        </div>`,document.body.appendChild(n),n.addEventListener("click",u=>{u.target===n&&window.fdCloseOverlay(n)}),n.querySelector("#pp-close").addEventListener("click",()=>window.fdCloseOverlay(n));function o(u,p,f){const m=n.querySelector("#"+u);m&&(m.textContent=p,m.style.display=p?"block":"none",m.style.background=f?"#fef2f2":"#f0fdf4",m.style.color=f?"#ef4444":"#16a34a")}try{const u=await apiCall("/api/v1/me","GET");if(!n.isConnected)return;const p=u.usage_bytes||0,f=u.quota_bytes||1,m=Math.min(100,p/f*100),y=m>=95?"#ef4444":m>=75?"#f59e0b":"#22c55e",b=g=>g>=1073741824?(g/1073741824).toFixed(2)+" GB":g>=1048576?(g/1048576).toFixed(1)+" MB":(g/1024).toFixed(0)+" KB",x=u.quota_override?` · <span style="color:#6366f1;font-size:11px">${t("quota_pinned")}</span>`:` · <span style="color:#94a3b8;font-size:11px">${t("quota_dynamic")}</span>`;n.querySelector("#pp-quota-card").innerHTML=`
            <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px">
                <span style="font-size:13px;font-weight:600;color:#374151">${t("storage_quota")}</span>
                <span style="font-size:13px;color:#475569">${b(p)} <span style="color:#94a3b8">${t("quota_of_word")}</span> ${b(f)}</span>
            </div>
            <div style="background:#e2e8f0;border-radius:6px;height:8px;overflow:hidden;margin-bottom:6px">
                <div style="height:100%;border-radius:6px;background:${y};width:${m.toFixed(1)}%;transition:width .4s"></div>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="font-size:12px;color:#64748b">${t("profile_info_quota_space",{pct:m.toFixed(1),free:b(f-p),pin:x})}</span>
                ${m>=95?`<span style="font-size:12px;color:#ef4444;font-weight:600">${t("profile_info_quota_space_warning")}</span>`:""}
            </div>
            <div style="font-size:11px;color:#94a3b8;margin-top:6px;text-align:right">${t("profile_info_quota_space_analyzer_hinter")}</div>`;const k=n.querySelector("#pp-quota-card");k.style.cursor="pointer",k.title=t("pp_open_space_analyzer"),k.addEventListener("click",()=>{window.fdCloseOverlay(n),openSpaceAnalyzer()}),n.querySelector("#pp-nickname").value=u.nickname||"",n.querySelector("#pp-email").value=u.email||"",u.id&&localStorage.setItem("fluxdrop_user_id",String(u.id)),n.querySelector("#pp-account-info").innerHTML=`ID ${u.id} ${t("profile_info_username")} <strong>${escapeHtml(u.username)}</strong> ${t("profile_info_join_time")} ${(u.created_at||"").slice(0,10)}`+(u.is_admin?` · <span style="color:#92400e;background:#fef3c7;padding:1px 6px;border-radius:999px;font-weight:600">${t("profile_info_admin_badge")}</span>`:"")}catch(u){if(!n.isConnected)return;n.querySelector("#pp-quota-card").innerHTML=`<div style="color:#ef4444;font-size:13px">${t("pp_load_failed")}: ${escapeHtml(u.message)}</div>`,n.querySelector("#pp-account-info").innerHTML=""}n.querySelector("#pp-save-profile").addEventListener("click",async()=>{const u=n.querySelector("#pp-save-profile"),p=n.querySelector("#pp-nickname").value.trim(),f=n.querySelector("#pp-email").value.trim();if(!p&&!f){o("pp-profile-msg",t("pp_nothing_to_save"),!0);return}o("pp-profile-msg","",!1),u.disabled=!0,u.textContent=t("pp_saving");try{await apiCall("/api/v1/me","PATCH",{nickname:p,email:f}),o("pp-profile-msg",t("pp_saved"),!1)}catch(m){if(!n.isConnected)return;o("pp-profile-msg",m.message,!0)}finally{n.isConnected&&(u.disabled=!1,u.textContent=t("save_changes"))}});function i(){_bumpAvatarVersion();const u=localStorage.getItem("fluxdrop_user_id")||"0",p=_avatarUrl(u),f=n.querySelector("#pp-avatar-img"),m=n.querySelector("#pp-avatar-fallback"),y=document.getElementById("header-avatar"),b=document.getElementById("header-avatar-fallback");f&&(f.style.display="block",m&&(m.style.display="none"),f.onerror=()=>{f.style.display="none",m&&(m.style.display="flex")},f.src=p),y&&(y.style.display="block",b&&(b.style.display="none"),y.onerror=()=>{y.style.display="none",b&&(b.style.display="flex")},y.src=p)}const c=n.querySelector("#pp-avatar-file"),l=n.querySelector("#pp-avatar-msg");async function r(u){l.textContent=t("uploading"),l.style.color="#64748b";const p=new FormData;p.append("avatar",u,"avatar.jpg");try{const f=await fetchWithFallback(`${API_BASE_URL}/api/v1/me/avatar`,{method:"POST",headers:authToken?{Authorization:`Bearer ${authToken}`}:{},body:p}),m=await f.json();if(!f.ok)throw new Error(m.error||`HTTP ${f.status}`);l.textContent="✓ "+t("pp_avatar_saved",{mime:m.mime,kb:Math.round(m.size_bytes/1024)}),l.style.color="#16a34a",i()}catch(f){l.textContent="⚠ "+f.message,l.style.color="#ef4444"}}c&&c.addEventListener("change",function(){const u=this.files&&this.files[0];if(u){if(!u.type.startsWith("image/")){l.textContent="⚠ "+t("pp_avatar_not_image"),l.style.color="#ef4444";return}this.value="",_showAvatarEditor(u,p=>r(p))}});const s=n.querySelector("#pp-avatar-remove");s&&s.addEventListener("click",async()=>{l.textContent=t("pp_avatar_removing"),l.style.color="#64748b";try{const u=await fetchWithFallback(`${API_BASE_URL}/api/v1/me/avatar`,{method:"DELETE",headers:authToken?{Authorization:`Bearer ${authToken}`}:{}});if(!u.ok)throw new Error(`HTTP ${u.status}`);l.textContent=t("pp_avatar_removed"),l.style.color="#64748b",i()}catch(u){l.textContent="⚠ "+u.message,l.style.color="#ef4444"}}),n.querySelector("#pp-change-pw").addEventListener("click",async()=>{const u=n.querySelector("#pp-change-pw"),p=n.querySelector("#pp-cur-pw").value,f=n.querySelector("#pp-new-pw").value,m=n.querySelector("#pp-confirm-pw").value;if(!p||!f||!m){o("pp-pw-msg",t("pp_pw_all_required"),!0);return}if(f!==m){o("pp-pw-msg",t("pp_pw_mismatch"),!0);return}if(f.length<8){o("pp-pw-msg",t("pp_pw_too_short",{n:8}),!0);return}o("pp-pw-msg","",!1),u.disabled=!0,u.textContent=t("pp_pw_changing");try{const y=await apiCall("/api/v1/me/password","PATCH",{current_password:p,new_password:f});o("pp-pw-msg",t("pp_pw_changed"),!1),n.querySelector("#pp-cur-pw").value="",n.querySelector("#pp-new-pw").value="",n.querySelector("#pp-confirm-pw").value=""}catch(y){if(!n.isConnected)return;o("pp-pw-msg",y.message,!0)}finally{n.isConnected&&(u.disabled=!1,u.textContent=t("change_password"))}});const a=n.querySelector("#pp-dismiss-delay");a&&(a.value=localStorage.getItem("fluxdrop_tray_dismiss_ms")||"0",a.addEventListener("change",()=>{localStorage.setItem("fluxdrop_tray_dismiss_ms",a.value)}));const d=n.querySelector("#pp-upload-conflict");d&&(d.value=_uploadConflictPref(),d.addEventListener("change",()=>{localStorage.setItem(_CONFLICT_PREF_KEY,d.value)}))}async function openAdminPanel(){const e=document.getElementById("admin-panel-overlay");if(e){e.remove();return}const n=document.createElement("div");n.className="modal-overlay",n.id="admin-panel-overlay",n.style.zIndex="9000",n.innerHTML=`
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
        </div>`,document.body.appendChild(n),n.addEventListener("click",o=>{o.target===n&&window.fdCloseOverlay(n)}),document.getElementById("ap-close").addEventListener("click",()=>window.fdCloseOverlay(n)),_apInjectStyle(),n.querySelectorAll(".ap-tab").forEach(o=>{o.addEventListener("click",()=>_apShowTab(o.dataset.tab))}),_apRefreshReportsBadge(),await _apShowTab("users")}async function _apShowTab(e){document.querySelectorAll("#ap-tabs .ap-tab").forEach(o=>o.classList.toggle("ap-tab-active",o.dataset.tab===e));const n=document.getElementById("ap-body");n&&(n.innerHTML=`<div style="padding:24px 0;color:#64748b;font-size:14px">${t("loading")}</div>`),e==="reports"?await _apLoadReports():await _apLoadUsers()}async function _apRefreshReportsBadge(){try{const e=await apiCall("/api/v1/admin/reports?status=open","GET"),n=document.getElementById("ap-reports-badge");n&&(n.innerHTML=e.open_count?`<span class="ap-badge" style="background:#fee2e2;color:#b91c1c">${e.open_count}</span>`:"")}catch{}}function _apInjectStyle(){if(document.getElementById("ap-style"))return;const e=document.createElement("style");e.id="ap-style",e.textContent=`
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
    `,document.head.appendChild(e)}let _apUsagePollTimer=null;async function _apLoadUsers(){const e=document.getElementById("ap-body"),n=document.getElementById("ap-stats");if(!e)return;const o=e.parentElement,i=o?o.scrollTop:0;try{const l=(await apiCall("/api/v1/admin/users","GET")).users||[],r=l.reduce((a,d)=>a+(d.usage_bytes||0),0),s=l.filter(a=>a.is_admin).length;if(n&&(n.innerHTML=[`<span style="font-size:13px;color:#475569"><strong style="color:#1e293b">${l.length}</strong> ${t("admin_panel_user_count")}</span>`,`<span style="font-size:13px;color:#475569"><strong style="color:#1e293b">${s}</strong> ${t("admin_panel_admin_count")}</span>`,`<span style="font-size:13px;color:#475569">${t("admin_panel_used")} <strong style="color:#1e293b">${_apFmtBytes(r)}</strong></span>`].join('<span style="color:#cbd5e1;margin:0 4px">|</span>')),l.length===0){e.innerHTML=`<p style="color:#64748b;font-size:14px;padding:20px 0">${t("admin_panel_no_users")}</p>`;return}_apInjectStyle(),e.innerHTML=`
            <div class="ap-row" style="font-size:12px;font-weight:700;color:#94a3b8;
                border-bottom:2px solid #e2e8f0;border-radius:0;padding-bottom:6px">
                <span>${t("admin_col_user")}</span><span>${t("admin_col_usage")}</span><span>${t("admin_col_quota")}</span>
                <span style="text-align:right">${t("fluxdrop_file_manager_actions")}</span>
            </div>`+l.map(a=>_apRenderRow(a)).join(""),o&&(o.scrollTop=i),e.querySelectorAll(".ap-edit-btn").forEach(a=>{a.addEventListener("click",()=>_apOpenEditModal(+a.dataset.id,l))}),e.querySelectorAll(".ap-del-btn").forEach(a=>{a.addEventListener("click",()=>_apDeleteUser(+a.dataset.id,a.dataset.name))}),clearTimeout(_apUsagePollTimer),l.some(a=>a.usage_bytes==null)&&(_apUsagePollTimer=setTimeout(()=>{const a=document.querySelector("#ap-tabs .ap-tab-active");a&&a.dataset.tab==="users"&&_apLoadUsers()},4e3))}catch(c){const l=document.getElementById("ap-body");c.message!=="SESSION_EXPIRED"&&l&&(l.innerHTML=`<p style="color:#ef4444;font-size:14px;padding:20px 0">${t("admin_panel_load_failed",{err:escapeHtml(c.message)})}</p>`)}}let _apReportsFilter="open";async function _apLoadReports(){const e=document.getElementById("ap-body"),n=document.getElementById("ap-stats");if(e)try{const i=await apiCall("/api/v1/admin/reports"+(_apReportsFilter==="open"?"?status=open":""),"GET"),c=i.reports||[];n&&(n.innerHTML=`
            <span style="font-size:13px;color:#475569"><strong style="color:#1e293b">${i.open_count}</strong> ${t("admin_reports_open_count")}</span>
            <label style="font-size:13px;color:#475569;margin-left:auto;display:flex;align-items:center;gap:6px">
                ${t("admin_reports_show")}
                <select id="ap-rep-filter" style="padding:3px 6px;border:1px solid #e2e8f0;border-radius:6px;font-size:13px">
                    <option value="open" ${_apReportsFilter==="open"?"selected":""}>${t("admin_reports_filter_open")}</option>
                    <option value="all" ${_apReportsFilter==="all"?"selected":""}>${t("admin_reports_filter_all")}</option>
                </select>
            </label>`),document.getElementById("ap-rep-filter")?.addEventListener("change",r=>{_apReportsFilter=r.target.value,_apLoadReports()});const l=document.getElementById("ap-reports-badge");if(l&&(l.innerHTML=i.open_count?`<span class="ap-badge" style="background:#fee2e2;color:#b91c1c">${i.open_count}</span>`:""),!c.length){e.innerHTML=`<p style="color:#64748b;font-size:14px;padding:20px 0">${t("admin_reports_none")}</p>`;return}e.innerHTML=c.map(_apRenderReport).join(""),e.querySelectorAll(".ap-rep-act").forEach(r=>{r.addEventListener("click",()=>_apReportAction(+r.dataset.id,r.dataset.action))})}catch(o){o.message!=="SESSION_EXPIRED"&&(e.innerHTML=`<p style="color:#ef4444;font-size:14px;padding:20px 0">${t("admin_panel_load_failed",{err:escapeHtml(o.message)})}</p>`)}}function _apRenderReport(e){const n={open:"background:#fee2e2;color:#b91c1c",action_taken:"background:#dcfce7;color:#166534",dismissed:"background:#f1f5f9;color:#475569"}[e.status]||"",o=e.share_token?t("admin_reports_kind_share"):e.cdn_path?t("admin_reports_kind_cdn"):t("admin_reports_kind_unknown"),i=e.reporter_username?escapeHtml(e.reporter_username)+(e.reporter_email?` · ${escapeHtml(e.reporter_email)}`:""):e.reporter_email?escapeHtml(e.reporter_email):t("admin_reports_anonymous"),c=/^https?:\/\//i.test(e.target_url)?escapeHtmlAttr(e.target_url):"",l=(s,a,d)=>`<button class="ap-btn ap-rep-act" data-id="${e.id}" data-action="${s}" style="background:${d};color:white">${a}</button>`;let r="";return e.status==="open"?(e.share_token&&e.share_active&&(r+=l("disable_link",t("admin_reports_disable_link"),"#ef4444")),e.cdn_file_exists&&(r+=l("delete_file",t("admin_reports_delete_file"),"#ef4444")),r+=l("resolve",t("admin_reports_resolve"),"#16a34a"),r+=l("dismiss",t("admin_reports_dismiss"),"#64748b")):r+=l("reopen",t("admin_reports_reopen"),"#64748b"),`<div class="ap-rep ${e.status==="open"?"":"ap-rep-closed"}">
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <strong style="font-size:14px">#${e.id}</strong>
            <span class="ap-badge" style="${n}">${t("admin_reports_status_"+e.status)}</span>
            <span class="ap-badge" style="background:#fef3c7;color:#92400e">${t("report_reason_"+e.reason)}</span>
            <span style="font-size:12px;color:#94a3b8;margin-left:auto">${escapeHtml(String(e.created_at||""))} UTC</span>
        </div>
        <div class="ap-rep-meta" data-fd-notranslate>
            ${o}: ${c?`<a href="${c}" target="_blank" rel="noopener noreferrer" style="color:#3b82f6;word-break:break-all">${escapeHtml(e.target_url)}</a>`:escapeHtml(e.target_url)}
            ${e.share_token&&!e.share_active?` <em>(${t("admin_reports_link_gone")})</em>`:""}<br>
            ${t("admin_reports_owner")}: ${e.owner_username?escapeHtml(e.owner_username):"—"}
            · ${t("admin_reports_reporter")}: ${i}
            ${e.resolution_note?`<br>${t("admin_reports_note")}: ${escapeHtml(e.resolution_note)}`:""}
        </div>
        ${e.message?`<div class="ap-rep-msg" data-fd-notranslate>${escapeHtml(e.message)}</div>`:""}
        <div class="ap-rep-actions">${r}</div>
    </div>`}async function _apReportAction(e,n){if(!((n==="disable_link"||n==="delete_file")&&!await showConfirmModal({title:t(n==="disable_link"?"admin_reports_confirm_disable":"admin_reports_confirm_delete",{id:e}),message:t("admin_reports_confirm_body")})))try{await apiCall(`/api/v1/admin/reports/${e}`,"POST",{action:n}),showToast(t("admin_reports_done")),await _apLoadReports()}catch(o){o.message!=="SESSION_EXPIRED"&&showMessage(t("update_failed"),o.message)}}function _apFmtBytes(e){return e>=1073741824?(e/1073741824).toFixed(1)+" GB":e>=1048576?(e/1048576).toFixed(1)+" MB":e>=1024?(e/1024).toFixed(0)+" KB":e+" B"}function _apRenderRow(e){const n=e.usage_bytes==null,o=!n&&e.quota_bytes>0?Math.min(100,e.usage_bytes/e.quota_bytes*100):0,i=o>=95?"#ef4444":o>=75?"#f59e0b":"#22c55e";return`<div class="ap-row">
        <div>
            <div style="font-size:14px;font-weight:600;color:#1e293b">${e.is_admin?`<span class="ap-badge" style="background:#fef3c7;color:#92400e">${t("profile_info_admin_badge")}</span> `:""}${escapeHtml(e.username)}</div>
            <div style="font-size:11px;color:#94a3b8;margin-top:1px">${escapeHtml(e.nickname||"")} · ${escapeHtml(e.email||"")}</div>
            <div style="font-size:11px;color:#cbd5e1;margin-top:1px">${t("admin_row_id_joined",{id:e.id,date:(e.created_at||"").slice(0,10)})}</div>
        </div>
        <div>
            <div style="font-size:12px;color:#475569;margin-bottom:3px">${n?t("admin_usage_calculating"):_apFmtBytes(e.usage_bytes)}</div>
            <div class="ap-bar-wrap"><div class="ap-bar-fill" style="width:${o.toFixed(1)}%;background:${i}"></div></div>
            <div style="font-size:10px;color:#94a3b8;margin-top:2px">${n?"…":o.toFixed(0)+"%"}</div>
        </div>
        <div>
            <div style="font-size:12px;color:#475569">${_apFmtBytes(e.quota_bytes||0)}</div>
            ${e.quota_override?`<div style="font-size:10px;color:#6366f1;margin-top:1px">${t("admin_panel_pinned_badge")}</div>`:`<div style="font-size:10px;color:#94a3b8;margin-top:1px">${t("admin_panel_dynamic_quota")}</div>`}
        </div>
        <div style="display:flex;gap:5px;justify-content:flex-end">
            <button class="ap-btn ap-edit-btn" data-id="${e.id}"
                style="background:#2563eb;color:white">${t("admin_panel_edit_button")}</button>
            <button class="ap-btn ap-del-btn" data-id="${e.id}" data-name="${escapeHtmlAttr(e.username)}"
                style="background:#dc2626;color:white">${t("admin_panel_delete_button")}</button>
        </div>
    </div>`}function _apOpenEditModal(e,n){const o=n.find(l=>l.id===e);if(!o)return;const i=document.getElementById("ap-edit-overlay");i&&i.remove();const c=document.createElement("div");c.className="modal-overlay",c.id="ap-edit-overlay",c.style.zIndex="9500",c.innerHTML=`
        <div style="background:white;border-radius:14px;width:95vw;max-width:460px;
                    overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.35)">
            <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:16px 20px;
                        display:flex;align-items:center;justify-content:space-between">
                <div style="color:white;font-weight:700;font-size:16px">${t("admin_edit_title",{name:escapeHtml(o.username)})}</div>
                <button id="ap-edit-close" style="background:rgba(255,255,255,.2);border:none;border-radius:50%;
                    width:28px;height:28px;color:white;font-size:16px;cursor:pointer;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <div style="padding:20px;display:grid;gap:12px">
                <label style="font-size:13px;font-weight:600;color:#374151">${t("username_login")}
                    <input id="ape-username" type="text" value="${escapeHtmlAttr(o.username)}"
                        style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                               border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                               box-sizing:border-box;font-family:Inter,sans-serif">
                </label>
                <label style="font-size:13px;font-weight:600;color:#374151">${t("admin_edit_nickname")}
                    <input id="ape-nickname" type="text" value="${escapeHtmlAttr(o.nickname||"")}"
                        style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                               border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                               box-sizing:border-box;font-family:Inter,sans-serif">
                </label>
                <label style="font-size:13px;font-weight:600;color:#374151">${t("email")}
                    <input id="ape-email" type="email" value="${escapeHtmlAttr(o.email||"")}"
                        style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                               border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                               box-sizing:border-box;font-family:Inter,sans-serif">
                </label>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
                    <label style="font-size:13px;font-weight:600;color:#374151">${t("admin_edit_quota_gb")}
                        <input id="ape-quota" type="number" min="1" step="1"
                            value="${Math.round((o.quota_bytes||0)/1024**3)}"
                            style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                   border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                   box-sizing:border-box;font-family:Inter,sans-serif">
                    </label>
                    <label style="font-size:13px;font-weight:600;color:#374151;display:flex;flex-direction:column">
                        <span>${t("admin_edit_flags")}</span>
                        <span style="display:flex;flex-direction:column;gap:6px;margin-top:8px">
                            <label style="display:flex;align-items:center;gap:7px;font-weight:400;cursor:pointer">
                                <input type="checkbox" id="ape-is-admin" ${o.is_admin?"checked":""}> ${t("admin_edit_flag_admin")}
                            </label>
                            <label style="display:flex;align-items:center;gap:7px;font-weight:400;cursor:pointer">
                                <input type="checkbox" id="ape-quota-override" ${o.quota_override?"checked":""}> ${t("admin_edit_flag_pin_quota")}
                            </label>
                            <label style="display:flex;align-items:center;gap:7px;font-weight:400;cursor:pointer"
                                   title="${escapeHtmlAttr(t("admin_edit_flag_publish_hint"))}">
                                <input type="checkbox" id="ape-can-publish" ${o.can_publish?"checked":""}> ${t("admin_edit_flag_publish")}
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
                <button id="ape-save" class="btn" style="background:#2563eb;min-width:80px">${t("admin_edit_save")}</button>
            </div>
        </div>`,document.body.appendChild(c),c.addEventListener("click",l=>{l.target===c&&window.fdCloseOverlay(c)}),c.querySelector("#ap-edit-close").addEventListener("click",()=>window.fdCloseOverlay(c)),c.querySelector("#ape-cancel").addEventListener("click",()=>window.fdCloseOverlay(c)),c.querySelector("#ape-save").addEventListener("click",async()=>{if(!c.isConnected)return;const l=c.querySelector("#ape-save"),r=c.querySelector("#ape-error"),s=parseFloat(c.querySelector("#ape-quota").value);if(isNaN(s)||s<1){r.textContent=t("admin_edit_quota_min_err"),r.style.display="block";return}r.style.display="none",l.disabled=!0,l.textContent=t("admin_edit_saving");try{await apiCall(`/api/v1/admin/users/${e}`,"PATCH",{username:c.querySelector("#ape-username").value.trim(),nickname:c.querySelector("#ape-nickname").value.trim(),email:c.querySelector("#ape-email").value.trim(),quota_bytes:Math.round(s*1024**3),is_admin:c.querySelector("#ape-is-admin").checked?1:0,quota_override:c.querySelector("#ape-quota-override").checked?1:0,can_publish:c.querySelector("#ape-can-publish").checked?1:0}),window.fdCloseOverlay(c),await _apLoadUsers()}catch(a){if(!c.isConnected)return;l.disabled=!1,l.textContent=t("admin_edit_save"),a.message!=="SESSION_EXPIRED"&&(r.textContent=a.message,r.style.display="block")}})}async function _apDeleteUser(e,n){const o=t("admin_delete_confirm",{name:n}),[i,...c]=o.split(`

`);if(await showConfirmModal({title:i,message:c.join(`

`)}))try{await apiCall(`/api/v1/admin/users/${e}`,"DELETE"),await _apLoadUsers()}catch(r){r.message!=="SESSION_EXPIRED"&&showMessage(t("admin_delete_failed"),r.message)}}async function _fetchCanPublish(){if(_canPublish!==null)return _canPublish;try{_canPublish=!!(await apiCall("/api/v1/me","GET",null,!0)).can_publish}catch{return isAdmin}return _canPublish}async function openShareDialog(e,n){const o=await _fetchCanPublish(),i=e.split("/").pop()||e,c=document.createElement("div");c.className="modal-overlay",c.id="share-dialog-overlay",c.innerHTML=`
        <div class="modal-content" style="max-width:500px">
            <h3 style="font-size:18px;font-weight:700;margin-bottom:4px">${t("share_dlg_title",{name:escapeHtml(i)})}</h3>
            <p style="font-size:13px;color:#64748b;margin-bottom:16px">${n?t("share_dlg_kind_folder"):t("share_dlg_kind_file")}: <code style="background:#f1f5f9;padding:1px 5px;border-radius:4px;word-break:break-all">${escapeHtml(e)}</code></p>

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
                    <span id="sh-expiry-label" style="font-size:14px;font-weight:600;white-space:nowrap">${t("share_dlg_expires_label")}</span>
                    <select id="sh-expiry-preset" aria-labelledby="sh-expiry-label" style="flex:1;padding:6px 10px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;background:white">
                        <option value="">${t("share_dlg_exp_never")}</option>
                        <option value="1">${t("share_dlg_exp_1d")}</option>
                        <option value="7">${t("share_dlg_exp_7d")}</option>
                        <option value="30">${t("share_dlg_exp_30d")}</option>
                        <option value="90">${t("share_dlg_exp_90d")}</option>
                        <option value="custom">${t("share_dlg_exp_custom")}</option>
                    </select>
                    <input type="datetime-local" id="sh-expiry-custom" aria-labelledby="sh-expiry-label"
                        style="display:none;padding:6px 10px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px"
                        min="${_localDateTimeValue(new Date)}">
                </div>

                <hr style="border:none;border-top:1px solid #e2e8f0;margin:2px 0">
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-allow-preview" style="width:16px;height:16px">
                    <span style="font-size:14px">${t("share_dlg_allow_preview")}</span>
                </label>
                ${n?"":`<label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-cdn-embed" style="width:16px;height:16px" ${o?"":"disabled"}>
                    <span style="font-size:14px">${t("share_dlg_allow_cdn")}</span>
                </label>`}

                ${n?`
                <hr style="border:none;border-top:1px solid #e2e8f0;margin:2px 0">
                <label style="display:flex;align-items:center;gap:10px">
                    <span style="font-size:14px;font-weight:600;white-space:nowrap">${t("share_dlg_upload_who")}</span>
                    <select id="sh-upload-policy" style="flex:1;padding:6px 10px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;background:white">
                        <option value="none">${t("share_dlg_upload_none")}</option>
                        <option value="anon" ${o?"":"disabled"}>${t("share_dlg_upload_anon")}</option>
                        <option value="auth">${t("share_dlg_upload_auth")}</option>
                    </select>
                </label>`:""}
                ${o?"":`<div style="font-size:12px;color:#94a3b8">${escapeHtml(t("share_publish_locked"))}</div>`}
            </div>

            <div id="sh-result" style="display:none;background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:12px;margin-bottom:14px">
                <div style="font-size:12px;color:#166534;margin-bottom:6px;font-weight:600">${t("share_dlg_link_created")}</div>
                <div style="display:flex;gap:6px">
                    <input id="sh-link-box" type="text" readonly aria-label="Link" style="flex:1;font-size:12px;padding:6px;border:1px solid #ccc;border-radius:6px;background:white;color:#1e293b">
                    <button id="sh-copy-btn" style="background:#15803d;color:white;border:none;border-radius:6px;padding:6px 12px;cursor:pointer;font-size:12px">${t("share_dlg_copy")}</button>
                </div>
            </div>

            <div style="display:flex;gap:8px;justify-content:flex-end">
                <button id="sh-cancel-btn" class="btn" style="background:#e2e8f0;color:#1e293b">${t("cancel")}</button>
                <button id="sh-create-btn" class="btn" style="background:#7c3aed">${t("share_dlg_create")}</button>
            </div>
        </div>`,document.body.appendChild(c);const l=document.getElementById("sh-expiry-preset"),r=document.getElementById("sh-expiry-custom");l.addEventListener("change",()=>{r.style.display=l.value==="custom"?"block":"none"});function s(){const y=l.value;if(!y)return null;if(y==="custom")return r.value?new Date(r.value).toISOString():null;const b=new Date;return b.setDate(b.getDate()+parseInt(y)),b.toISOString()}const a=c.querySelector("#sh-cancel-btn"),d=c.querySelector("#sh-create-btn"),u=c.querySelector("#sh-result"),p=c.querySelector("#sh-link-box"),f=c.querySelector("#sh-copy-btn");a.addEventListener("click",()=>window.fdCloseOverlay(c)),c.addEventListener("click",y=>{y.target===c&&window.fdCloseOverlay(c)});let m=!1;d.addEventListener("click",async()=>{if(m){window.fdCloseOverlay(c);return}if(!c.isConnected)return;if(d.disabled=!0,d.innerHTML='<span style="display:inline-flex;align-items:center;gap:6px"><svg style="animation:spin 0.8s linear infinite;width:14px;height:14px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>'+t("share_dlg_creating")+"</span>",!document.getElementById("fd-spin-style")){const k=document.createElement("style");k.id="fd-spin-style",k.textContent="@keyframes spin{to{transform:rotate(360deg)}}",document.head.appendChild(k)}const y=c.querySelector("#sh-upload-policy")?.value??"none",b={path:e,is_dir:n,require_account:c.querySelector("#sh-require-account")?.checked??!1,track_stats:c.querySelector("#sh-stats")?.checked??!1,allow_anon_upload:n?y==="anon":!1,allow_auth_upload:n?y==="auth":!1,allow_preview:c.querySelector("#sh-allow-preview")?.checked??!1,allow_cdn_embed:n?!1:c.querySelector("#sh-cdn-embed")?.checked??!1,expires_at:s()};try{let w=function(){navigator.clipboard.writeText(g).then(()=>{f.textContent=t("share_dlg_copied"),f.style.background="#15803d",setTimeout(()=>{f.textContent=t("share_dlg_copy"),f.style.background="#16a34a"},2e3)}).catch(()=>{p.select()})};var x=w;const k=await apiCall("/api/v1/shares","POST",b);if(!c.isConnected)return;const g=`${window.location.origin}/share/${k.token}`;u.style.display="block",p.value=g,f.addEventListener("click",w),w(),d.textContent=t("share_dlg_done"),d.style.background="#16a34a",d.disabled=!1,m=!0}catch(k){if(!c.isConnected)return;d.disabled=!1,d.textContent=t("share_dlg_create"),k.message!=="SESSION_EXPIRED"&&showMessage(t("share_dlg_failed"),k.message)}})}function _smEnsureStyle(){if(document.getElementById("sm-style"))return;const e=document.createElement("style");e.id="sm-style",e.textContent=`
#share-manager-overlay .sm-panel{max-width:880px;width:95vw;max-height:88vh;display:flex;flex-direction:column;padding:0;overflow:hidden}
.sm-head{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:14px 20px;border-bottom:1px solid var(--fd-border,#e2e8f0);flex-shrink:0}
.sm-head h3{font-size:18px;font-weight:700;margin:0}
.sm-close{background:none;border:none;font-size:20px;line-height:1;padding:4px;cursor:pointer;color:var(--fd-muted,#64748b)}
.sm-filters{display:none;flex-wrap:wrap;gap:6px;padding:10px 20px;border-bottom:1px solid var(--fd-border,#e2e8f0);flex-shrink:0}
.sm-filter{border:1px solid var(--fd-border,#e2e8f0);background:none;color:var(--fd-muted,#64748b);border-radius:999px;padding:3px 10px;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap;flex-shrink:0}
.sm-filter[aria-pressed="true"]{background:#2563eb;border-color:#2563eb;color:#fff}
.sm-filter span{opacity:.75}
.sm-body{overflow-y:auto;padding:16px 20px;flex:1}
.sm-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px;align-items:start}
.sm-empty{grid-column:1/-1;color:var(--fd-muted,#64748b);font-size:14px;margin:0}
.sm-card{border:1px solid var(--fd-border,#e2e8f0);border-radius:12px;padding:12px 14px;min-width:0}
.sm-top{display:flex;gap:10px;align-items:flex-start;min-width:0}
.sm-icon{font-size:20px;line-height:1.3;flex-shrink:0}
.sm-main{flex:1;min-width:0}
.sm-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap;min-width:0}
.sm-name{font-weight:600;font-size:14px;min-width:0;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sm-badge{border-radius:999px;padding:1px 8px;font-size:11px;font-weight:600;white-space:nowrap;flex-shrink:0;background:#fef3c7;color:#92400e}
.sm-badge.expired{background:#fee2e2;color:#b91c1c}
.sm-path{font-size:11px;color:var(--fd-muted,#64748b);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:rtl;text-align:left}
.sm-meta{font-size:11px;color:var(--fd-muted,#64748b);margin-top:2px}
.sm-opts{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:6px 14px;margin-top:10px}
.sm-opts label{display:flex;align-items:flex-start;gap:7px;font-size:13px;cursor:pointer;min-width:0}
.sm-opts input{flex-shrink:0;margin-top:3px}
.sm-exp{display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-size:13px;margin-top:10px}
.sm-exp input{padding:3px 7px;border:1px solid var(--fd-border,#e2e8f0);border-radius:6px;font-size:12px;color:var(--fd-text,#1e293b);background:var(--fd-input-bg,#fff);max-width:100%}
.sm-expiry-clear{background:none;border:1px solid var(--fd-border,#e2e8f0);border-radius:6px;padding:3px 7px;cursor:pointer;font-size:11px;color:#94a3b8}
.sm-never{font-size:12px;color:var(--fd-muted,#64748b)}
.sm-cdn{margin-top:10px;padding:10px;background:#fefce8;border:1px solid #fde047;border-radius:8px}
.sm-cdn-title{font-size:11px;color:#854d0e;font-weight:600;margin-bottom:5px}
.sm-cdn-row{display:flex;gap:6px}
.sm-cdn-row input{flex:1;min-width:0;font-size:11px;padding:4px 7px;border:1px solid #fde047;border-radius:5px;background:#fff;color:#1e293b}
.sm-cdn-row button{background:#a16207;color:#fff;border:none;border-radius:5px;padding:4px 10px;cursor:pointer;font-size:11px;flex-shrink:0}
.sm-actions{display:flex;gap:6px;justify-content:flex-end;margin-top:10px;padding-top:10px;border-top:1px solid var(--fd-border,#e2e8f0)}
.sm-actions button{border:none;border-radius:6px;padding:5px 11px;cursor:pointer;font-size:12px;color:#fff;white-space:nowrap}
.sm-actions .sm-stats-btn{background:#0369a1}
.sm-actions .sm-copy-btn{background:#2563eb}
.sm-actions .sm-delete-btn{background:#dc2626}
.sm-actions button:hover,.sm-cdn-row button:hover{filter:brightness(1.12)}
.sm-card .sm-copied{background:#15803d}
.sm-short{display:none}
@media (max-width:560px){
  .sm-head,.sm-filters,.sm-body{padding-left:14px;padding-right:14px}
  .sm-filters{flex-wrap:nowrap;overflow-x:auto;scrollbar-width:none}
  .sm-list{grid-template-columns:1fr}
  .sm-actions button{flex:1 1 auto;padding:7px 8px}
  .sm-long{display:none}
  .sm-short{display:inline}
}
[data-theme="dark"] .sm-badge{background:#3a2e0b;color:#fcd34d}
[data-theme="dark"] .sm-badge.expired{background:#3b1618;color:#fca5a5}
[data-theme="dark"] .sm-cdn{background:#2a220a;border-color:#854d0e}
[data-theme="dark"] .sm-cdn-title{color:#fcd34d}
[data-theme="dark"] .sm-cdn-row input{background:#0d1520;color:#e2e8f0;border-color:#854d0e}
`,document.head.appendChild(e)}async function openShareManager(){await _fetchCanPublish(),_smEnsureStyle();const e=document.createElement("div");e.className="modal-overlay",e.id="share-manager-overlay",e.innerHTML=`
        <div class="modal-content sm-panel">
            <div class="sm-head">
                <h3>${t("shares_manager_title")}</h3>
                <button id="sm-close" class="sm-close" aria-label="${escapeHtmlAttr(t("close"))}">✕</button>
            </div>
            <div id="sm-filters" class="sm-filters" role="group" aria-label="${escapeHtmlAttr(t("shares_filter_label"))}"></div>
            <div id="sm-body" class="sm-body" tabindex="0">
                <p class="sm-empty">${t("loading")}</p>
            </div>
        </div>`,document.body.appendChild(e),document.getElementById("sm-close").addEventListener("click",()=>window.fdCloseOverlay(e)),e.addEventListener("click",n=>{n.target===e&&window.fdCloseOverlay(e)}),_smBindBody(e.querySelector("#sm-body")),_smFilter="all",await loadShareManager()}let _smFilter="all",_smShares=[],_smGen=0;const _smExpired=e=>!!e.expires_at&&new Date(e.expires_at)<new Date,_SM_FILTERS=[["all",()=>!0],["active",e=>!_smExpired(e)],["expired",_smExpired],["files",e=>!e.is_dir],["folders",e=>!!e.is_dir],["cdn",e=>!e.is_dir&&!!e.allow_cdn_embed],["uploads",e=>!!e.is_dir&&!!(e.allow_anon_upload||e.allow_auth_upload)],["account",e=>!!e.require_account],["stats",e=>!!e.track_stats]],_smFilterFn=()=>(_SM_FILTERS.find(e=>e[0]===_smFilter)||_SM_FILTERS[0])[1];function _smRenderFilters(){const e=document.getElementById("sm-filters");if(e){if(_smShares.length<2){e.style.display="none";return}e.style.display="flex",e.innerHTML=_SM_FILTERS.map(([n,o])=>{const i=_smShares.filter(o).length;return!i&&n!=="all"&&n!==_smFilter?"":`<button type="button" class="sm-filter" data-filter="${n}" aria-pressed="${n===_smFilter}">${t("shares_filter_"+n)} <span>${i}</span></button>`}).join(""),e.querySelectorAll(".sm-filter").forEach(n=>n.addEventListener("click",()=>{_smFilter=n.dataset.filter,_smRenderFilters(),_smApplyFilter();const o=document.getElementById("sm-body");o&&(o.scrollTop=0)}))}}function _smApplyFilter(){const e=document.getElementById("sm-body");if(!e)return;const n=_smFilterFn(),o=new Map(_smShares.map(c=>[c.token,c]));e.querySelectorAll(".sm-card").forEach(c=>{const l=o.get(c.dataset.token);c.hidden=!(l&&n(l))});const i=e.querySelector("#sm-filter-empty");i&&(i.hidden=_smShares.some(n))}function _smRenderList(e,n){const o=++_smGen,i=document.createElement("div");i.className="sm-list",i.innerHTML=`<p id="sm-filter-empty" class="sm-empty" hidden>${t("shares_filter_empty")}</p>`,e.replaceChildren(i);let c=0;const l=()=>{if(o!==_smGen||!i.isConnected)return;const r=n?_smShares.length:Math.min(_smShares.length,c+(c?30:12));i.insertAdjacentHTML("beforeend",_smShares.slice(c,r).map(renderShareRow).join("")),c=r,_smApplyFilter(),c<_smShares.length&&setTimeout(l,0)};l()}function _smBindBody(e){e.addEventListener("mouseover",n=>{const o=n.target.closest(".fd-tooltip-wrap");o&&o.classList.toggle("fd-tooltip-below",o.getBoundingClientRect().top<240)}),e.addEventListener("change",async n=>{const o=n.target,i=o.dataset.token;if(o.classList.contains("sm-toggle")){const c=o.dataset.field;try{await apiCall(`/api/v1/shares/${i}`,"PATCH",{[c]:o.checked});const l=_smShares.find(r=>r.token===i);l&&(l[c]=o.checked,_smRenderFilters())}catch(l){showMessage(t("shares_update_failed"),l.message),o.checked=!o.checked}}else if(o.classList.contains("sm-expiry-input")){const c=o.value?new Date(o.value).toISOString():null;try{await apiCall(`/api/v1/shares/${i}`,"PATCH",{expires_at:c}),await loadShareManager({quiet:!0})}catch(l){showMessage(t("update_failed"),l.message)}}}),e.addEventListener("click",async n=>{const o=n.target.closest("button");if(!o||!e.contains(o))return;const i=o.dataset.token;if(o.classList.contains("sm-copy-btn"))navigator.clipboard.writeText(o.dataset.url).then(()=>{const c=o.innerHTML;o.textContent=t("share_dlg_copied"),o.classList.add("sm-copied"),setTimeout(()=>{o.innerHTML=c,o.classList.remove("sm-copied")},1500)});else if(o.classList.contains("sm-stats-btn")){if(o.disabled)return;const c=o.innerHTML;o.style.minWidth=o.offsetWidth+"px",o.disabled=!0,_loadingHtml(),o.innerHTML='<span style="display:inline-block;width:10px;height:10px;border:2px solid rgba(255,255,255,.5);border-top-color:#fff;border-radius:50%;animation:fd-spin .7s linear infinite;vertical-align:-1px"></span>';try{await openShareStats(i,o.dataset.name)}finally{o.disabled=!1,o.innerHTML=c,o.style.minWidth=""}}else if(o.classList.contains("sm-delete-btn")){if(!await showConfirmModal({title:t("shares_revoke_confirm_title"),message:t("shares_revoke_confirm_body"),danger:!0}))return;try{await apiCall(`/api/v1/shares/${i}`,"DELETE"),_smShares=_smShares.filter(l=>l.token!==i),_smShares.length?(o.closest(".sm-card")?.remove(),_smRenderFilters(),_smApplyFilter()):await loadShareManager({quiet:!0,refetch:!1})}catch(l){showMessage(t("shares_revoke_failed"),l.message)}}else if(o.classList.contains("sm-expiry-clear"))try{await apiCall(`/api/v1/shares/${i}`,"PATCH",{expires_at:null}),await loadShareManager({quiet:!0})}catch(c){showMessage(t("update_failed"),c.message)}})}async function loadShareManager({quiet:e=!1,refetch:n=!0}={}){const o=document.getElementById("sm-body");if(!o)return;const i=o.scrollTop;e||(o.innerHTML=Array.from({length:3},()=>`
        <div style="border:1px solid #e2e8f0;border-radius:10px;padding:14px;margin-bottom:10px">
            <span style="display:inline-block;width:160px;height:15px;border-radius:4px;
                background:linear-gradient(90deg,var(--fd-skel-base,#e2e8f0) 25%,var(--fd-skel-shine,#f1f5f9) 50%,var(--fd-skel-base,#e2e8f0) 75%);
                background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></span><br>
            <span style="display:inline-block;width:100px;height:11px;border-radius:4px;margin-top:6px;
                background:linear-gradient(90deg,var(--fd-skel-base,#e2e8f0) 25%,var(--fd-skel-shine,#f1f5f9) 50%,var(--fd-skel-base,#e2e8f0) 75%);
                background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></span>
        </div>`).join(""));try{if(n&&(_smShares=(await apiCall("/api/v1/shares","GET")).shares||[]),_smRenderFilters(),_smShares.length===0){++_smGen,o.innerHTML=`<p class="sm-empty">${t("shares_manager_empty")}</p>`;return}_smRenderList(o,e),e&&(o.scrollTop=i)}catch(c){o.innerHTML=`<p class="sm-empty" style="color:#ef4444">${escapeHtml(t("shares_load_failed",{msg:c.message}))}</p>`}}function _localDateTimeValue(e){const n=o=>String(o).padStart(2,"0");return`${e.getFullYear()}-${n(e.getMonth()+1)}-${n(e.getDate())}T${n(e.getHours())}:${n(e.getMinutes())}`}function _fmtExpiry(e){return e.toLocaleString(window.FDi18n?.lang||void 0,{year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit"})}function renderShareRow(e){const n=`${window.location.origin}/share/${e.token}`,o=escapeHtmlAttr(n),i=e.path.split("/").pop()||e.path,c=escapeHtmlAttr(i),l=escapeHtmlAttr(e.path),r=escapeHtmlAttr(e.path.slice(0,e.path.length-i.length)||"/"),s=e.created_at?new Date(e.created_at).toLocaleDateString():"?";let a="",d="";if(e.expires_at){const m=new Date(e.expires_at);a=m<new Date?`<span class="sm-badge expired">${t("shares_expired_label")} ${_fmtExpiry(m)}</span>`:`<span class="sm-badge">⏰ ${_fmtExpiry(m)}</span>`,d=_localDateTimeValue(m)}const u=(m,y,b,x=!1)=>`<label><input type="checkbox" class="sm-toggle" data-token="${e.token}" data-field="${m}" ${y?"checked":x?"disabled":""}><span>${b}</span></label>`,p=escapeHtmlAttr(t("shares_stats_button")),f=escapeHtmlAttr(t("shares_revoke_button"));return`<div class="sm-card" data-token="${e.token}">
        <div class="sm-top">
            <span class="sm-icon" aria-hidden="true">${e.is_dir?"📁":"📄"}</span>
            <div class="sm-main">
                <div class="sm-title"><span class="sm-name" title="${c}">${c}</span>${a}</div>
                <div class="sm-path" title="${l}"><bdi>${r}</bdi></div>
                <div class="sm-meta">${t("shares_info_created")} ${s} · ${t("shares_access_count",{n:e.access_count||0})}</div>
            </div>
        </div>
        <div class="sm-opts">
            ${u("require_account",e.require_account,t("shares_info_account_requirement"))}
            ${u("track_stats",e.track_stats,t("shares_info_stats_tracking"))}
            ${u("allow_preview",e.allow_preview,t("shares_info_preview"))}
            ${e.is_dir?"":u("allow_cdn_embed",e.allow_cdn_embed,t("shares_info_cdn_embed"),!_canPublish)}
            ${e.is_dir?u("allow_anon_upload",e.allow_anon_upload,t("shares_info_uploads_anyone"),!_canPublish):""}
            ${e.is_dir?u("allow_auth_upload",e.allow_auth_upload,t("shares_info_uploads_auth_only")):""}
        </div>
        <div class="sm-exp">
            <span>${t("shares_info_expiry")}</span>
            <input type="datetime-local" class="sm-expiry-input" data-token="${e.token}" value="${d}"
                aria-label="${escapeHtmlAttr(t("shares_info_expiry"))}">
            <button class="sm-expiry-clear" data-token="${e.token}" title="${escapeHtmlAttr(t("shares_expiry_remove_title"))}"
                aria-label="${escapeHtmlAttr(t("shares_expiry_remove_title"))}">✕</button>
            ${e.expires_at?"":`<span class="sm-never">${t("shares_info_never")}</span>`}
        </div>
        ${e.allow_cdn_embed&&!e.is_dir?`
        <div class="sm-cdn">
            <div class="sm-cdn-title">${t("shares_cdn_embed_title")}
                <span class="fd-tooltip-wrap">
                    <span class="fd-tooltip-icon" style="font-family:Playwrite Norge;font-style:italic">i</span>
                    <div class="fd-tooltip-bubble">${t("shares_cdn_embed_tooltip")}</div>
                </span>
            </div>
            <div class="sm-cdn-row">
                <input type="text" readonly value="${o}" aria-label="${escapeHtmlAttr(t("shares_cdn_embed_title"))}">
                <button class="sm-copy-btn" data-url="${o}">${t("shares_copy_button")}</button>
            </div>
        </div>`:""}
        <div class="sm-actions">
            ${e.track_stats?`<button class="sm-stats-btn" data-token="${e.token}" data-name="${c}" title="${p}" aria-label="${p}"><span class="sm-long">${p}</span><span class="sm-short">📊</span></button>`:""}
            <button class="sm-copy-btn" data-url="${o}"><span class="sm-long">${t("shares_copy_link_button")}</span><span class="sm-short">🔗 ${t("shares_copy_button")}</span></button>
            <button class="sm-delete-btn" data-token="${e.token}" title="${f}" aria-label="${f}"><span class="sm-long">${f}</span><span class="sm-short">🗑</span></button>
        </div>
    </div>`}function _shareActionLabel(e){const n=e||"view",o="share_action_"+n,i=t(o);return i!==o?i:n}async function openShareStats(e,n){try{const i=(await apiCall(`/api/v1/shares/${e}/stats`,"GET")).logs||[],c=`<span style="color:#94a3b8">${t("shares_stats_anonymous")}</span>`,l=i.length===0?`<tr><td colspan="3" style="padding:12px;color:#94a3b8;text-align:center">${t("shares_stats_no_accesses")}</td></tr>`:i.map(r=>`<tr style="border-top:1px solid #f1f5f9">
                <td style="padding:8px 12px;font-size:13px">${r.accessed_at?new Date(r.accessed_at).toLocaleString():"?"}</td>
                <td style="padding:8px 12px;font-size:13px">${r.username?escapeHtml(r.username):c}</td>
                <td style="padding:8px 12px;font-size:13px">${escapeHtmlAttr(_shareActionLabel(r.action))}</td>
            </tr>`).join("");showMessage(t("shares_stats_title",{name:n}),`<div tabindex="0" style="text-align:left;max-height:300px;overflow-y:auto"><table style="width:100%;border-collapse:collapse"><thead><tr style="background:#f8fafc">
                <th style="padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;text-align:left">${t("shares_stats_col_time")}</th>
                <th style="padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;text-align:left">${t("shares_stats_col_user")}</th>
                <th style="padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;text-align:left">${t("shares_stats_col_action")}</th>
            </tr></thead><tbody>${l}</tbody></table></div>`,!0)}catch(o){showMessage(t("stats_error"),o.message)}}function openUploadQueuePanel(e){document.getElementById("upload-queue-panel")?.remove();const n=document.createElement("div");n.id="upload-queue-panel",n.style.cssText=`
        position:fixed;top:0;left:0;width:100%;height:100%;
        background:rgba(0,0,0,0.55);display:flex;align-items:center;
        justify-content:center;z-index:10000;font-family:Inter,sans-serif;
    `;function o(){const c=window._uploadQueue||[],l=c.length===0?`<p style="color:#94a3b8;text-align:center;padding:1.5rem 0">${t("queue_empty")}</p>`:c.map((r,s)=>`
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
                        style="background:#dc2626;color:white;border:none;border-radius:6px;
                               padding:4px 10px;cursor:pointer;font-size:12px;flex-shrink:0">
                        Remove
                    </button>
                </div>`).join("");return`
        <div style="background:#0f172a;border-radius:14px;padding:1.5rem;
                    width:95vw;max-width:560px;max-height:80vh;overflow-y:auto;
                    color:#e2e8f0;position:relative">
            <div style="display:flex;justify-content:space-between;align-items:center;
                        margin-bottom:1rem;border-bottom:1px solid #334155;padding-bottom:.75rem">
                <span style="font-weight:700;font-size:16px">📋 Upload Queue (${c.length} pending)</span>
                <button id="qp-close" style="background:rgba(255,255,255,0.1);border:none;color:white;
                    border-radius:50%;width:28px;height:28px;cursor:pointer;font-size:16px;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <div id="qp-list">${l}</div>
            ${c.length>0?`<div style="margin-top:1rem;text-align:right">
                <button id="qp-clear-all"
                    style="background:#64748b;color:white;border:none;border-radius:7px;
                           padding:6px 14px;cursor:pointer;font-size:12px">Clear all</button>
            </div>`:""}
        </div>`}function i(){n.innerHTML=o(),n.querySelector("#qp-close").addEventListener("click",()=>{n.remove(),e&&e()}),n.querySelector("#qp-clear-all")?.addEventListener("click",()=>{window._uploadQueue=[],i(),e&&e()}),n.querySelectorAll(".qp-remove").forEach(c=>{c.addEventListener("click",()=>{const l=+c.dataset.qi;window._uploadQueue.splice(l,1),i(),e&&e()})}),n.addEventListener("click",c=>{c.target===n&&(n.remove(),e&&e())})}document.body.appendChild(n),i()}function openInterruptedManager(e){document.getElementById("interrupted-manager-panel")?.remove();const n=document.createElement("div");n.id="interrupted-manager-panel",n.className="modal-overlay",n.style.cssText=`
        position:fixed;top:0;left:0;width:100%;height:100%;
        background:rgba(0,0,0,0.55);display:flex;align-items:center;
        justify-content:center;z-index:10000;font-family:Inter,sans-serif;
    `;function o(r){const s=r.length===0?`<p style="color:#94a3b8;text-align:center;padding:1.5rem 0">${t("im_empty")}</p>`:r.map((a,d)=>{const u=a.total>0?Math.min(100,Math.round((a.nextChunkIdx||0)*(a.chunkSize||1)/a.total*100)):0;return`
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
                                <div style="background:#22c55e;height:6px;border-radius:4px;width:${u}%"></div>
                            </div>
                            <div style="font-size:11px;color:#64748b">${t("im_progress",{pct:u})}</div>
                        </div>
                        <div style="display:flex;flex-direction:column;gap:5px;flex-shrink:0">
                            <button class="im-resume" data-im="${d}"
                                style="background:#15803d;color:white;border:none;border-radius:6px;
                                       padding:5px 12px;cursor:pointer;font-size:12px;font-weight:600">
                                ▶ ${t("im_resume")}
                            </button>
                            <button class="im-discard" data-im="${d}"
                                style="background:#dc2626;color:white;border:none;border-radius:6px;
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
        </div>`}async function i(r){let s=r.nextChunkIdx||0;try{const d=await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${r.uploadToken}/status`,{method:"GET",headers:authToken?{Authorization:`Bearer ${authToken}`}:{}});if(d.ok){const u=await d.json();if(u.missing_chunks&&u.missing_chunks.length>0)s=u.missing_chunks[0];else if(!u.missing_chunks||u.missing_chunks.length===0){await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${r.uploadToken}/complete`,{method:"POST",headers:authToken?{Authorization:`Bearer ${authToken}`}:{}}),removeInterruptedUpload(r.uploadToken),e&&e(),n.remove(),loadDirectory(currentPath);return}}else{removeInterruptedUpload(r.uploadToken),e&&e(),l(getAllInterruptedUploads()),showMessage(t("im_expired_title"),t("im_expired_body",{name:r.filename}));return}}catch{}for(const d of activeUploads.values())if(d.uploadToken===r.uploadToken&&!d.paused&&["uploading","verifying"].includes(d.status)){showMessage(t("im_already_running_title"),t("im_already_running_body",{name:r.filename}));return}const a=document.createElement("input");a.type="file",a.style.display="none",document.body.appendChild(a),a.click(),a.addEventListener("change",async()=>{if(document.body.removeChild(a),!a.files.length)return;const d=a.files[0];if(d.name!==r.filename||d.size!==r.total){showMessage(t("im_mismatch_title"),t("im_mismatch_body",{expected:r.filename,expected_size:formatBytes(r.total),got:d.name,got_size:formatBytes(d.size)}));return}n.remove(),uploadChunked(d,r.destRel,{ownerType:r.ownerType,shareToken:r.shareToken||"",resumeToken:r.uploadToken,resumeFromChunk:s,resumeChunkSize:r.chunkSize,resumeAnonToken:r.anonDeviceToken}).then(()=>{loadDirectory(currentPath),e&&e()}).catch(u=>{u.name!=="PauseSignal"&&u.message!=="Upload cancelled"&&showMessage(t("im_resume_failed"),u.message),e&&e()})})}function c(){_detachModalKeys(),window.fdCloseOverlay(n),e&&e()}function l(r){n.innerHTML=o(r),n.querySelector("#im-close").addEventListener("click",c),n.addEventListener("click",s=>{s.target===n&&c()}),_attachModalKeys(null,c),n.querySelector("#im-discard-all")?.addEventListener("click",()=>{getAllInterruptedUploads().forEach(s=>removeInterruptedUpload(s.uploadToken)),l(getAllInterruptedUploads()),e&&e()}),n.querySelectorAll(".im-resume").forEach(s=>{s.addEventListener("click",async()=>{const d=getAllInterruptedUploads()[+s.dataset.im];d&&await i(d)})}),n.querySelectorAll(".im-discard").forEach(s=>{s.addEventListener("click",()=>{const d=getAllInterruptedUploads()[+s.dataset.im];d&&(removeInterruptedUpload(d.uploadToken),fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${d.uploadToken}/cancel`,{method:"DELETE",headers:authToken?{Authorization:`Bearer ${authToken}`}:{}}).catch(()=>{}),l(getAllInterruptedUploads()),e&&e())})})}document.body.appendChild(n),l(getAllInterruptedUploads())}document.addEventListener("DOMContentLoaded",()=>{if("serviceWorker"in navigator){const d=()=>navigator.serviceWorker.register(_APP_BASE+"/sw.js",{scope:_APP_BASE+"/"}).catch(u=>{console.warn("[FluxDrop] SW registration failed:",u)});document.readyState==="complete"?d():window.addEventListener("load",d,{once:!0})}let e=null,n=!1;function o(){if(document.getElementById("offline-banner"))return;const d=document.createElement("div");d.id="offline-banner",d.style.cssText=["position:fixed;top:0;left:0;width:100%;z-index:99999","background:#1e293b;color:#e2e8f0","display:flex;align-items:center;justify-content:center;gap:10px","padding:10px 16px;font-family:Inter,sans-serif;font-size:14px","font-weight:500;box-shadow:0 2px 8px rgba(0,0,0,0.3)","transform:translateY(-100%);transition:transform 0.3s ease"].join(";"),d.innerHTML=`
            <span style="font-size:18px">📡</span>
            <span id="offline-banner-text">Seems like you're offline. Please connect to the internet to access FluxDrop.</span>
        `,document.body.prepend(d),requestAnimationFrame(()=>requestAnimationFrame(()=>{d.style.transform="translateY(0)"}))}function i(){const d=document.getElementById("offline-banner");d&&(d.style.transform="translateY(-100%)",setTimeout(()=>d.remove(),320))}async function c(){try{const d=await fetch(`${API_BASE_URL}/api/v1/upload_session/config`,{method:"HEAD",cache:"no-store",signal:AbortSignal.timeout(4e3)});return d.ok||d.status<500}catch{return!1}}function l(){e||(e=setInterval(async()=>{if(await c())n=!1,i(),clearInterval(e),e=null;else{const u=document.getElementById("offline-banner-text");u&&(u.textContent="You're offline — retrying connection…")}},5e3))}function r(){n||(n=!0,o(),l())}function s(){c().then(d=>{d&&(n=!1,i(),clearInterval(e),e=null)})}window.addEventListener("offline",r),window.addEventListener("online",s),navigator.onLine||r(),document.addEventListener("keydown",d=>{if(d.key==="Escape"){if(!document.getElementById("preview-modal").classList.contains("hidden"))closePreview();else if(document.getElementById("mv-dialog-overlay"))window.fdCloseOverlay(document.getElementById("mv-dialog-overlay"));else if(document.getElementById("share-dialog-overlay"))window.fdCloseOverlay(document.getElementById("share-dialog-overlay"));else if(document.getElementById("ap-edit-overlay"))window.fdCloseOverlay(document.getElementById("ap-edit-overlay"));else if(document.getElementById("admin-panel-overlay"))window.fdCloseOverlay(document.getElementById("admin-panel-overlay"));else if(document.getElementById("profile-panel-overlay"))window.fdCloseOverlay(document.getElementById("profile-panel-overlay"));else if(document.getElementById("share-manager-overlay"))window.fdCloseOverlay(document.getElementById("share-manager-overlay"));else if(document.getElementById("profile-menu-modal"))window.fdCloseOverlay(document.getElementById("profile-menu-modal"));else if(!document.getElementById("message-modal").classList.contains("hidden"))hideModal("message-modal");else if(document.getElementById("trash-overlay"))window.fdCloseOverlay(document.getElementById("trash-overlay"));else if(document.getElementById("fd-ctx-menu"))_dismissContextMenu();else if(_selectedPaths.size>0&&!document.getElementById("trash-overlay")){const u=document.activeElement;if(u&&(u.tagName==="INPUT"&&u.type!=="checkbox"||u.tagName==="TEXTAREA"||u.isContentEditable))return;_clearSelection(),_updateSelBar()}}}),document.addEventListener("keydown",d=>{if(d.key!=="Delete")return;const u=document.activeElement;u&&(u.tagName==="INPUT"||u.tagName==="TEXTAREA"||u.isContentEditable)||document.getElementById("preview-modal").classList.contains("hidden")&&(document.getElementById("mv-dialog-overlay")||document.getElementById("share-dialog-overlay")||document.getElementById("ap-edit-overlay")||document.getElementById("admin-panel-overlay")||document.getElementById("profile-panel-overlay")||document.getElementById("share-manager-overlay")||document.getElementById("profile-menu-modal")||document.getElementById("trash-overlay")||document.getElementById("fd-conflict-overlay")||_selectedPaths.size!==0&&(d.preventDefault(),_trashSelectedPaths([..._selectedPaths])))}),new URLSearchParams(window.location.search).has("verified")&&(showMessage(t("verify_success_title"),t("verify_success_msg")),window.history.replaceState({},document.title,window.location.pathname)),renderApp(),setTimeout(async()=>{if(!("serviceWorker"in navigator)||!navigator.serviceWorker.controller)return;try{if(sessionStorage.getItem("fd_just_updated")==="1"){sessionStorage.removeItem("fd_just_updated");return}}catch{}if(!SCRIPT_VERSION_RAW.includes("@@"))try{if(await new Promise((p,f)=>{const m=new MessageChannel;m.port1.onmessage=y=>y.data?.version?p(y.data.version):f(),navigator.serviceWorker.controller.postMessage({type:"GET_VERSION"},[m.port2]),setTimeout(()=>f(new Error("sw-timeout")),3e3)})===SCRIPT_VERSION)return}catch{}const d=[_APP_BASE+"/index.html",_APP_BASE+"/script.js"];try{const u=await caches.open("fluxdrop-v-d538d268");(await Promise.all(d.map(async f=>{try{const m=await fetch(f,{method:"HEAD",cache:"no-store",signal:AbortSignal.timeout(8e3)});if(!m.ok)return!1;const y=await u.match(f,{ignoreMethod:!0});if(!y)return!0;const b=m.headers.get("ETag"),x=y.headers.get("ETag");if(b&&x)return b!==x;const k=m.headers.get("Last-Modified"),g=y.headers.get("Last-Modified");if(k&&g)return k!==g;const w=m.headers.get("Content-Length"),h=y.headers.get("Content-Length");return!!(w&&h&&w!==h)}catch{return!1}}))).some(f=>f)&&_showUpdateBanner()}catch{}},2e3)});function initFooter(){const e=document.createElement("footer");if(e.id="fluxdrop-footer",Object.assign(e.style,{width:"100%",maxWidth:"64rem",marginTop:"auto",paddingTop:"0.75rem",paddingBottom:"0.5rem",color:"#475569",fontSize:"11px",fontFamily:"sans-serif",fontWeight:"300",textAlign:"right",lineHeight:"1.5"}),!document.getElementById("fd-retry-pulse-style")){const l=document.createElement("style");l.id="fd-retry-pulse-style",l.textContent="@keyframes fd-retry-pulse{0%,100%{opacity:1}50%{opacity:.45}}",document.head.appendChild(l)}const n=(l,r)=>`
        <div>${escapeHtml(t("footer_fluxdrop_pp"))} | <a href="https://github.com/ArsenijN/server/" style="color: inherit; text-decoration: underline;">${escapeHtml(t("footer_github_repo"))}</a></div>
        <div>${escapeHtml(t("footer_creator_note"))}</div>
        <div><button onclick="showPolicyModal('tos')" style="background:none; border:none; color:inherit; cursor:pointer; text-decoration:underline; padding:0; font:inherit;">${escapeHtml(t("footer_tos"))}</button> | <button onclick="showPolicyModal('pp')" style="background:none; border:none; color:inherit; cursor:pointer; text-decoration:underline; padding:0; font:inherit;">${escapeHtml(t("footer_pp"))}</button></div>
        <div>Script v.${SCRIPT_VERSION} · SW v.${l} · Server v.${r||"?"}</div>
    `;let o="...",i="...";const c=()=>{e.innerHTML=n(o,i)};if(e.innerHTML=n(o,i),document.body.appendChild(e),document.addEventListener("fd-locale-change",c),navigator.serviceWorker&&navigator.serviceWorker.controller){const l=new MessageChannel;l.port1.onmessage=r=>{r.data&&r.data.version&&(o=r.data.version,c())},navigator.serviceWorker.controller.postMessage({type:"GET_VERSION"},[l.port2])}else o="N/A",c();fetch(API_BASE_URL+"/api/v1/status.json",{cache:"no-store"}).then(l=>l.ok?l.json():null).then(l=>{l&&l.server_version&&(i=l.server_version,c())}).catch(()=>{i="?",c()})}document.addEventListener("DOMContentLoaded",initFooter);const _NOTICE_SEEN_KEY="fluxdrop_notice_seen",_NOTICE_ACCENT={info:"#38bdf8",ok:"#4ade80",warning:"#fbbf24",critical:"#f87171"};function _noticeSeen(e){try{return localStorage.getItem(_NOTICE_SEEN_KEY)===String(e)}catch{return!1}}function _markNoticeSeen(e){try{localStorage.setItem(_NOTICE_SEEN_KEY,String(e))}catch{}}function _noticeLang(){try{return(localStorage.getItem("fluxdrop_lang")||"en").toLowerCase()}catch{return"en"}}function _noticeText(e){const n=e.i18n||{},o=_noticeLang(),i=n[o]||n[o.split("-")[0]]||{};return{title:i.title||e.title||"",body:i.body||e.body||""}}let _activeNotice=null;function _renderNotice(e){const n=_noticeText(e);document.getElementById("notice-modal-accent").style.background=_NOTICE_ACCENT[e.level]||_NOTICE_ACCENT.info,document.getElementById("notice-modal-title").textContent=n.title;const o=document.getElementById("notice-modal-body");o.textContent=n.body,o.style.display=n.body?"":"none";const i=document.getElementById("notice-modal-meta");if(e.expires_at){const l=new Date(e.expires_at.replace(" ","T")+"Z");i.textContent=isNaN(l)?"":l.toLocaleString()}else i.textContent="";i.style.display=i.textContent?"":"none";const c=document.getElementById("notice-modal-ok");c.textContent=window.t?t("ok"):"OK"}document.addEventListener("fd-locale-change",()=>{_activeNotice&&!document.getElementById("notice-modal")?.classList.contains("hidden")&&_renderNotice(_activeNotice)});async function checkSiteNotice(){let e=null;try{const i=await fetch(`${API_BASE_URL}/api/v1/notice`,{cache:"no-store"});if(!i.ok)return;e=(await i.json()).notice}catch{return}if(!e||!(e.level==="critical")&&_noticeSeen(e.id))return;_activeNotice=e,_renderNotice(e);const o=()=>{_activeNotice=null,_markNoticeSeen(e.id),hideModal("notice-modal")};document.getElementById("notice-modal-ok").onclick=o,showModal("notice-modal"),_attachModalKeys(o,o)}document.addEventListener("DOMContentLoaded",checkSiteNotice);function fdModalGallery(){document.getElementById("fd-modal-gallery")?.remove();const e=()=>{const a=_getFileRows()[0];return a||showToast("Open a folder that has files first",{type:"error"}),a},n=new Set(["message-modal","notice-modal","preview-modal"].map(a=>document.getElementById(a)).filter(Boolean)),o=()=>{document.querySelectorAll('[role="dialog"], .modal-overlay, [id$="-overlay"], #profile-menu-modal, #fd-auth-modal, #fd-info-panel, #fd-ctx-menu, #upload-queue-panel, #interrupted-manager-panel, #fd-update-banner, [id^="fd-spinner-"]').forEach(a=>{a.id!=="fd-modal-gallery"&&(n.has(a)?a.classList.add("hidden"):a.remove())})},i=()=>new Promise(a=>{const d=document.createElement("canvas");d.width=d.height=256;const u=d.getContext("2d"),p=u.createLinearGradient(0,0,256,256);p.addColorStop(0,"#2563eb"),p.addColorStop(1,"#7c3aed"),u.fillStyle=p,u.fillRect(0,0,256,256),d.toBlob(f=>a(new File([f],"sample.png",{type:"image/png"})),"image/png")}),c=[["Basics",[["Message",()=>showMessage(t("file_info_title"),"Sample message text.")],["Prompt",()=>showPromptModal({title:t("new_folder")||"Prompt",label:"Name",defaultValue:"example"})],["Confirm",()=>showConfirmModal({title:t("trash"),message:"Sample confirmation text."})],["Spinner (2 s)",()=>{const a=showSpinnerOverlay(t("mv_renaming"),{minMs:0});setTimeout(()=>a&&a(),2e3)}],["Toast: info",()=>showToast("Sample info",{type:"info"})],["Toast: success",()=>showToast("Sample success")],["Toast: error",()=>showToast("Sample error",{type:"error"})],["Update banner",()=>_showUpdateBanner()]]],["Account",[["Login",()=>_showAuthModal("login")],["Register",()=>_showAuthModal("register")],["Welcome screen",()=>_showWelcomeScreen()],["Profile menu",()=>openProfileMenu()],["Profile panel",()=>openProfilePanel()],["Avatar editor",async()=>_showAvatarEditor(await i(),()=>{})],["Admin panel",()=>openAdminPanel()]]],["Policies",[["Terms",()=>showPolicyModal("tos")],["Privacy",()=>showPolicyModal("pp")],["Agreement prompt (preview)",()=>_showPolicyAgreementModal("tos","",()=>{},{preview:!0})]]],["Files",[["Context menu",()=>{const a=e();a&&_showContextMenu(260,220,a)}],["Info panel",()=>{const a=e();a&&_showFileInfo(a)}],["⚠ Move / rename / copy",()=>{const a=e();a&&openMoveDialog(a.dataset.path)}],["Name clash (upload)",()=>_askUploadConflict({name:"example.txt",size:2048,lastModified:Date.now()},"/example.txt",{existing:{name:"example.txt",size:1900,mtime:new Date(Date.now()-864e5).toISOString()}})],["Trash",()=>openTrashView()],["Trash batch notice",()=>{localStorage.removeItem(_TRASH_BATCH_NOTICE_KEY),_showTrashBatchNotice(3,30)}],["Upload queue",()=>openUploadQueuePanel(()=>{})],["Interrupted uploads",()=>openInterruptedManager(()=>{})]]],["Sharing",[["⚠ Share dialog (creates a link)",()=>{const a=e();a&&openShareDialog(a.dataset.path,a.dataset.isDir==="1")}],["Share manager",()=>openShareManager()]]]],l=document.createElement("div");l.id="fd-modal-gallery",l.setAttribute("role","complementary"),l.setAttribute("aria-label","Modal gallery"),l.style.cssText="position:fixed;left:12px;bottom:12px;z-index:2147483000;width:230px;max-height:70vh;overflow:auto;background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,.4);font:12px Inter,sans-serif;padding:8px";const r="display:block;width:100%;text-align:left;margin:2px 0;padding:4px 8px;border:none;border-radius:5px;background:#1e293b;color:#e2e8f0;cursor:pointer;font:inherit";l.innerHTML=`<div style="display:flex;align-items:center;gap:4px;margin-bottom:6px">
            <strong style="flex:1">Modal gallery</strong>
            <button data-lang="en" style="${r};width:auto;display:inline-block">EN</button>
            <button data-lang="uk" style="${r};width:auto;display:inline-block">UK</button>
            <button data-close style="${r};width:auto;display:inline-block" aria-label="Close gallery">✕</button>
        </div>
        <button data-closeall style="${r};background:#7f1d1d">Close all open modals</button>`+c.map(([a,d],u)=>`<div style="margin:8px 0 2px;color:#94a3b8;font-weight:600">${a}</div>`+d.map(([p],f)=>`<button data-entry="${u}:${f}" style="${r}">${escapeHtml(p)}</button>`).join("")).join("");let s=null;l.addEventListener("click",async a=>{const d=a.target.closest("button");if(!d)return;if(a.stopPropagation(),d.hasAttribute("data-close"))return l.remove();if(d.hasAttribute("data-closeall"))return o();if(d.dataset.lang){if(await FDi18n.setLang(d.dataset.lang),!s)return}else s=d.dataset.entry;const[u,p]=s.split(":").map(Number);o();try{await c[u][1][p][1]()}catch(f){console.error("[modal gallery]",f),showToast(String(f.message||f),{type:"error"})}}),document.body.appendChild(l)}window.fdModalGallery=fdModalGallery,document.addEventListener("DOMContentLoaded",()=>{new URLSearchParams(location.search).has("modals")&&setTimeout(fdModalGallery,1500)});
//# sourceMappingURL=script.js.map
