const form=document.getElementById('lookup');
const result=document.getElementById('result');
form.addEventListener('submit',async e=>{
  e.preventDefault();
  const q=document.getElementById('q').value.trim();
  if(!q)return;
  result.classList.remove('hidden');
  result.textContent='Consultando envío…';
  try{
    const r=await fetch('/api/tracking/lookup?q='+encodeURIComponent(q));
    if(!r.ok)throw Error();
    const d=await r.json();
    const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const loc=o=>[o?.city,o?.country].filter(Boolean).map(esc).join(', ')||'Por confirmar';
    result.innerHTML='<div class="result-card"><div class="result-head"><strong>'+esc(d.tracking_number)+'</strong><span>'+esc(d.status)+'</span></div>'+
      '<p class="hint">Pedido '+esc(d.order_ref)+' · '+esc(d.carrier)+'</p>'+
      '<div class="route"><div><small>ORIGEN</small><b>'+loc(d.origin)+'</b></div><div><small>DESTINO</small><b>'+loc(d.destination)+'</b></div></div>'+
      '<p class="hint">Entrega estimada: '+esc(d.estimated_delivery||'Por confirmar')+'</p><div class="timeline">'+
      (d.events||[]).map(x=>'<article><b>'+esc(x.status)+'</b><p>'+esc(x.description)+'</p><small>'+esc(x.location||'')+' · '+esc(x.source_label)+' · '+esc(x.created_at)+'</small></article>').join('')+
      '</div></div>';
  }catch(_){
    result.innerHTML='<div class="result-card error">No se encontró información de seguimiento. Verifica el número e inténtalo nuevamente.</div>';
  }
});