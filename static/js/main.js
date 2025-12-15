// Basic client-side interactions for upload UI
document.addEventListener('DOMContentLoaded', function(){
    const drop = document.getElementById('dropzone');
    const input = document.getElementById('fileInput');
    const fileName = document.getElementById('fileName');
    const classifyBtn = document.getElementById('classifyBtn');
    const resetBtn = document.getElementById('resetBtn');
    const overlay = document.getElementById('overlay');
    const advToggle = document.getElementById('advToggle');
    const threatLevel = document.getElementById('threatLevel');

    if(!drop || !input) return;

    // click opens file dialog
    drop.addEventListener('click', ()=> input.click());

    // drag & drop
    drop.addEventListener('dragover', (e)=>{ e.preventDefault(); drop.classList.add('dragover'); });
    drop.addEventListener('dragleave', ()=> drop.classList.remove('dragover'));
    drop.addEventListener('drop', (e)=>{
        e.preventDefault();
        drop.classList.remove('dragover');
        const f = e.dataTransfer.files[0];
        if(f) { input.files = e.dataTransfer.files; handleFileSelect(f); }
    });

    // change
    input.addEventListener('change', (e)=>{
        const f = e.target.files[0];
        if(f) handleFileSelect(f);
    });

    resetBtn.addEventListener('click', function(){
        input.value = '';
        fileName.textContent = '';
        classifyBtn.disabled = true;
    });

    function handleFileSelect(file){
        fileName.textContent = file.name + " · " + Math.round(file.size/1024) + " KB";
        classifyBtn.disabled = false;
        // a little playful threat-level randomizer (dummy)
        const levels = ['LOW','MEDIUM','HIGH'];
        const pick = levels[Math.floor(Math.random()*levels.length)];
        threatLevel.textContent = pick;
    }

    // on submit — play quick overlay animation and then allow submit
    const form = document.getElementById('uploadForm');
    if(form){
        form.addEventListener('submit', function(e){
            // show overlay for a short moment for effect (then let form submit)
            overlay.classList.remove('hidden');

            // if you want to actually wait then submit: simulate 900ms and submit
            // but to avoid interfering with server, we will delay only briefly
            e.preventDefault();
            setTimeout(()=> {
                overlay.classList.add('hidden');
                form.submit();
            }, 800);
        });
    }

    // visual effect: toggling advanced analysis changes a stat (dummy)
    if(advToggle){
        advToggle.addEventListener('change', function(){
            if(this.checked){
                threatLevel.textContent = 'SCANNING';
            } else {
                threatLevel.textContent = 'LOW';
            }
        });
    }

    // On result pages, animate radial from data-val
    document.querySelectorAll('.radial').forEach(el=>{
        const val = parseInt(el.dataset.val || '0', 10);
        let cur = 0;
        const step = Math.max(1, Math.floor(val/20));
        const interval = setInterval(()=>{
            cur += step;
            if(cur >= val){ cur = val; clearInterval(interval); }
            el.style.setProperty('--p', cur + '%');
        }, 16);
    });
});
