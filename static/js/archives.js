(() => {
  const app = document.getElementById('archive-app');
  const list = document.getElementById('archive-list');
  const message = document.getElementById('archive-message');
  const upload = document.getElementById('upload-form');
  const uploadMessage = document.getElementById('upload-message');
  const names = {identity: 'Identity', document: 'Health document', video: 'Video'};
  const url = (template, id) => template.replace('FILE_ID', encodeURIComponent(id));
  async function loadArchives() {
    message.textContent = 'Loading your archive…';
    try {
      const response = await fetch(app.dataset.listUrl, {headers: {'Accept': 'application/json'}});
      if (response.redirected) { window.location.assign(response.url); return; }
      if (!response.ok) throw new Error('Could not load the archive.');
      const data = await response.json();
      list.replaceChildren();
      message.textContent = data.archives.length ? '' : 'No files have been saved yet.';
      for (const archive of data.archives) {
        const item = document.createElement('article'); item.className = 'archive-item';
        const title = document.createElement('strong'); title.textContent = names[archive.category] || archive.category;
        const details = document.createElement('small'); details.textContent = `Uploaded: ${archive.created_at} · ID: ${archive.id}`;
        const controls = document.createElement('div'); controls.className = 'archive-controls';
        const select = document.createElement('select'); select.setAttribute('aria-label', 'Download algorithm');
        ['AES', 'DES', 'RC4'].forEach(value => { const option = document.createElement('option'); option.value = value; option.textContent = value; select.append(option); });
        const download = document.createElement('a'); download.className = 'button secondary'; download.textContent = 'Download';
        const updateLink = () => { download.href = url(app.dataset.downloadTemplate, archive.id) + '?algorithm=' + encodeURIComponent(select.value); };
        select.addEventListener('change', updateLink); updateLink();
        const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'button danger'; remove.textContent = 'Delete';
        remove.addEventListener('click', async () => {
          if (!window.confirm('Delete this file? This action cannot be undone.')) return;
          remove.disabled = true;
          try {
            const body = new FormData(); body.append('csrf_token', app.dataset.csrf);
            const response = await fetch(url(app.dataset.deleteTemplate, archive.id), {method:'POST', body});
            if (response.redirected) { window.location.assign(response.url); return; }
            const text = await response.text();
            if (!response.ok) throw new Error(text || 'Could not delete the file.');
            await loadArchives(); message.textContent = text;
          } catch (error) { message.textContent = error.message || 'Could not delete the file.'; remove.disabled = false; }
        });
        controls.append(select, download, remove); item.append(title, details, controls); list.append(item);
      }
    } catch (error) { message.textContent = error.message || 'Could not load the archive.'; }
  }
  upload.addEventListener('submit', async event => {
    event.preventDefault(); const button = upload.querySelector('button[type=submit]'); button.disabled = true; uploadMessage.textContent = 'Uploading file…';
    try {
      const response = await fetch(upload.action, {method:'POST', body:new FormData(upload)});
      if (response.redirected) { window.location.assign(response.url); return; }
      const text = await response.text();
      if (!response.ok) throw new Error(text || 'Could not upload the file.');
      uploadMessage.textContent = text; upload.reset(); await loadArchives();
    } catch (error) { uploadMessage.textContent = error.message || 'Could not upload the file.'; }
    finally { button.disabled = false; }
  });
  loadArchives();
})();
