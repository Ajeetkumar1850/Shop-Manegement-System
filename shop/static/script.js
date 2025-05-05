
function readText(text) {
    fetch('/speak', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({text: text})
    });
}



{/* <button onclick="readText('{{ page_content_to_read }}')" class="btn btn-info btn-sm">
    <i class="fas fa-volume-up"></i> Read This
</button> */}