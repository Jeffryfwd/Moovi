async function Post(file) {
    try {
        const formData = new FormData();
        formData.append('archivo_pdf', file);

        const response = await fetch('http://127.0.0.1:8000/api/procesar-pdf/', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        console.log('Datos extraídos:', data);
    } catch (error) {
        console.error('Error:', error);
    }
}

export default Post;

