import React, { useState } from 'react'
import Post from '../Services/Post'

function Home() {
    const [file, setFile] = useState(null);

    const cargarFile = (e) => {
        setFile(e.target.files[0]); // Guardamos el archivo en el estado
    }

    async function enviar(e) {
        e.preventDefault();
        try {
            if (file) {
                await Post(file);  // Enviamos el archivo al backend
                alert('Se envió el pdf al backend');
            } else {
                alert('Por favor, selecciona un archivo primero');
            }
        } catch (error) {
            alert('Hubo un error al enviar el pdf al backend', error);
        }
    }

    return (
        <div>
            <h3>Enviar Pdf</h3>
            <form onSubmit={enviar}>
                <label htmlFor="fileInput">Pdf</label>
                <input 
                    id="fileInput"
                    type="file"
                    onChange={cargarFile} 
                />
                <button type="submit">Enviar</button>
            </form>
        </div>
    )
}

export default Home;
