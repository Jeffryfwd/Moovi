import React from 'react'
import PHome from '../Pages/PHome'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';


function Routing() {
  return (
    <div>
        <Router>

            <Routes>
            <Route path='/' element={<PHome/>}></Route>
                
            </Routes>
    
        </Router>    


    </div>
  )
}

export default Routing
