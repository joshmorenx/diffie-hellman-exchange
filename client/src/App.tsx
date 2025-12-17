import { Routes, Route } from 'react-router-dom'
import './App.css'
import Home from './pages/Home.tsx'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
    </Routes>
  )
}