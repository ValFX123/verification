import { useState, useEffect, useCallback } from 'react'
import './App.css'

// Enhanced product data with descriptions and stock
const products = [
  {
    id: 1,
    name: 'Minimalist Ceramic Vase',
    price: 49.99,
    originalPrice: 69.99,
    image: 'https://images.unsplash.com/photo-1581783342308-f792ca11df53?w=600&h=600&fit=crop',
    images: [
      'https://images.unsplash.com/photo-1581783342308-f792ca11df53?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1578500494198-246f612d3b3d?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1580480055273-228ff5388ef8?w=600&h=600&fit=crop'
    ],
    description: 'Handcrafted ceramic vase with a minimalist design. Perfect for displaying fresh or dried flowers. Made from premium clay with a smooth matte finish.',
    category: 'Home Decor',
    badge: 'sale',
    rating: 4.8,
    reviews: 124,
    stock: 15,
    sku: 'VASE-001'
  },
  {
    id: 2,
    name: 'Organic Cotton Throw Blanket',
    price: 89.99,
    originalPrice: null,
    image: 'https://images.unsplash.com/photo-1580480055273-228ff5388ef8?w=600&h=600&fit=crop',
    images: [
      'https://images.unsplash.com/photo-1580480055273-228ff5388ef8?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1580587771525-78b9dba3b91d?w=600&h=600&fit=crop'
    ],
    description: 'Luxuriously soft organic cotton throw blanket. Ethically sourced and perfect for cozy evenings. Available in multiple pastel colors.',
    category: 'Textiles',
    badge: 'new',
    rating: 4.9,
    reviews: 89,
    stock: 23,
    sku: 'BLNK-002'
  },
  {
    id: 3,
    name: 'Handcrafted Wooden Bowl Set',
    price: 64.99,
    originalPrice: null,
    image: 'https://images.unsplash.com/photo-1610701596007-11502861dcfa?w=600&h=600&fit=crop',
    images: [
      'https://images.unsplash.com/photo-1610701596007-11502861dcfa?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1610701596169-6e2175e5a989?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1594385208974-2e75f8d7bb48?w=600&h=600&fit=crop'
    ],
    description: 'Set of 3 handcrafted wooden bowls made from sustainable acacia wood. Each piece is unique with natural grain patterns. Food-safe finish.',
    category: 'Kitchen',
    badge: 'bestseller',
    rating: 4.7,
    reviews: 203,
    stock: 8,
    sku: 'BOWL-003'
  },
  {
    id: 4,
    name: 'Scented Soy Candle Collection',
    price: 34.99,
    originalPrice: null,
    image: 'https://images.unsplash.com/photo-1602825418221-7cfee7f6f88b?w=600&h=600&fit=crop',
    images: [
      'https://images.unsplash.com/photo-1602825418221-7cfee7f6f88b?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1603006905003-be42556265a5?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1570823336712-6a08a0a9e9ec?w=600&h=600&fit=crop'
    ],
    description: 'Collection of 3 hand-poured soy candles with essential oils. Long-lasting burn time with notes of lavender, vanilla, and eucalyptus.',
    category: 'Home Fragrance',
    badge: 'new',
    rating: 4.6,
    reviews: 156,
    stock: 42,
    sku: 'CNDL-004'
  },
  {
    id: 5,
    name: 'Linen Table Runner',
    price: 42.99,
    originalPrice: 54.99,
    image: 'https://images.unsplash.com/photo-1616627547584-bf28cee262db?w=600&h=600&fit=crop',
    images: [
      'https://images.unsplash.com/photo-1616627547584-bf28cee262db?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1616486029423-aaa4789e8c9a?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1534349762913-96c8713d8c91?w=600&h=600&fit=crop'
    ],
    description: 'Premium linen table runner with natural texture. Adds elegance to any dining table. Machine washable and gets softer with each wash.',
    category: 'Textiles',
    badge: 'sale',
    rating: 4.8,
    reviews: 67,
    stock: 19,
    sku: 'RUNR-005'
  },
  {
    id: 6,
    name: 'Modern Wall Art Print',
    price: 79.99,
    originalPrice: null,
    image: 'https://images.unsplash.com/photo-1513519245088-0e12902e5a38?w=600&h=600&fit=crop',
    images: [
      'https://images.unsplash.com/photo-1513519245088-0e12902e5a38?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1513519245088-0e12902e5a38?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1534349762913-96c8713d8c91?w=600&h=600&fit=crop'
    ],
    description: 'Contemporary abstract wall art print on premium paper. Framed in sustainable wood. Adds a modern touch to any room.',
    category: 'Home Decor',
    badge: null,
    rating: 4.9,
    reviews: 234,
    stock: 31,
    sku: 'ARTP-006'
  },
  {
    id: 7,
    name: 'Artisan Coffee Mug Set',
    price: 38.99,
    originalPrice: null,
    image: 'https://images.unsplash.com/photo-1514228742587-6b1558fcca3d?w=600&h=600&fit=crop',
    images: [
      'https://images.unsplash.com/photo-1514228742587-6b1558fcca3d?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1514228742587-6b1558fcca3d?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1577937927633-2d9f3a2f7c60?w=600&h=600&fit=crop'
    ],
    description: 'Set of 4 handmade ceramic coffee mugs. Each mug features a unique glaze pattern. Microwave and dishwasher safe.',
    category: 'Kitchen',
    badge: 'bestseller',
    rating: 4.7,
    reviews: 178,
    stock: 27,
    sku: 'MUGS-007'
  },
  {
    id: 8,
    name: 'Botanical Plant Pot',
    price: 29.99,
    originalPrice: null,
    image: 'https://images.unsplash.com/photo-1485955900006-10f4d324d411?w=600&h=600&fit=crop',
    images: [
      'https://images.unsplash.com/photo-1485955900006-10f4d324d411?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1459156212016-c812468e2115?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1463936575829-25148e1791de?w=600&h=600&fit=crop'
    ],
    description: 'Elegant ceramic plant pot with drainage hole. Perfect for succulents and small plants. Includes matching saucer.',
    category: 'Garden',
    badge: 'new',
    rating: 4.8,
    reviews: 145,
    stock: 36,
    sku: 'POTP-008'
  },
  {
    id: 9,
    name: 'Woven Storage Basket',
    price: 54.99,
    originalPrice: null,
    image: 'https://images.unsplash.com/photo-1595341888016-a392ef81b7de?w=600&h=600&fit=crop',
    images: [
      'https://images.unsplash.com/photo-1595341888016-a392ef81b7de?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1595341888016-a392ef81b7de?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1534349762913-96c8713d8c91?w=600&h=600&fit=crop'
    ],
    description: 'Handwoven storage basket made from natural seagrass. Perfect for organizing blankets, toys, or magazines. Durable and stylish.',
    category: 'Home Decor',
    badge: null,
    rating: 4.7,
    reviews: 92,
    stock: 14,
    sku: 'BSKT-009'
  },
  {
    id: 10,
    name: 'Marble Serving Tray',
    price: 72.99,
    originalPrice: 89.99,
    image: 'https://images.unsplash.com/photo-1610701596169-6e2175e5a989?w=600&h=600&fit=crop',
    images: [
      'https://images.unsplash.com/photo-1610701596169-6e2175e5a989?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1610701596007-11502861dcfa?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1594385208974-2e75f8d7bb48?w=600&h=600&fit=crop'
    ],
    description: 'Elegant marble serving tray with brass handles. Ideal for entertaining guests or as a decorative piece. Each marble pattern is unique.',
    category: 'Kitchen',
    badge: 'sale',
    rating: 4.9,
    reviews: 167,
    stock: 11,
    sku: 'TRAY-010'
  },
  {
    id: 11,
    name: 'Cashmere Blend Scarf',
    price: 95.99,
    originalPrice: null,
    image: 'https://images.unsplash.com/photo-1601924994980-42c5b2cb1a99?w=600&h=600&fit=crop',
    images: [
      'https://images.unsplash.com/photo-1601924994980-42c5b2cb1a99?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1580480055273-228ff5388ef8?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=600&h=600&fit=crop'
    ],
    description: 'Luxuriously soft cashmere blend scarf. Lightweight yet warm. Available in subtle pastel shades to complement any outfit.',
    category: 'Textiles',
    badge: 'new',
    rating: 4.8,
    reviews: 78,
    stock: 22,
    sku: 'SCRF-011'
  },
  {
    id: 12,
    name: 'Essential Oil Diffuser',
    price: 58.99,
    originalPrice: null,
    image: 'https://images.unsplash.com/photo-1608571423902-eed4a5ad8108?w=600&h=600&fit=crop',
    images: [
      'https://images.unsplash.com/photo-1608571423902-eed4a5ad8108?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1602825418221-7cfee7f6f88b?w=600&h=600&fit=crop',
      'https://images.unsplash.com/photo-1603006905003-be42556265a5?w=600&h=600&fit=crop'
    ],
    description: 'Ultrasonic essential oil diffuser with LED mood lighting. Whisper-quiet operation. Auto shut-off feature for safety.',
    category: 'Home Fragrance',
    badge: 'bestseller',
    rating: 4.7,
    reviews: 289,
    stock: 18,
    sku: 'DIFF-012'
  }
]

const categories = ['All', 'Home Decor', 'Textiles', 'Kitchen', 'Home Fragrance', 'Garden']

// Testimonials data
const testimonials = [
  {
    id: 1,
    name: 'Emma Richardson',
    role: 'Interior Designer',
    content: 'The quality of products from Pastel Shop is exceptional. I regularly recommend them to my clients for their minimalist aesthetic and durability.',
    avatar: 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=100&h=100&fit=crop',
    rating: 5
  },
  {
    id: 2,
    name: 'James Chen',
    role: 'Verified Customer',
    content: 'Fast shipping and beautiful packaging. The ceramic vase exceeded my expectations. Will definitely be ordering again!',
    avatar: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=100&h=100&fit=crop',
    rating: 5
  },
  {
    id: 3,
    name: 'Sophie Martinez',
    role: 'Home Blogger',
    content: 'As someone who writes about home decor, I can confidently say Pastel Shop offers some of the best curated items I\'ve seen. Truly special pieces.',
    avatar: 'https://images.unsplash.com/photo-1438761681033-6461ffad8d80?w=100&h=100&fit=crop',
    rating: 5
  }
]

function App() {
  const [cart, setCart] = useState([])
  const [isCartOpen, setIsCartOpen] = useState(false)
  const [selectedCategory, setSelectedCategory] = useState('All')
  const [searchQuery, setSearchQuery] = useState('')
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [visibleProducts, setVisibleProducts] = useState([])

  // Filter products based on category and search
  useEffect(() => {
    let filtered = products
    
    if (selectedCategory !== 'All') {
      filtered = filtered.filter(p => p.category === selectedCategory)
    }
    
    if (searchQuery) {
      filtered = filtered.filter(p => 
        p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.category.toLowerCase().includes(searchQuery.toLowerCase())
      )
    }
    
    setVisibleProducts(filtered)
  }, [selectedCategory, searchQuery])

  // Add to cart
  const addToCart = (product) => {
    setCart(prevCart => {
      const existingItem = prevCart.find(item => item.id === product.id)
      if (existingItem) {
        return prevCart.map(item =>
          item.id === product.id
            ? { ...item, quantity: item.quantity + 1 }
            : item
        )
      }
      return [...prevCart, { ...product, quantity: 1 }]
    })
    
    // Show subtle animation feedback
    const event = new CustomEvent('addToCart', { detail: { product } })
    window.dispatchEvent(event)
  }

  // Remove from cart
  const removeFromCart = (productId) => {
    setCart(prevCart => prevCart.filter(item => item.id !== productId))
  }

  // Update quantity
  const updateQuantity = (productId, newQuantity) => {
    if (newQuantity <= 0) {
      removeFromCart(productId)
      return
    }
    setCart(prevCart =>
      prevCart.map(item =>
        item.id === productId
          ? { ...item, quantity: newQuantity }
          : item
      )
    )
  }

  // Calculate totals
  const cartTotal = cart.reduce((sum, item) => sum + item.price * item.quantity, 0)
  const cartItemCount = cart.reduce((sum, item) => sum + item.quantity, 0)

  return (
    <div className="app">
      {/* Header */}
      <header className="header animate-fade-in-down">
        <div className="container header-content">
          <div className="logo">
            <span className="logo-icon">✦</span>
            <span className="logo-text">Pastel Shop</span>
          </div>
          
          <nav className={`nav ${isMenuOpen ? 'nav-open' : ''}`}>
            <a href="#home" className="nav-link">Home</a>
            <a href="#products" className="nav-link">Shop</a>
            <a href="#about" className="nav-link">About</a>
            <a href="#contact" className="nav-link">Contact</a>
          </nav>
          
          <div className="header-actions">
            <button className="icon-btn search-btn" onClick={() => document.getElementById('search-input').focus()}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8"/>
                <path d="m21 21-4.35-4.35"/>
              </svg>
            </button>
            
            <button 
              className="icon-btn cart-btn"
              onClick={() => setIsCartOpen(true)}
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"/>
                <line x1="3" y1="6" x2="21" y2="6"/>
                <path d="M16 10a4 4 0 0 1-8 0"/>
              </svg>
              {cartItemCount > 0 && <span className="cart-badge">{cartItemCount}</span>}
            </button>
            
            <button 
              className="icon-btn menu-btn"
              onClick={() => setIsMenuOpen(!isMenuOpen)}
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="3" y1="6" x2="21" y2="6"/>
                <line x1="3" y1="12" x2="21" y2="12"/>
                <line x1="3" y1="18" x2="21" y2="18"/>
              </svg>
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section id="home" className="hero">
        <div className="container hero-content">
          <div className="hero-text">
            <h1 className="hero-title animate-fade-in-up">
              Curated Home Essentials
            </h1>
            <p className="hero-subtitle animate-fade-in-up delay-1">
              Discover beautifully crafted items for your living space. 
              Minimalist design meets everyday functionality.
            </p>
            <div className="hero-buttons animate-fade-in-up delay-2">
              <a href="#products" className="btn btn-primary">
                Shop Collection
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M5 12h14M12 5l7 7-7 7"/>
                </svg>
              </a>
              <a href="#about" className="btn btn-secondary">
                Learn More
              </a>
            </div>
          </div>
          <div className="hero-image animate-scale-in delay-3">
            <div className="hero-image-wrapper">
              <img 
                src="https://images.unsplash.com/photo-1616486338812-3dadae4b4ace?w=600&h=600&fit=crop" 
                alt="Beautiful home interior"
              />
              <div className="floating-badge animate-float">
                <span className="badge-new">New Arrivals</span>
              </div>
            </div>
          </div>
        </div>
        
        {/* Decorative elements */}
        <div className="hero-decoration decoration-1"></div>
        <div className="hero-decoration decoration-2"></div>
      </section>

      {/* Features Section */}
      <section className="features">
        <div className="container">
          <div className="features-grid">
            <div className="feature-card animate-fade-in-up delay-1">
              <div className="feature-icon">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="3" y="3" width="18" height="18" rx="2"/>
                  <path d="M3 9h18"/>
                  <path d="M9 21V9"/>
                </svg>
              </div>
              <h3>Quality Materials</h3>
              <p>Crafted with premium, sustainable materials for lasting beauty.</p>
            </div>
            
            <div className="feature-card animate-fade-in-up delay-2">
              <div className="feature-icon">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
              </div>
              <h3>Secure Shopping</h3>
              <p>Your data is protected with industry-leading encryption.</p>
            </div>
            
            <div className="feature-card animate-fade-in-up delay-3">
              <div className="feature-icon">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
                  <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
                  <line x1="12" y1="22.08" x2="12" y2="12"/>
                </svg>
              </div>
              <h3>Fast Delivery</h3>
              <p>Free shipping on orders over $75. Delivered in 3-5 business days.</p>
            </div>
            
            <div className="feature-card animate-fade-in-up delay-4">
              <div className="feature-icon">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>
                </svg>
              </div>
              <h3>24/7 Support</h3>
              <p>Our team is always here to help with any questions or concerns.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Products Section */}
      <section id="products" className="products-section">
        <div className="container">
          <div className="section-header animate-fade-in-up">
            <h2 className="section-title">Our Collection</h2>
            <p className="section-subtitle">Thoughtfully designed pieces for every corner of your home</p>
          </div>
          
          {/* Filters */}
          <div className="filters animate-fade-in-up delay-1">
            <div className="search-box">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8"/>
                <path d="m21 21-4.35-4.35"/>
              </svg>
              <input
                id="search-input"
                type="text"
                placeholder="Search products..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="input search-input"
              />
            </div>
            
            <div className="category-filters">
              {categories.map((category, index) => (
                <button
                  key={category}
                  className={`filter-btn ${selectedCategory === category ? 'active' : ''}`}
                  onClick={() => setSelectedCategory(category)}
                  style={{ animationDelay: `${index * 0.05}s` }}
                >
                  {category}
                </button>
              ))}
            </div>
          </div>
          
          {/* Products Grid */}
          <div className="products-grid">
            {visibleProducts.map((product, index) => (
              <ProductCard
                key={product.id}
                product={product}
                onAddToCart={addToCart}
                index={index}
              />
            ))}
          </div>
          
          {visibleProducts.length === 0 && (
            <div className="no-products animate-fade-in">
              <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="11" cy="11" r="8"/>
                <path d="m21 21-4.35-4.35"/>
              </svg>
              <h3>No products found</h3>
              <p>Try adjusting your search or filter criteria</p>
            </div>
          )}
        </div>
      </section>

      {/* About Section */}
      <section id="about" className="about-section">
        <div className="container about-content">
          <div className="about-image animate-slide-in-left">
            <img 
              src="https://images.unsplash.com/photo-1556228453-efd6c1ff04f6?w=600&h=600&fit=crop" 
              alt="Our story"
            />
          </div>
          <div className="about-text animate-slide-in-right">
            <h2>Our Story</h2>
            <p>
              Founded with a passion for minimalist design and quality craftsmanship, 
              Pastel Shop brings you carefully curated home essentials that blend 
              form and function seamlessly.
            </p>
            <p>
              We believe in sustainable practices, ethical sourcing, and creating 
              products that stand the test of time. Each item in our collection is 
              chosen with intention and purpose.
            </p>
            <div className="about-stats">
              <div className="stat">
                <span className="stat-number">5K+</span>
                <span className="stat-label">Happy Customers</span>
              </div>
              <div className="stat">
                <span className="stat-number">500+</span>
                <span className="stat-label">Unique Products</span>
              </div>
              <div className="stat">
                <span className="stat-number">99%</span>
                <span className="stat-label">Satisfaction Rate</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Newsletter Section */}
      <section className="newsletter-section">
        <div className="container newsletter-content">
          <div className="newsletter-text animate-fade-in-up">
            <h2>Stay Updated</h2>
            <p>Subscribe to our newsletter for exclusive offers and new arrivals</p>
          </div>
          <form className="newsletter-form animate-fade-in-up delay-1" onSubmit={(e) => e.preventDefault()}>
            <input 
              type="email" 
              placeholder="Enter your email" 
              className="input newsletter-input"
              required
            />
            <button type="submit" className="btn btn-primary">
              Subscribe
            </button>
          </form>
        </div>
      </section>

      {/* Contact Section */}
      <section id="contact" className="contact-section">
        <div className="container">
          <div className="section-header animate-fade-in-up">
            <h2 className="section-title">Get In Touch</h2>
            <p className="section-subtitle">We'd love to hear from you</p>
          </div>
          
          <div className="contact-content">
            <div className="contact-info animate-slide-in-left">
              <div className="contact-item">
                <div className="contact-icon">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/>
                    <circle cx="12" cy="10" r="3"/>
                  </svg>
                </div>
                <div>
                  <h4>Address</h4>
                  <p>123 Design Street, Creative City, 10001</p>
                </div>
              </div>
              
              <div className="contact-item">
                <div className="contact-icon">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/>
                  </svg>
                </div>
                <div>
                  <h4>Phone</h4>
                  <p>+1 (555) 123-4567</p>
                </div>
              </div>
              
              <div className="contact-item">
                <div className="contact-icon">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
                    <polyline points="22,6 12,13 2,6"/>
                  </svg>
                </div>
                <div>
                  <h4>Email</h4>
                  <p>hello@pastelshop.com</p>
                </div>
              </div>
            </div>
            
            <form className="contact-form animate-slide-in-right" onSubmit={(e) => e.preventDefault()}>
              <div className="form-row">
                <input type="text" placeholder="Your Name" className="input" required />
                <input type="email" placeholder="Your Email" className="input" required />
              </div>
              <input type="text" placeholder="Subject" className="input" />
              <textarea placeholder="Your Message" className="input textarea" rows="5" required></textarea>
              <button type="submit" className="btn btn-primary">
                Send Message
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="22" y1="2" x2="11" y2="13"/>
                  <polygon points="22 2 15 22 11 13 2 9 22 2"/>
                </svg>
              </button>
            </form>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="footer">
        <div className="container footer-content">
          <div className="footer-brand">
            <div className="logo">
              <span className="logo-icon">✦</span>
              <span className="logo-text">Pastel Shop</span>
            </div>
            <p>Curated home essentials for modern living.</p>
          </div>
          
          <div className="footer-links">
            <div className="footer-column">
              <h4>Shop</h4>
              <a href="#">All Products</a>
              <a href="#">New Arrivals</a>
              <a href="#">Best Sellers</a>
              <a href="#">Sale</a>
            </div>
            
            <div className="footer-column">
              <h4>Support</h4>
              <a href="#">FAQ</a>
              <a href="#">Shipping</a>
              <a href="#">Returns</a>
              <a href="#">Contact</a>
            </div>
            
            <div className="footer-column">
              <h4>Company</h4>
              <a href="#">About Us</a>
              <a href="#">Careers</a>
              <a href="#">Press</a>
              <a href="#">Blog</a>
            </div>
          </div>
          
          <div className="footer-social">
            <h4>Follow Us</h4>
            <div className="social-links">
              <a href="#" className="social-link">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M24 4.557c-.883.392-1.832.656-2.828.775 1.017-.609 1.798-1.574 2.165-2.724-.951.564-2.005.974-3.127 1.195-.897-.957-2.178-1.555-3.594-1.555-3.179 0-5.515 2.966-4.797 6.045-4.091-.205-7.719-2.165-10.148-5.144-1.29 2.213-.669 5.108 1.523 6.574-.806-.026-1.566-.247-2.229-.616-.054 2.281 1.581 4.415 3.949 4.89-.693.188-1.452.232-2.224.084.626 1.956 2.444 3.379 4.6 3.419-2.07 1.623-4.678 2.348-7.29 2.04 2.179 1.397 4.768 2.212 7.548 2.212 9.142 0 14.307-7.721 13.995-14.646.962-.695 1.797-1.562 2.457-2.549z"/>
                </svg>
              </a>
              <a href="#" className="social-link">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163c0-3.403-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z"/>
                </svg>
              </a>
              <a href="#" className="social-link">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M22.675 0h-21.35c-.732 0-1.325.593-1.325 1.325v21.351c0 .731.593 1.324 1.325 1.324h11.495v-9.294h-3.128v-3.622h3.128v-2.671c0-3.1 1.893-4.788 4.659-4.788 1.325 0 2.463.099 2.795.143v3.24l-1.918.001c-1.504 0-1.795.715-1.795 1.763v2.313h3.587l-.467 3.622h-3.12v9.293h6.116c.73 0 1.323-.593 1.323-1.325v-21.35c0-.732-.593-1.325-1.325-1.325z"/>
                </svg>
              </a>
              <a href="#" className="social-link">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 0c-6.627 0-12 5.373-12 12s5.373 12 12 12 12-5.373 12-12-5.373-12-12-12zm-2 16h-2v-6h2v6zm-1-6.891c-.607 0-1.1-.496-1.1-1.109 0-.612.492-1.109 1.1-1.109s1.1.497 1.1 1.109c0 .613-.493 1.109-1.1 1.109zm8 6.891h-1.998v-2.861c0-1.881-2.002-1.722-2.002 0v2.861h-2v-6h2v1.093c.872-1.616 4-1.736 4 1.548v3.359z"/>
                </svg>
              </a>
            </div>
          </div>
        </div>
        
        <div className="footer-bottom">
          <div className="container">
            <p>&copy; 2024 Pastel Shop. All rights reserved.</p>
            <div className="footer-bottom-links">
              <a href="#">Privacy Policy</a>
              <a href="#">Terms of Service</a>
              <a href="#">Cookie Policy</a>
            </div>
          </div>
        </div>
      </footer>

      {/* Cart Sidebar */}
      <div className={`cart-overlay ${isCartOpen ? 'open' : ''}`} onClick={() => setIsCartOpen(false)}></div>
      <div className={`cart-sidebar ${isCartOpen ? 'open' : ''}`}>
        <div className="cart-header">
          <h2>Your Cart ({cartItemCount})</h2>
          <button className="close-btn" onClick={() => setIsCartOpen(false)}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
        
        <div className="cart-items">
          {cart.length === 0 ? (
            <div className="empty-cart">
              <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"/>
                <line x1="3" y1="6" x2="21" y2="6"/>
                <path d="M16 10a4 4 0 0 1-8 0"/>
              </svg>
              <p>Your cart is empty</p>
              <button className="btn btn-primary" onClick={() => setIsCartOpen(false)}>
                Continue Shopping
              </button>
            </div>
          ) : (
            cart.map(item => (
              <div key={item.id} className="cart-item">
                <img src={item.image} alt={item.name} className="cart-item-image" />
                <div className="cart-item-details">
                  <h4>{item.name}</h4>
                  <p className="cart-item-price">${item.price.toFixed(2)}</p>
                  <div className="quantity-controls">
                    <button onClick={() => updateQuantity(item.id, item.quantity - 1)}>-</button>
                    <span>{item.quantity}</span>
                    <button onClick={() => updateQuantity(item.id, item.quantity + 1)}>+</button>
                  </div>
                </div>
                <button className="remove-item" onClick={() => removeFromCart(item.id)}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                  </svg>
                </button>
              </div>
            ))
          )}
        </div>
        
        {cart.length > 0 && (
          <div className="cart-footer">
            <div className="cart-total">
              <span>Subtotal:</span>
              <span>${cartTotal.toFixed(2)}</span>
            </div>
            <button className="btn btn-primary checkout-btn">
              Checkout
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M5 12h14M12 5l7 7-7 7"/>
              </svg>
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

// Product Card Component
function ProductCard({ product, onAddToCart, index }) {
  const [isAdding, setIsAdding] = useState(false)
  
  const handleAddToCart = () => {
    setIsAdding(true)
    onAddToCart(product)
    setTimeout(() => setIsAdding(false), 500)
  }
  
  return (
    <div 
      className="product-card hover-lift"
      style={{ animationDelay: `${index * 0.05}s` }}
    >
      <div className="product-image-wrapper">
        <img src={product.image} alt={product.name} className="product-image" />
        {product.badge && (
          <span className={`badge badge-${product.badge}`}>{product.badge}</span>
        )}
        <button className="quick-add-btn" onClick={handleAddToCart}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="12" y1="5" x2="12" y2="19"/>
            <line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
        </button>
      </div>
      
      <div className="product-info">
        <p className="product-category">{product.category}</p>
        <h3 className="product-name">{product.name}</h3>
        <div className="product-rating">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
          </svg>
          <span>{product.rating}</span>
          <span className="rating-count">({product.reviews})</span>
        </div>
        <div className="product-price">
          <span className="current-price">${product.price.toFixed(2)}</span>
          {product.originalPrice && (
            <span className="original-price">${product.originalPrice.toFixed(2)}</span>
          )}
        </div>
        <button 
          className={`btn btn-primary add-to-cart-btn ${isAdding ? 'adding' : ''}`}
          onClick={handleAddToCart}
        >
          {isAdding ? (
            <>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="check-icon">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
              Added!
            </>
          ) : (
            <>
              Add to Cart
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="12" y1="5" x2="12" y2="19"/>
                <line x1="5" y1="12" x2="19" y2="12"/>
              </svg>
            </>
          )}
        </button>
      </div>
    </div>
  )
}

export default App
