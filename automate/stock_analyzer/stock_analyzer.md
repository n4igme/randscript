# Stock Fundamental Analyzer

A web application that analyzes stock fundamentals by fetching data from Stockbit and calculating fair value using PER and PBV methods.

## Features

- Fetches fundamental data from Stockbit (EPS, PER, PBV, Book Value per Share, Market Price)
- Calculates fair value using two methods:
  - PER Method: Fair Value = EPS × PER Industry
  - PBV Method: Fair Value = PBV Industry × Book Value per Share
- Real-time analysis and valuation status (Undervalued/Overvalued)
- Manual input fallback when scraping fails
- Clean, responsive UI

## How to Use

### For Browser Extension (Recommended)
1. Create a browser extension that can bypass CORS
2. Or disable CORS in browser developer options for testing

### For Node.js Server
1. Set up a proxy server to fetch data from Stockbit
2. Use Puppeteer or similar library to handle the scraping

### Direct Browser Usage (Limited)
1. Download the `stock_analyzer.html` file
2. Open in browser (note: may not work due to CORS policy)

## Code Implementation Notes

### Data Scraping
- The current implementation simulates data due to CORS restrictions
- To implement actual scraping:
  1. Use puppeteer in a Node.js server
  2. Set up a proxy server
  3. Use browser extension with proper permissions

### Calculation Logic
- PER Method: Fair Value = EPS × PER Industry
- PBV Method: Fair Value = PBV Industry × Book Value per Share
- Average Fair Value = (PER Method + PBV Method) / 2

### UI Components
- Symbol input and analyze button
- Manual input fields as fallback
- Results display with valuation status
- Responsive design for all devices

## Cross-Origin Policy Limitations

This application faces several challenges due to cross-origin policy:

1. **CORS Restrictions**: Browsers block requests to stockbit.com from local files
2. **Solution Options**:
   - Browser extension with host permissions
   - Server-side proxy
   - Disabled CORS in development mode

## Running the Application

### Option 1: Browser Extension
1. Create a manifest.json file
2. Add permissions for stockbit.com
3. Include stock_analyzer.html as popup or panel

### Option 2: Node.js Server
```javascript
// Example server.js
const express = require('express');
const puppeteer = require('puppeteer');
const app = express();

app.use(express.static('.'));

app.get('/api/stock/:symbol', async (req, res) => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    try {
        await page.goto(`https://stockbit.com/symbol/${req.params.symbol}`);
        // Extract data using page.evaluate
        const data = await page.evaluate(() => {
            // Implementation to extract data from DOM
        });
        
        res.json(data);
        await browser.close();
    } catch (error) {
        res.status(500).json({ error: error.message });
        await browser.close();
    }
});

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
```

### Option 3: Development Mode
For testing only - disable CORS:
```bash
# Chrome with CORS disabled (NOT recommended for regular browsing)
google-chrome --disable-web-security --user-data-dir="/tmp/chrome_dev"
```

## File Structure
- `stock_analyzer.html` - Complete web application
- `README.md` - This file

## Dependencies for Full Implementation
If using server-side scraping:
- Node.js
- Express.js (for server)
- Puppeteer (for web scraping)
- Or alternatives like Cheerio + Request

## Legal and Ethical Considerations
- Respect robots.txt files
- Follow terms of service of target websites
- Implement appropriate rate limiting
- Consider using official APIs when available
- Be aware of copyright and data usage rights

## Future Enhancements
- Add more fundamental metrics
- Include technical analysis
- Historical data visualization
- Industry comparison features
- Export to PDF/Excel functionality

## License
This project is for educational purposes only. The code is released under MIT License. Stock data belongs to Stockbit and respective exchanges.