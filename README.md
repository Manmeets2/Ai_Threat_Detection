# AI Threat Detection System

A modern, AI-powered cybersecurity threat detection system built with Python and JavaScript.

## Features

- 🔍 **Real-time Threat Detection**: Pattern matching, port analysis, and AI simulation
- 📊 **Analytics Dashboard**: Visual charts and statistics
- 🚨 **Alert System**: Real-time threat notifications
- 📝 **Threat Logs**: Comprehensive logging of all detected threats
- ⚙️ **Settings Management**: Configurable system parameters
- 🎨 **Modern UI**: Beautiful, responsive interface

## Tech Stack

- **Backend**: Python (Flask-like serverless functions)
- **Frontend**: HTML, CSS, JavaScript
- **Deployment**: Vercel (Serverless Functions + Static Site)
- **Charts**: Chart.js
- **Icons**: Font Awesome

## Quick Start

### Local Development

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd ai-threat-detection
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the development server**
   ```bash
   python simple_app.py
   ```

4. **Open your browser**
   Navigate to `http://localhost:5000`

### Vercel Deployment

1. **Install Vercel CLI**
   ```bash
   npm i -g vercel
   ```

2. **Deploy to Vercel**
   ```bash
   vercel
   ```

3. **Follow the prompts**
   - Link to existing project or create new
   - Set project name
   - Deploy

4. **Your app will be live at**
   `https://your-project-name.vercel.app`

## Project Structure

```
├── api/                    # Serverless functions
│   ├── health.py          # Health check endpoint
│   ├── detect.py          # Threat detection
│   ├── threats.py         # Threat management
│   ├── analytics.py       # Analytics data
│   └── stats.py           # System statistics
├── frontend/              # Static frontend
│   ├── index.html         # Main HTML file
│   ├── styles.css         # Styling
│   └── script.js          # JavaScript logic
├── simple_app.py          # Local development server
├── requirements.txt       # Python dependencies
├── package.json           # Project metadata
├── vercel.json           # Vercel configuration
└── README.md             # This file
```

## API Endpoints

### Health Check
- **GET** `/api/health` - System health status

### Threat Detection
- **POST** `/api/detect` - Analyze data for threats
- **GET** `/api/detect` - Get detection info

### Threat Management
- **GET** `/api/threats` - Get all threats
- **DELETE** `/api/threats/{id}` - Delete specific threat

### Analytics
- **GET** `/api/analytics` - Get analytics data
- **GET** `/api/stats` - Get system statistics

## Usage

### 1. Dashboard
- View real-time system statistics
- Monitor threat counts and system health
- Quick overview of recent activity

### 2. Threat Detection
- Submit network traffic data for analysis
- Test with sample data
- View detection results

### 3. Analytics
- Detailed threat analytics
- Visual charts and graphs
- Performance metrics

### 4. Threat Logs
- View all detected threats
- Filter by severity and type
- Search through logs

### 5. Settings
- Configure API endpoints
- Set refresh intervals
- System preferences

## Threat Detection Methods

1. **Pattern Matching**: Detects known attack patterns
2. **Port Analysis**: Identifies suspicious port usage
3. **AI Simulation**: Random threat detection simulation
4. **Anomaly Detection**: Rate limiting and unusual behavior

## Environment Variables

For local development, you can set:
- `HOST`: Server host (default: 0.0.0.0)
- `PORT`: Server port (default: 5000)
- `DEBUG`: Debug mode (default: False)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

For issues and questions:
- Create an issue on GitHub
- Check the documentation
- Review the code comments

## Security Note

This is a demonstration system. For production use:
- Implement proper authentication
- Use a real database
- Add input validation
- Enable HTTPS
- Implement rate limiting
- Add logging and monitoring 