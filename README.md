# ERP Purchase Order Management System

A comprehensive web-based Enterprise Resource Planning (ERP) system designed for managing purchase requisitions, purchase orders, and procurement workflows with automated approval processes, budget management, and vendor management.

## 🚀 Features

### Core Functionality
- **Purchase Requisition (PR) Management**: Create, edit, and track purchase requisitions
- **Purchase Order (PO) Generation**: Automated PO creation from approved PRs
- **Multi-level Approval Workflows**: Configurable approval chains based on amount thresholds
- **Budget Management**: Real-time budget tracking and deduction
- **Vendor Management**: Comprehensive vendor database with item tracking
- **Document Generation**: Automated Word document creation for POs
- **Email Notifications**: Automated email alerts for approvals and status changes

### Advanced Features
- **Real-time Dashboard**: Live statistics and analytics
- **Role-based Access Control**: Secure user management with permissions
- **Mobile Responsive**: Access from any device
- **File Upload Support**: Material requisition file attachments
- **NFA (No Further Action) Document Handling**: For budget-exceeding or non-budgeted items
- **Vendor Lookup System**: Auto-fill vendor details and item search
- **Project-based Budget Tracking**: Department-wise budget management
- **Audit Trail**: Complete history of all transactions

## 🏗️ System Architecture

### Technology Stack
- **Backend**: Python Flask 2.3.3
- **Database**: SQLite3 with custom DatabaseManager
- **Data Storage**: Excel files (pandas + openpyxl)
- **Document Generation**: python-docx
- **Frontend**: HTML5, CSS3, JavaScript, Tailwind CSS
- **Authentication**: Session-based with secure token validation
- **Email**: SMTP integration with HTML templates

### File Structure
```
ERP/
├── app.py                 # Main Flask application
├── database.py           # Database management
├── requirements.txt      # Python dependencies
├── template.docx         # PO document template
├── data/
│   └── clients.xlsx      # Client information
├── static/               # CSS, JS, images
├── templates/            # HTML templates
├── Purchase_Order/       # Generated PO documents
├── Upload_MRF/          # Material requisition files
├── uploaded_PO_docs/    # Uploaded PO documents
└── *.xlsx files         # Data storage files
```

## 📊 Data Files

### Core Data Files
- **`PO_data.xlsx`**: Purchase order records
- **`data.xlsx`**: Purchase requisition records
- **`vendor_items.xlsx`**: Vendor and item database
- **`department_emails.xlsx`**: Department approver emails
- **`department_budgets.xlsx`**: Budget allocations
- **`{Project}_budget.xlsx`**: Project-specific budgets

### Database Tables
- **`users`**: User accounts and permissions
- **`notifications`**: User-specific notifications
- **`system_notifications`**: Global system notifications
- **`feedback`**: User feedback and suggestions

## 🔧 Installation & Setup

### Prerequisites
- Python 3.8+
- pip package manager

### Installation Steps

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ERP
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   Create a `.env` file with:
   ```env
   ADMIN_EMAIL=admin@company.com
   ADMIN_PASSWORD=secure_password
   GMAIL_EMAIL=your-email@gmail.com
   GMAIL_PASSWORD=your-app-password
   SECRET_KEY=your-secret-key
   ```

4. **Initialize the system**
   ```bash
   python app.py
   ```

5. **Access the application**
   - HTTP: `http://localhost:5122`

### SSL/TLS
- Local SSL is no longer used. In production (e.g., AWS Lightsail), terminate SSL at the load balancer or reverse proxy and forward traffic to the app over HTTP.

## 👥 User Roles & Permissions

### Role Hierarchy
1. **Admin**: Full system access, user management
2. **Head of Procurement**: PO approval authority
3. **CFO**: High-value PO approval
4. **CEO**: Final approval authority
5. **Chairman**: Ultimate approval authority
6. **Regular Users**: PR creation and PO generation

### Permission System
- Role-based access control
- Department-specific permissions
- Feature-level access restrictions
- Session-based authentication

## 📋 Workflow Process

### Purchase Requisition (PR) Workflow
1. **Create PR**: User creates purchase requisition
2. **Submit for Approval**: PR sent to department approver
3. **Approval/Rejection**: Approver reviews and decides
4. **Generate PO**: Approved PRs can generate POs

### Purchase Order (PO) Workflow
1. **Select PR**: Choose approved PR for PO generation
2. **Fill Details**: Add vendor information and item details
3. **Budget Check**: System validates budget availability
4. **Generate Document**: Create Word document
5. **Send for Approval**: Route to appropriate approvers
6. **Final Approval**: Multi-level approval process
7. **Execution**: Approved PO ready for execution

### Approval Chains
- **Amount-based Routing**: Different approvers based on PO value
- **Department Hierarchy**: Respects organizational structure
- **Budget Validation**: Ensures sufficient funds
- **NFA Requirements**: Handles budget-exceeding scenarios

## 🎯 Key Features Deep Dive

### Budget Management
- **Real-time Tracking**: Live budget updates
- **Department-wise Allocation**: Separate budgets per department
- **Material vs Services**: Different budget types
- **Automatic Deduction**: Budget reduced on PO approval
- **Refund on Rejection**: Budget restored on PO rejection

### Vendor Management
- **Smart Vendor Database**: Auto-updates vendor information
- **Item Tracking**: Multiple items per vendor with numbering
- **Lookup System**: Quick vendor and item search
- **Data Validation**: Prevents duplicate and invalid entries

### Document Generation
- **Template-based**: Uses Word templates for consistency
- **Auto-population**: Fills data from forms and databases
- **Professional Formatting**: Company-branded documents
- **File Management**: Organized storage and retrieval

### Email System
- **HTML Templates**: Professional email formatting
- **Direct Links**: One-click approval/rejection
- **Status Updates**: Real-time notifications
- **Attachment Support**: File attachments in emails

## 🔒 Security Features

### Authentication & Authorization
- Session-based authentication
- Secure password hashing
- Role-based access control
- Session timeout and validation

### Data Protection
- Input sanitization
- SQL injection prevention
- XSS protection
- CSRF protection
- Secure headers

### File Security
- Secure file uploads
- File type validation
- Path traversal prevention
- Secure file storage

## 📈 Analytics & Reporting

### Dashboard Features
- **Real-time Statistics**: Live PO/PR counts
- **Budget Analytics**: Spending trends and patterns
- **Vendor Performance**: Top vendors by spend
- **Monthly Trends**: Historical data analysis
- **Project Tracking**: Project-wise expenditure

### API Endpoints
- `/api/dashboard_stats`: Dashboard statistics
- `/api/monthly_spend_trend`: Spending trends
- `/api/top_vendors_by_spend`: Vendor analytics
- `/api/avg_po_value_by_month`: Average PO values

## 🛠️ Configuration

### Environment Variables
```env
# Admin Credentials
ADMIN_EMAIL=admin@company.com
ADMIN_PASSWORD=secure_password

# Email Configuration
GMAIL_EMAIL=your-email@gmail.com
GMAIL_PASSWORD=your-app-password

# Security
SECRET_KEY=your-secret-key

# Database
DATABASE_URL=sqlite:///erp_system.db
```

### Budget Configuration
- Edit `department_budgets.xlsx` for department budgets
- Create `{Project}_budget.xlsx` for project-specific budgets
- Configure approval thresholds in code

### Email Configuration
- Set up Gmail App Password
- Configure SMTP settings
- Customize email templates

## 🚀 Deployment

### Production Deployment
1. **Set up production environment**
2. **Terminate SSL at Lightsail load balancer or web server (nginx)**
3. **Forward to the app over HTTP on port 5122**
4. **Configure database backups**
5. **Set up monitoring and logging**

### Docker Deployment (Optional)
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5122
CMD ["python", "app.py"]
```

## 🔧 Maintenance

### Regular Tasks
- **Database Backup**: Regular SQLite backups
- **File Cleanup**: Remove old uploaded files
- **Log Rotation**: Manage application logs
- **Security Updates**: Keep dependencies updated

### Monitoring
- **Application Logs**: Monitor for errors
- **Performance Metrics**: Track response times
- **User Activity**: Monitor system usage
- **Budget Alerts**: Low budget notifications

## 🐛 Troubleshooting

### Common Issues
1. **Email Not Sending**: Check Gmail credentials and app password
2. **File Upload Errors**: Verify file permissions and size limits
3. **Database Errors**: Check SQLite file permissions
4. **SSL Certificate Issues**: Manage certificates at the load balancer/web server

### Debug Mode
```bash
export FLASK_DEBUG=1
python app.py
```

## 📞 Support

### Getting Help
- Check the documentation
- Review application logs
- Contact system administrator
- Submit feedback through the system

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is proprietary software. All rights reserved.

## 🔄 Version History

### Current Version: 2.0
- Enhanced vendor management
- Improved budget tracking
- Better user interface
- Advanced analytics
- Security improvements

### Previous Versions
- v1.0: Basic PO/PR management
- v1.5: Added approval workflows
- v1.8: Integrated budget management

---

**Note**: This system is designed for enterprise use and requires proper configuration and maintenance for optimal performance. Always backup your data before making changes and test in a development environment first.
