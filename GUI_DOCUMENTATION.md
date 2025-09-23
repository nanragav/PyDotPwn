# DotDotPwn GUI Application

A comprehensive cross-platform graphical user interface for the DotDotPwn directory traversal fuzzer.

## 🎯 Features

### Core Functionality

- **Intuitive Interface**: Easy-to-use GUI with guided workflows
- **Real-time Output**: Live monitoring of scan progress and results
- **Advanced Configuration**: Comprehensive options for all scan parameters
- **Cross-platform**: Runs on Windows, Linux, and macOS
- **Resource Monitoring**: Real-time system and process resource tracking

### Scan Capabilities

- **Multiple Modules**: HTTP, FTP, TFTP, Payload, and Pattern Generation
- **Smart Presets**: Quick configuration for common scenarios
- **Pattern Visualization**: Live output with syntax highlighting
- **Performance Tracking**: Resource usage and scan speed monitoring

### Data Management

- **Scan History**: Track all previous scans with detailed information
- **Report Generation**: Export results in multiple formats (Text, JSON, CSV, XML, HTML)
- **Configuration Management**: Save and load scan configurations
- **Output Management**: Save, clear, and manage scan outputs

## 🚀 Quick Start

### Prerequisites

1. **Python 3.8+** with virtual environment
2. **DotDotPwn Python Implementation** (verified working)
3. **GUI Dependencies**:
   ```bash
   pip install PyQt6 PyQt6-tools qtawesome pyqtgraph qdarkstyle
   ```

### Installation & Launch

1. **Ensure DotDotPwn is verified**:

   ```bash
   python comprehensive_verification.py
   ```

2. **Launch the GUI**:
   ```bash
   python launch_gui.py
   ```

## 📋 User Guide

### Main Interface

The GUI is organized into two main panels:

#### Left Panel - Configuration

- **Basic Configuration**: Module, OS type, and depth settings
- **Target Configuration**: Host, port, file, and pattern settings
- **Advanced Options**: Delays, HTTP methods, and behavior settings
- **Authentication**: Username and password for secured services
- **Output Settings**: Report format and file output options

#### Right Panel - Monitoring & Output

- **Output Tab**: Real-time scan output with syntax highlighting
- **Monitoring Tab**: System resource usage graphs and metrics
- **History Tab**: Previous scan history and results

### Scan Workflow

1. **Select Module**: Choose the appropriate fuzzing module
2. **Configure Target**: Set host, port, and target file
3. **Set Parameters**: Adjust depth, patterns, and options
4. **Start Scan**: Click "Start Scan" or use Ctrl+R
5. **Monitor Progress**: Watch real-time output and resource usage
6. **Save Results**: Export findings in preferred format

### Quick Presets

Use the preset buttons for common scenarios:

- **Web App**: Standard web application testing (HTTP/HTTPS)
- **Windows**: Windows-specific file targeting
- **Linux**: Unix/Linux system file targeting
- **Generate**: Pattern generation mode

## 🔧 Advanced Features

### Resource Monitoring

- **CPU Usage**: Real-time system and process CPU monitoring
- **Memory Usage**: RAM consumption tracking
- **Performance Graphs**: Historical resource usage visualization
- **Process Monitoring**: Scan process specific resource tracking

### Output Management

- **Syntax Highlighting**: Color-coded output for easy reading
- **Auto-scroll**: Automatic scrolling to latest output
- **Export Options**: Save output in various formats
- **Search & Filter**: Find specific patterns in output

### Configuration Management

- **Save/Load**: Store and retrieve scan configurations
- **Presets**: Quick-load common configuration sets
- **History**: Access previous scan configurations
- **Validation**: Real-time parameter validation

## 🎨 Interface Design

### Theme & Styling

- **Dark Theme**: Easy-on-eyes dark interface using QDarkStyle
- **Icons**: FontAwesome icons via QtAwesome for intuitive navigation
- **Responsive Layout**: Adaptive interface that works on different screen sizes
- **Professional Look**: Clean, modern interface suitable for security professionals

### Accessibility

- **Keyboard Shortcuts**: Full keyboard navigation support
- **Tooltips**: Helpful explanations for all options
- **Status Indicators**: Clear visual feedback for all operations
- **Error Handling**: User-friendly error messages and recovery options

## 🔍 Troubleshooting

### Common Issues

#### GUI Won't Start

```bash
# Check PyQt6 installation
python -c "import PyQt6; print('PyQt6 OK')"

# Install missing dependencies
pip install PyQt6 PyQt6-tools qtawesome pyqtgraph qdarkstyle
```

#### Scan Fails to Start

1. Verify DotDotPwn installation: `python comprehensive_verification.py`
2. Check target host connectivity
3. Validate scan parameters
4. Review error messages in output

#### Performance Issues

1. Monitor resource usage in Monitoring tab
2. Adjust delay settings for better performance
3. Use quiet mode for faster scanning
4. Close unnecessary applications

### Debug Mode

Enable debug mode by setting environment variable:

```bash
export DOTDOTPWN_DEBUG=1
python launch_gui.py
```

## 📊 Performance Optimization

### System Requirements

- **Minimum**: 2GB RAM, dual-core CPU
- **Recommended**: 8GB RAM, quad-core CPU
- **Storage**: 1GB free space for reports and logs

### Performance Tips

1. **Adjust Delays**: Lower delays for faster scans (be mindful of target load)
2. **Use Quiet Mode**: Reduces output overhead
3. **Monitor Resources**: Watch CPU/memory usage during scans
4. **Limit Depth**: Higher depths generate more patterns and take longer
5. **Break on First**: Stop after finding first vulnerability for speed

## 🔒 Security Considerations

### Ethical Usage

- **Authorization Required**: Only test systems you own or have explicit permission to test
- **Professional Use**: Designed for security professionals and researchers
- **Responsible Disclosure**: Follow proper vulnerability disclosure practices
- **Legal Compliance**: Ensure compliance with local laws and regulations

### Safe Practices

1. **Test Environment**: Use isolated test environments when possible
2. **Rate Limiting**: Use appropriate delays to avoid overwhelming targets
3. **Documentation**: Keep detailed records of all testing activities
4. **Cleanup**: Remove any test files or artifacts after testing

## 📈 Advanced Usage

### Batch Operations

- Save multiple configurations for different targets
- Use history to replay previous successful scans
- Export configurations for team sharing

### Integration

- API mode available for automation
- Command-line interface remains available
- Results can be imported into other security tools

### Customization

- Configuration files for default settings
- Custom patterns and payloads
- Extensible reporting formats

## 🆘 Support & Documentation

### Getting Help

1. **Built-in Help**: Use Help menu in application
2. **Documentation**: Reference COMPREHENSIVE_GUIDE.md
3. **Examples**: See QUICK_REFERENCE.md for command examples
4. **Troubleshooting**: Check TEST_DOCUMENTATION.md

### Reporting Issues

When reporting issues, please include:

- Operating system and version
- Python version
- GUI dependencies versions
- Error messages and logs
- Steps to reproduce the issue

## 🔄 Updates & Maintenance

### Keeping Updated

- Regularly run verification script to ensure proper operation
- Update GUI dependencies as needed
- Monitor for new features and improvements

### Backup & Recovery

- Export important scan configurations
- Save significant scan results
- Keep verification reports for compliance

---

**Remember**: This tool is designed for authorized security testing only. Always ensure you have proper permission before testing any system.
