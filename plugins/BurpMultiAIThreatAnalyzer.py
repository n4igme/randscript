#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Burp Suite Extension: Multi-AI Threat Analyzer
===============================================

Supports multiple AI providers:
- Qwen (Alibaba Cloud) - RECOMMENDED & CHEAPEST
- OpenAI GPT-4/GPT-4o
- Anthropic Claude (via API)
- Ollama (Local)

Features:
- Right-click context menu on any HTTP request/response
- Send selected requests to AI for threat modeling
- Automatic STRIDE/OWASP threat analysis
- Security test case generation
- Export analysis to report

Installation:
1. Burp Suite > Extender > Extensions > Add
2. Select "Python" as extension type
3. Select this file (BurpMultiAIThreatAnalyzer.py)
4. Configure API key in settings

Author: Security Automation Team
Version: 2.0.0
"""

# Python 2/3 compatibility for Jython (Python 2.7)
from __future__ import print_function

from burp import IBurpExtender, IContextMenuFactory, ITab, IHttpListener
from javax.swing import (JMenuItem, JPanel, JLabel, JTextField, JButton, JComboBox,
                         JTextArea, JScrollPane, JTabbedPane, JSplitPane,
                         BoxLayout, JOptionPane, SwingConstants, BorderFactory, JPasswordField)
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, Color, Font
from java.util import ArrayList
from java.net import URL
import json
import base64

# Python 2/3 compatibility for urllib
try:
    import urllib2
except ImportError:
    import urllib.request as urllib2

import sys
import traceback
from datetime import datetime

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Extension info
        callbacks.setExtensionName("Multi-AI Threat Analyzer")

        # Initialize storage
        self.api_key = ""
        self.provider = "openai"  # Default to OpenAI
        self.model = "gpt-4o"
        self.api_endpoint = ""
        self.selected_requests = []
        self.analysis_results = {}

        # Provider configurations
        self.providers = {
            "qwen": {
                "name": "Qwen (Alibaba Cloud) - RECOMMENDED",
                "endpoint": "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation",
                "models": ["qwen-max", "qwen-plus", "qwen-turbo", "qwen-coder-plus"],
                "default_model": "qwen-max"
            },
            "openai": {
                "name": "OpenAI (GPT-4/GPT-4o)",
                "endpoint": "https://api.openai.com/v1/chat/completions",
                "models": ["gpt-4o", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"],
                "default_model": "gpt-4o"
            },
            "anthropic": {
                "name": "Anthropic Claude",
                "endpoint": "https://api.anthropic.com/v1/messages",
                "models": ["claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-sonnet-20240229"],
                "default_model": "claude-3-5-sonnet-20241022"
            },
            "ollama": {
                "name": "Ollama (Local)",
                "endpoint": "http://localhost:11434/api/chat",
                "models": ["llama3", "mistral", "codellama", "deepseek-coder"],
                "default_model": "llama3"
            },
            "glm": {
                "name": "GLM (Zhipu/BigModel)",
                "endpoint": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
                "models": ["glm-4-flash", "glm-4", "glm-4-plus", "glm-4-air", "glm-4-long"],
                "default_model": "glm-4-flash"
            },
            "glm_openrouter": {
                "name": "GLM via OpenRouter (DeepSeek)",
                "endpoint": "https://openrouter.ai/api/v1/chat/completions",
                "models": ["deepseek/deepseek-chat", "deepseek/deepseek-coder", "thudm/glm-4-32b"],
                "default_model": "deepseek/deepseek-chat"
            }
        }

        # Register context menu
        callbacks.registerContextMenuFactory(self)

        # Register HTTP listener
        callbacks.registerHttpListener(self)

        # Build UI
        self._build_ui()

        # Add custom tab
        callbacks.addSuiteTab(self)

        print("[+] Multi-AI Threat Analyzer loaded successfully!")
        print("[i] Supports: Qwen, OpenAI, Claude, Ollama, GLM (Zhipu), GLM via OpenRouter")
        print("[i] Configure your provider in the 'AI Analyzer' tab")

    def _build_ui(self):
        """Build the main UI panel"""
        self._main_panel = JPanel(BorderLayout())

        # Create tabbed pane
        self._tabs = JTabbedPane()

        # Tab 1: Settings
        settings_panel = self._create_settings_panel()
        self._tabs.addTab("Settings", settings_panel)

        # Tab 2: Analysis Results
        results_panel = self._create_results_panel()
        self._tabs.addTab("Analysis Results", results_panel)

        # Tab 3: Test Cases
        testcases_panel = self._create_testcases_panel()
        self._tabs.addTab("Generated Test Cases", testcases_panel)

        # Tab 4: History
        history_panel = self._create_history_panel()
        self._tabs.addTab("Request History", history_panel)

        self._main_panel.add(self._tabs, BorderLayout.CENTER)

    def _create_settings_panel(self):
        """Create settings configuration panel"""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(EmptyBorder(20, 20, 20, 20))

        # Title
        title = JLabel("AI Provider Configuration")
        title.setFont(Font("Arial", Font.BOLD, 18))
        panel.add(title)
        panel.add(JLabel(" "))

        # Provider selection
        provider_label = JLabel("AI Provider:")
        provider_label.setFont(Font("Arial", Font.PLAIN, 14))
        panel.add(provider_label)

        provider_names = [self.providers[k]["name"] for k in ["qwen", "openai", "anthropic", "ollama", "glm", "glm_openrouter"]]
        self._provider_combo = JComboBox(provider_names)
        self._provider_combo.setMaximumSize(Dimension(600, 30))
        self._provider_combo.addActionListener(lambda e: self._on_provider_change())
        panel.add(self._provider_combo)
        panel.add(JLabel(" "))

        # API Key field
        api_key_label = JLabel("API Key:")
        api_key_label.setFont(Font("Arial", Font.PLAIN, 14))
        panel.add(api_key_label)

        self._api_key_field = JPasswordField(50)
        self._api_key_field.setMaximumSize(Dimension(600, 30))
        panel.add(self._api_key_field)
        panel.add(JLabel(" "))

        # Model selection
        model_label = JLabel("Model:")
        model_label.setFont(Font("Arial", Font.PLAIN, 14))
        panel.add(model_label)

        self._model_combo = JComboBox(self.providers["openai"]["models"])
        self._model_combo.setMaximumSize(Dimension(600, 30))
        panel.add(self._model_combo)
        panel.add(JLabel(" "))

        # API Endpoint (optional override)
        endpoint_label = JLabel("API Endpoint (optional - leave blank for default):")
        endpoint_label.setFont(Font("Arial", Font.PLAIN, 14))
        panel.add(endpoint_label)

        self._endpoint_field = JTextField(50)
        self._endpoint_field.setMaximumSize(Dimension(600, 30))
        panel.add(self._endpoint_field)
        panel.add(JLabel(" "))

        # Save button
        save_btn = JButton("Save Configuration", actionPerformed=self._save_config)
        save_btn.setMaximumSize(Dimension(200, 30))
        panel.add(save_btn)
        panel.add(JLabel(" "))

        # Test connection button
        test_btn = JButton("Test Connection", actionPerformed=self._test_connection)
        test_btn.setMaximumSize(Dimension(200, 30))
        panel.add(test_btn)
        panel.add(JLabel(" "))

        # Instructions
        instructions = JTextArea()
        instructions.setText(
            "Supported AI Providers:\n\n"
            "1. Qwen (Alibaba Cloud) - RECOMMENDED & CHEAPEST\n"
            "   - Get API key: https://dashscope.console.aliyun.com/\n"
            "   - Cost: ~$0.001-0.003 per analysis (10x cheaper!)\n"
            "   - Models: qwen-max, qwen-plus, qwen-turbo, qwen-coder-plus\n"
            "   - Best for: Cost-effective comprehensive analysis\n\n"
            "2. OpenAI (GPT-4/GPT-4o)\n"
            "   - Get API key: https://platform.openai.com/api-keys\n"
            "   - Cost: ~$0.01-0.03 per analysis\n"
            "   - Best for: Well-tested, reliable analysis\n\n"
            "3. Anthropic Claude\n"
            "   - Get API key: https://console.anthropic.com/settings/keys\n"
            "   - Cost: ~$0.01-0.02 per analysis\n"
            "   - Best for: Detailed threat modeling\n\n"
            "4. Ollama (Local) - FREE\n"
            "   - Install: https://ollama.ai\n"
            "   - Run: ollama run llama3\n"
            "   - No API key needed (local processing)\n"
            "   - Best for: Privacy-sensitive analysis\n\n"
            "5. GLM (Zhipu/BigModel) - CHINESE AI\n"
            "   - Get API key: https://open.bigmodel.cn/\n"
            "   - API Key format: ID.SECRET (e.g., abc123.xyz789)\n"
            "   - Cost: Very cheap, similar to Qwen\n"
            "   - Models: glm-4-flash, glm-4, glm-4-plus\n"
            "   - Best for: Chinese language support\n\n"
            "6. GLM via OpenRouter (DeepSeek)\n"
            "   - Get API key: https://openrouter.ai/\n"
            "   - Uses OpenRouter to access DeepSeek models\n"
            "   - Alternative if direct GLM has balance issues\n"
            "   - Models: deepseek-chat, deepseek-coder\n\n"
            "How to use:\n"
            "1. Select provider and enter API key (skip for Ollama)\n"
            "2. Click 'Save Configuration'\n"
            "3. Click 'Test Connection' to verify\n"
            "4. Right-click on requests in Burp > 'Send to AI Analyzer'\n"
        )
        instructions.setEditable(False)
        instructions.setBackground(Color(245, 245, 245))
        instructions.setBorder(BorderFactory.createLineBorder(Color.GRAY))
        instructions_scroll = JScrollPane(instructions)
        instructions_scroll.setMaximumSize(Dimension(600, 300))
        panel.add(instructions_scroll)

        return panel

    def _create_results_panel(self):
        """Create analysis results panel"""
        panel = JPanel(BorderLayout())
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Results text area
        self._results_area = JTextArea()
        self._results_area.setEditable(False)
        self._results_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._results_area.setText("No analysis performed yet.\n\nRight-click on any request and select 'Send to AI Analyzer'")

        scroll = JScrollPane(self._results_area)
        panel.add(scroll, BorderLayout.CENTER)

        # Action buttons
        button_panel = JPanel()

        export_btn = JButton("Export TXT", actionPerformed=self._export_report)
        button_panel.add(export_btn)

        export_md_btn = JButton("Export Markdown", actionPerformed=self._export_report_md)
        button_panel.add(export_md_btn)

        clear_btn = JButton("Clear Results", actionPerformed=self._clear_results)
        button_panel.add(clear_btn)

        panel.add(button_panel, BorderLayout.SOUTH)

        return panel

    def _create_testcases_panel(self):
        """Create test cases panel"""
        panel = JPanel(BorderLayout())
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        self._testcases_area = JTextArea()
        self._testcases_area.setEditable(False)
        self._testcases_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._testcases_area.setText("No test cases generated yet.")

        scroll = JScrollPane(self._testcases_area)
        panel.add(scroll, BorderLayout.CENTER)

        # Action buttons
        button_panel = JPanel()

        copy_btn = JButton("Copy Test Cases", actionPerformed=self._copy_testcases)
        button_panel.add(copy_btn)

        export_btn = JButton("Export CSV", actionPerformed=self._export_testcases)
        button_panel.add(export_btn)

        export_md_btn = JButton("Export Markdown", actionPerformed=self._export_testcases_md)
        button_panel.add(export_md_btn)

        panel.add(button_panel, BorderLayout.SOUTH)

        return panel

    def _create_history_panel(self):
        """Create request history panel"""
        panel = JPanel(BorderLayout())
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        self._history_area = JTextArea()
        self._history_area.setEditable(False)
        self._history_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._history_area.setText("Selected requests will appear here...")

        scroll = JScrollPane(self._history_area)
        panel.add(scroll, BorderLayout.CENTER)

        return panel

    def _on_provider_change(self):
        """Handle provider selection change"""
        selected_name = self._provider_combo.getSelectedItem()

        # Find provider key
        provider_key = None
        for key, config in self.providers.items():
            if config["name"] == selected_name:
                provider_key = key
                break

        if provider_key:
            # Update model combo box
            models = self.providers[provider_key]["models"]
            self._model_combo.removeAllItems()
            for model in models:
                self._model_combo.addItem(model)

            # Update endpoint field with default
            default_endpoint = self.providers[provider_key]["endpoint"]
            self._endpoint_field.setText(default_endpoint)

            # Show/hide API key field for Ollama
            if provider_key == "ollama":
                self._api_key_field.setEnabled(False)
                self._api_key_field.setText("(not required for local)")
            else:
                self._api_key_field.setEnabled(True)
                if self._api_key_field.getText() == "(not required for local)":
                    self._api_key_field.setText("")

    def _save_config(self, event):
        """Save API configuration"""
        selected_name = self._provider_combo.getSelectedItem()

        # Find provider key
        for key, config in self.providers.items():
            if config["name"] == selected_name:
                self.provider = key
                break

        self.api_key = "".join([str(c) for c in self._api_key_field.getPassword()])
        self.model = self._model_combo.getSelectedItem()

        custom_endpoint = self._endpoint_field.getText().strip()
        if custom_endpoint:
            self.api_endpoint = custom_endpoint
        else:
            self.api_endpoint = self.providers[self.provider]["endpoint"]

        # Validate
        if self.provider != "ollama" and not self.api_key:
            JOptionPane.showMessageDialog(self._main_panel,
                "Please enter an API key for {}!".format(selected_name),
                "Error", JOptionPane.ERROR_MESSAGE)
            return

        JOptionPane.showMessageDialog(self._main_panel,
            "Configuration saved successfully!\n\nProvider: {}\nModel: {}\n\nYou can now use 'Send to AI Analyzer' from context menu.".format(
                selected_name, self.model),
            "Success", JOptionPane.INFORMATION_MESSAGE)

        print("[+] Configuration saved: {} - {}".format(self.provider, self.model))

    def _test_connection(self, event):
        """Test API connection"""
        if not self.api_key and self.provider != "ollama":
            JOptionPane.showMessageDialog(self._main_panel,
                "Please save configuration first!",
                "Error", JOptionPane.ERROR_MESSAGE)
            return

        self._results_area.setText("Testing connection to {}...\n".format(self.provider))

        try:
            test_prompt = "Respond with 'OK' if you can read this message."
            result = self._call_ai_api(test_prompt, "You are a helpful assistant. Respond briefly.")

            if "ERROR" not in result and "HTTP ERROR" not in result:
                JOptionPane.showMessageDialog(self._main_panel,
                    "Connection successful!\n\nProvider: {}\nModel: {}\n\nResponse: {}".format(
                        self.provider, self.model, result[:100]),
                    "Success", JOptionPane.INFORMATION_MESSAGE)
                self._results_area.setText("Connection test successful!\n\n" + result)
            else:
                JOptionPane.showMessageDialog(self._main_panel,
                    "Connection failed!\n\n{}".format(result),
                    "Error", JOptionPane.ERROR_MESSAGE)
                self._results_area.setText("Connection test failed:\n\n" + result)
        except Exception, e:
            error_msg = "Connection test failed: {}".format(str(e))
            JOptionPane.showMessageDialog(self._main_panel, error_msg, "Error", JOptionPane.ERROR_MESSAGE)
            self._results_area.setText(error_msg)

    def _clear_results(self, event):
        """Clear analysis results"""
        self._results_area.setText("Results cleared.")
        self._testcases_area.setText("Test cases cleared.")
        self.analysis_results = {}

    def _export_report(self, event):
        """Export analysis report to file"""
        results = self._results_area.getText()
        if results and "No analysis performed yet" not in results:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = "/Users/nb-dk-0569/Documents/tools/burp_ai_analysis_{}.txt".format(timestamp)
            try:
                with open(filename, 'w') as f:
                    f.write(results)
                JOptionPane.showMessageDialog(self._main_panel,
                    "Report exported successfully to:\n{}".format(filename),
                    "Export Success", JOptionPane.INFORMATION_MESSAGE)
                print("[+] Report exported to: {}".format(filename))
            except Exception, e:
                JOptionPane.showMessageDialog(self._main_panel,
                    "Export failed: {}".format(str(e)),
                    "Error", JOptionPane.ERROR_MESSAGE)
        else:
            JOptionPane.showMessageDialog(self._main_panel,
                "No results to export!",
                "Warning", JOptionPane.WARNING_MESSAGE)

    def _export_report_md(self, event):
        """Export analysis report to Markdown file"""
        results = self._results_area.getText()
        if results and "No analysis performed yet" not in results:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = "/Users/nb-dk-0569/Documents/tools/burp_ai_analysis_{}.md".format(timestamp)
            try:
                # Build markdown content
                md_content = "# AI Threat Analysis Report\n\n"
                md_content += "**Generated:** {}\n\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                md_content += "**Provider:** {} ({})\n\n".format(
                    self.providers.get(self.provider, {}).get("name", self.provider),
                    self.model
                )
                md_content += "---\n\n"
                md_content += results
                md_content += "\n\n---\n\n"
                md_content += "*Report generated by Burp Multi-AI Threat Analyzer*\n"

                with open(filename, 'w') as f:
                    f.write(md_content)
                JOptionPane.showMessageDialog(self._main_panel,
                    "Markdown report exported to:\n{}".format(filename),
                    "Export Success", JOptionPane.INFORMATION_MESSAGE)
                print("[+] Markdown report exported to: {}".format(filename))
            except Exception, e:
                JOptionPane.showMessageDialog(self._main_panel,
                    "Export failed: {}".format(str(e)),
                    "Error", JOptionPane.ERROR_MESSAGE)
        else:
            JOptionPane.showMessageDialog(self._main_panel,
                "No results to export!",
                "Warning", JOptionPane.WARNING_MESSAGE)

    def _export_testcases(self, event):
        """Export test cases to CSV"""
        testcases = self._testcases_area.getText()
        if testcases and testcases != "No test cases generated yet.":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = "/Users/nb-dk-0569/Documents/tools/burp_testcases_{}.csv".format(timestamp)
            try:
                with open(filename, 'w') as f:
                    f.write(testcases)
                JOptionPane.showMessageDialog(self._main_panel,
                    "Test cases exported to:\n{}".format(filename),
                    "Export Success", JOptionPane.INFORMATION_MESSAGE)
            except Exception, e:
                JOptionPane.showMessageDialog(self._main_panel,
                    "Export failed: {}".format(str(e)),
                    "Error", JOptionPane.ERROR_MESSAGE)
        else:
            JOptionPane.showMessageDialog(self._main_panel,
                "No test cases to export!",
                "Warning", JOptionPane.WARNING_MESSAGE)

    def _export_testcases_md(self, event):
        """Export test cases to Markdown file"""
        testcases = self._testcases_area.getText()
        if testcases and testcases != "No test cases generated yet.":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = "/Users/nb-dk-0569/Documents/tools/burp_testcases_{}.md".format(timestamp)
            try:
                # Build markdown content
                md_content = "# Security Test Cases\n\n"
                md_content += "**Generated:** {}\n\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                md_content += "**Provider:** {} ({})\n\n".format(
                    self.providers.get(self.provider, {}).get("name", self.provider),
                    self.model
                )
                md_content += "---\n\n"
                md_content += "## Test Cases\n\n"
                md_content += testcases
                md_content += "\n\n---\n\n"
                md_content += "### Usage Instructions\n\n"
                md_content += "1. Review each test case for applicability\n"
                md_content += "2. Execute tests in a controlled environment\n"
                md_content += "3. Document findings with evidence\n"
                md_content += "4. Report vulnerabilities following responsible disclosure\n\n"
                md_content += "*Generated by Burp Multi-AI Threat Analyzer*\n"

                with open(filename, 'w') as f:
                    f.write(md_content)
                JOptionPane.showMessageDialog(self._main_panel,
                    "Markdown test cases exported to:\n{}".format(filename),
                    "Export Success", JOptionPane.INFORMATION_MESSAGE)
                print("[+] Markdown test cases exported to: {}".format(filename))
            except Exception, e:
                JOptionPane.showMessageDialog(self._main_panel,
                    "Export failed: {}".format(str(e)),
                    "Error", JOptionPane.ERROR_MESSAGE)
        else:
            JOptionPane.showMessageDialog(self._main_panel,
                "No test cases to export!",
                "Warning", JOptionPane.WARNING_MESSAGE)

    def _copy_testcases(self, event):
        """Copy test cases to clipboard"""
        testcases = self._testcases_area.getText()
        if testcases:
            from java.awt.datatransfer import StringSelection
            from java.awt import Toolkit
            toolkit = Toolkit.getDefaultToolkit()
            clipboard = toolkit.getSystemClipboard()
            clipboard.setContents(StringSelection(testcases), None)
            JOptionPane.showMessageDialog(self._main_panel,
                "Test cases copied to clipboard!",
                "Success", JOptionPane.INFORMATION_MESSAGE)

    def getTabCaption(self):
        """Return tab caption"""
        return "AI Analyzer"

    def getUiComponent(self):
        """Return UI component"""
        return self._main_panel

    def createMenuItems(self, invocation):
        """Create context menu items"""
        menu_items = ArrayList()

        # Only show menu for requests
        if invocation.getInvocationContext() in [
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_INTRUDER_ATTACK_RESULTS
        ]:
            # Main menu item
            menu_item_analyze = JMenuItem("Send to AI Analyzer > Analyze Threats",
                                          actionPerformed=lambda x: self._analyze_threats(invocation))
            menu_items.add(menu_item_analyze)

            # Generate test cases menu
            menu_item_testcases = JMenuItem("Send to AI Analyzer > Generate Test Cases",
                                            actionPerformed=lambda x: self._generate_testcases(invocation))
            menu_items.add(menu_item_testcases)

            # Quick vulnerability scan
            menu_item_vulnscan = JMenuItem("Send to AI Analyzer > Quick Vulnerability Scan",
                                           actionPerformed=lambda x: self._quick_vuln_scan(invocation))
            menu_items.add(menu_item_vulnscan)

            # STRIDE analysis
            menu_item_stride = JMenuItem("Send to AI Analyzer > STRIDE Threat Model",
                                        actionPerformed=lambda x: self._stride_analysis(invocation))
            menu_items.add(menu_item_stride)

        return menu_items

    def _get_request_details(self, invocation):
        """Extract request details from invocation"""
        messages = invocation.getSelectedMessages()
        if not messages or len(messages) == 0:
            return None

        request_info_list = []

        for message in messages:
            request = message.getRequest()
            response = message.getResponse()
            http_service = message.getHttpService()

            # Parse request
            analyzed_request = self._helpers.analyzeRequest(http_service, request)
            headers = analyzed_request.getHeaders()
            method = analyzed_request.getMethod()
            url = analyzed_request.getUrl().toString()
            body_offset = analyzed_request.getBodyOffset()
            body = request[body_offset:].tostring()

            # Parse response if available
            response_data = None
            if response:
                analyzed_response = self._helpers.analyzeResponse(response)
                response_headers = analyzed_response.getHeaders()
                response_body_offset = analyzed_response.getBodyOffset()
                response_body = response[response_body_offset:].tostring()
                status_code = analyzed_response.getStatusCode()

                response_data = {
                    "status_code": status_code,
                    "headers": list(response_headers),
                    "body": response_body[:5000]  # Limit body size
                }

            request_info = {
                "method": method,
                "url": url,
                "headers": list(headers),
                "body": body[:5000],  # Limit body size
                "response": response_data
            }

            request_info_list.append(request_info)

        return request_info_list

    def _call_ai_api(self, prompt, system_prompt=None):
        """Call AI API based on selected provider"""
        if self.provider == "qwen":
            return self._call_qwen(prompt, system_prompt)
        elif self.provider == "openai":
            return self._call_openai(prompt, system_prompt)
        elif self.provider == "anthropic":
            return self._call_anthropic(prompt, system_prompt)
        elif self.provider == "ollama":
            return self._call_ollama(prompt, system_prompt)
        elif self.provider == "glm":
            return self._call_glm(prompt, system_prompt)
        elif self.provider == "glm_openrouter":
            return self._call_glm_openrouter(prompt, system_prompt)
        else:
            return "ERROR: Unknown provider: {}".format(self.provider)

    def _call_qwen(self, prompt, system_prompt=None):
        """Call Qwen API (Alibaba Cloud)"""
        if not self.api_key:
            return "ERROR: API key not configured. Please configure in Settings tab."

        try:
            messages = []

            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})

            messages.append({"role": "user", "content": prompt})

            payload = {
                "model": self.model,
                "input": {
                    "messages": messages
                },
                "parameters": {
                    "max_tokens": 8000,
                    "temperature": 0.7,
                    "top_p": 0.8
                }
            }

            req = urllib2.Request(self.api_endpoint)
            req.add_header("Content-Type", "application/json")
            req.add_header("Authorization", "Bearer {}".format(self.api_key))

            response = urllib2.urlopen(req, json.dumps(payload))
            result = json.loads(response.read())

            # Qwen response format
            if "output" in result and "text" in result["output"]:
                return result["output"]["text"]
            elif "output" in result and "choices" in result["output"]:
                if len(result["output"]["choices"]) > 0:
                    return result["output"]["choices"][0]["message"]["content"]
            else:
                return "ERROR: Unexpected Qwen API response format: {}".format(str(result))

        except urllib2.HTTPError, e:
            error_body = e.read()
            return "HTTP ERROR {}: {}\nPlease check your Qwen API key at https://dashscope.console.aliyun.com/".format(e.code, error_body)
        except Exception, e:
            return "ERROR: {}\n\nTroubleshooting:\n- Verify API key is correct\n- Check internet connection\n- Ensure Qwen API service is accessible".format(str(e))

    def _call_openai(self, prompt, system_prompt=None):
        """Call OpenAI API"""
        if not self.api_key:
            return "ERROR: API key not configured. Please configure in Settings tab."

        try:
            messages = []

            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})

            messages.append({"role": "user", "content": prompt})

            payload = {
                "model": self.model,
                "messages": messages,
                "max_tokens": 8000,
                "temperature": 0.7
            }

            req = urllib2.Request(self.api_endpoint)
            req.add_header("Content-Type", "application/json")
            req.add_header("Authorization", "Bearer {}".format(self.api_key))

            response = urllib2.urlopen(req, json.dumps(payload))
            result = json.loads(response.read())

            if "choices" in result and len(result["choices"]) > 0:
                return result["choices"][0]["message"]["content"]
            else:
                return "ERROR: Unexpected API response format"

        except urllib2.HTTPError, e:
            error_body = e.read()
            return "HTTP ERROR {}: {}".format(e.code, error_body)
        except Exception, e:
            return "ERROR: {}".format(str(e))

    def _call_anthropic(self, prompt, system_prompt=None):
        """Call Anthropic API"""
        if not self.api_key:
            return "ERROR: API key not configured."

        try:
            messages = [{"role": "user", "content": prompt}]

            payload = {
                "model": self.model,
                "max_tokens": 8192,
                "messages": messages
            }

            if system_prompt:
                payload["system"] = system_prompt

            req = urllib2.Request(self.api_endpoint)
            req.add_header("Content-Type", "application/json")
            req.add_header("x-api-key", self.api_key)
            req.add_header("anthropic-version", "2023-06-01")

            response = urllib2.urlopen(req, json.dumps(payload))
            result = json.loads(response.read())

            if "content" in result and len(result["content"]) > 0:
                return result["content"][0]["text"]
            else:
                return "ERROR: Unexpected API response format"

        except urllib2.HTTPError, e:
            error_body = e.read()
            return "HTTP ERROR {}: {}".format(e.code, error_body)
        except Exception, e:
            return "ERROR: {}".format(str(e))

    def _call_ollama(self, prompt, system_prompt=None):
        """Call Ollama local API"""
        try:
            messages = []

            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})

            messages.append({"role": "user", "content": prompt})

            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False
            }

            req = urllib2.Request(self.api_endpoint)
            req.add_header("Content-Type", "application/json")

            response = urllib2.urlopen(req, json.dumps(payload))
            result = json.loads(response.read())

            if "message" in result and "content" in result["message"]:
                return result["message"]["content"]
            else:
                return "ERROR: Unexpected Ollama response format"

        except urllib2.URLError, e:
            return "ERROR: Cannot connect to Ollama. Is it running? (ollama serve)\n{}".format(str(e))
        except Exception, e:
            return "ERROR: {}".format(str(e))

    def _generate_glm_token(self):
        """Generate JWT token for Zhipu BigModel API"""
        import time
        import hmac
        import hashlib

        try:
            # API key format: api_key_id.api_key_secret
            parts = self.api_key.split('.')
            if len(parts) != 2:
                return self.api_key  # Return as-is if format is wrong

            api_key_id = parts[0]
            api_key_secret = parts[1]

            # Create JWT header and payload
            timestamp = int(time.time() * 1000)
            exp_time = int(time.time()) + 3600  # 1 hour expiry

            # JWT Header
            header = {"alg": "HS256", "sign_type": "SIGN", "typ": "JWT"}
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()

            # JWT Payload
            payload = {
                "api_key": api_key_id,
                "exp": exp_time,
                "timestamp": timestamp
            }
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()

            # Create signature
            sign_content = "{}.{}".format(header_b64, payload_b64)
            signature = hmac.new(
                api_key_secret.encode(),
                sign_content.encode(),
                hashlib.sha256
            ).digest()
            signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

            # Combine to JWT
            jwt_token = "{}.{}.{}".format(header_b64, payload_b64, signature_b64)
            return jwt_token

        except Exception, e:
            print("[!] Error generating GLM token: {}".format(str(e)))
            return self.api_key  # Return as-is on error

    def _call_glm(self, prompt, system_prompt=None):
        """Call GLM API (Zhipu/BigModel)"""
        if not self.api_key:
            return "ERROR: API key not configured. Please configure in Settings tab."

        try:
            messages = []

            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})

            messages.append({"role": "user", "content": prompt})

            payload = {
                "model": self.model,
                "messages": messages,
                "max_tokens": 8000,
                "temperature": 0.7,
                "top_p": 0.8
            }

            # Generate JWT token for authentication
            token = self._generate_glm_token()

            req = urllib2.Request(self.api_endpoint)
            req.add_header("Content-Type", "application/json")
            req.add_header("Authorization", "Bearer {}".format(token))

            response = urllib2.urlopen(req, json.dumps(payload), timeout=120)
            result = json.loads(response.read())

            # GLM response format
            if "choices" in result and len(result["choices"]) > 0:
                return result["choices"][0]["message"]["content"]
            else:
                return "ERROR: Unexpected GLM API response format: {}".format(str(result))

        except urllib2.HTTPError, e:
            error_body = e.read()
            return "HTTP ERROR {}: {}\n\nPlease check:\n- API key format: ID.SECRET\n- Account balance at https://open.bigmodel.cn/".format(e.code, error_body)
        except Exception, e:
            return "ERROR: {}\n\nTroubleshooting:\n- Verify API key format is ID.SECRET\n- Check internet connection\n- Ensure GLM API service is accessible".format(str(e))

    def _call_glm_openrouter(self, prompt, system_prompt=None):
        """Call GLM via OpenRouter (uses DeepSeek as alternative)"""
        if not self.api_key:
            return "ERROR: OpenRouter API key not configured. Please configure in Settings tab."

        try:
            messages = []

            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})

            messages.append({"role": "user", "content": prompt})

            payload = {
                "model": self.model,
                "messages": messages,
                "max_tokens": 8000,
                "temperature": 0.7
            }

            req = urllib2.Request(self.api_endpoint)
            req.add_header("Content-Type", "application/json")
            req.add_header("Authorization", "Bearer {}".format(self.api_key))
            req.add_header("HTTP-Referer", "https://burp-ai-analyzer.local")
            req.add_header("X-Title", "Burp Multi-AI Threat Analyzer")

            response = urllib2.urlopen(req, json.dumps(payload), timeout=120)
            result = json.loads(response.read())

            if "choices" in result and len(result["choices"]) > 0:
                return result["choices"][0]["message"]["content"]
            else:
                return "ERROR: Unexpected OpenRouter API response format: {}".format(str(result))

        except urllib2.HTTPError, e:
            error_body = e.read()
            return "HTTP ERROR {}: {}\n\nPlease check your OpenRouter API key at https://openrouter.ai/".format(e.code, error_body)
        except Exception, e:
            return "ERROR: {}".format(str(e))

    def _analyze_threats(self, invocation):
        """Perform comprehensive threat analysis"""
        request_details = self._get_request_details(invocation)
        if not request_details:
            return

        self._update_history(request_details)
        self._results_area.setText("Analyzing threats with {} ({})...\nPlease wait...".format(
            self.providers[self.provider]["name"], self.model))
        self._tabs.setSelectedIndex(1)

        prompt = self._build_threat_analysis_prompt(request_details)
        system_prompt = """You are an expert security researcher and penetration tester specializing in web application security, API security, and threat modeling.

Your task is to perform comprehensive threat analysis on HTTP requests/responses from Burp Suite.

Provide analysis in this format:

# THREAT ANALYSIS REPORT

## EXECUTIVE SUMMARY
[Brief overview of findings]

## ENDPOINT ANALYSIS
[Analyze each endpoint: method, URL, parameters, authentication]

## OWASP TOP 10 MAPPING
[Map findings to OWASP Top 10 2021]

## STRIDE THREAT MODEL
- Spoofing: [threats]
- Tampering: [threats]
- Repudiation: [threats]
- Information Disclosure: [threats]
- Denial of Service: [threats]
- Elevation of Privilege: [threats]

## VULNERABILITIES DETECTED
[List specific vulnerabilities with severity, CWE, CVSS]

## ATTACK VECTORS
[Provide specific attack scenarios with PoC]

## SECURITY TEST CASES REQUIRED
[List test cases needed to validate security]

## RECOMMENDATIONS
[Prioritized remediation steps]

Be specific, technical, and provide actionable findings."""

        result = self._call_ai_api(prompt, system_prompt)
        self._results_area.setText(result)
        self._extract_testcases(result)

        print("[+] Threat analysis completed using {}".format(self.provider))

    def _generate_testcases(self, invocation):
        """Generate security test cases"""
        request_details = self._get_request_details(invocation)
        if not request_details:
            return

        self._testcases_area.setText("Generating test cases with {} ({})...\nPlease wait...".format(
            self.providers[self.provider]["name"], self.model))
        self._tabs.setSelectedIndex(2)

        prompt = self._build_testcase_generation_prompt(request_details)
        system_prompt = """You are a security QA engineer specializing in security test case design.

Generate comprehensive security test cases in CSV format:

Test_ID,Category,Test_Case_Name,Endpoint,Method,Test_Data,Expected_Result,Severity,CWE

Include test cases for:
- Authentication bypass
- Authorization flaws
- Input validation
- Injection attacks (SQL, XSS, XXE, etc.)
- Business logic flaws
- Rate limiting
- CSRF
- Insecure deserialization
- API abuse

Provide specific, executable test cases with actual payloads."""

        result = self._call_ai_api(prompt, system_prompt)
        self._testcases_area.setText(result)

        print("[+] Test case generation completed using {}".format(self.provider))

    def _quick_vuln_scan(self, invocation):
        """Quick vulnerability scan"""
        request_details = self._get_request_details(invocation)
        if not request_details:
            return

        self._results_area.setText("Running quick vulnerability scan...\nPlease wait...")
        self._tabs.setSelectedIndex(1)

        prompt = self._build_vuln_scan_prompt(request_details)
        system_prompt = """You are a vulnerability scanner. Quickly identify potential vulnerabilities in HTTP requests/responses.

Format:
# QUICK VULNERABILITY SCAN

## CRITICAL
[List critical vulnerabilities]

## HIGH
[List high severity vulnerabilities]

## MEDIUM
[List medium severity vulnerabilities]

## LOW
[List low severity vulnerabilities]

For each vulnerability:
- Name
- Location (parameter/header)
- PoC payload
- Impact

Be concise but specific."""

        result = self._call_ai_api(prompt, system_prompt)
        self._results_area.setText(result)

        print("[+] Quick vulnerability scan completed")

    def _stride_analysis(self, invocation):
        """STRIDE threat model analysis"""
        request_details = self._get_request_details(invocation)
        if not request_details:
            return

        self._results_area.setText("Performing STRIDE analysis...\nPlease wait...")
        self._tabs.setSelectedIndex(1)

        prompt = self._build_stride_prompt(request_details)
        system_prompt = """You are a threat modeling expert using the STRIDE methodology.

Analyze the HTTP request/response and identify threats in each STRIDE category:

# STRIDE THREAT MODEL

## Spoofing (Authentication)
[Identify spoofing threats]

## Tampering (Integrity)
[Identify tampering threats]

## Repudiation (Non-repudiation)
[Identify repudiation threats]

## Information Disclosure (Confidentiality)
[Identify information disclosure threats]

## Denial of Service (Availability)
[Identify DoS threats]

## Elevation of Privilege (Authorization)
[Identify privilege escalation threats]

For each threat, provide:
- Threat description
- Attack scenario
- Risk level (Critical/High/Medium/Low)
- Mitigation"""

        result = self._call_ai_api(prompt, system_prompt)
        self._results_area.setText(result)

        print("[+] STRIDE analysis completed")

    def _build_threat_analysis_prompt(self, request_details):
        """Build prompt for threat analysis"""
        prompt = "Analyze the following HTTP request(s) for security threats:\n\n"

        for i, req in enumerate(request_details, 1):
            prompt += "REQUEST #{}\n".format(i)
            prompt += "=" * 60 + "\n"
            prompt += "Method: {}\n".format(req["method"])
            prompt += "URL: {}\n\n".format(req["url"])
            prompt += "Headers:\n"
            for header in req["headers"]:
                prompt += "  {}\n".format(header)
            prompt += "\nRequest Body:\n"
            prompt += req["body"][:2000]
            prompt += "\n\n"

            if req["response"]:
                prompt += "Response Status: {}\n".format(req["response"]["status_code"])
                prompt += "Response Body (truncated):\n"
                prompt += req["response"]["body"][:2000]

            prompt += "\n\n"

        return prompt

    def _build_testcase_generation_prompt(self, request_details):
        """Build prompt for test case generation"""
        prompt = "Generate comprehensive security test cases for:\n\n"

        for i, req in enumerate(request_details, 1):
            prompt += "Endpoint #{}: {} {}\n".format(i, req["method"], req["url"])
            if req["body"]:
                prompt += "Request Body: {}\n".format(req["body"][:500])

        return prompt

    def _build_vuln_scan_prompt(self, request_details):
        """Build prompt for vulnerability scan"""
        prompt = "Perform quick vulnerability scan on:\n\n"

        for req in request_details:
            prompt += "{} {}\n".format(req["method"], req["url"])
            prompt += "Headers: {}\n".format(", ".join(req["headers"][:5]))
            prompt += "Body: {}\n\n".format(req["body"][:500])

        return prompt

    def _build_stride_prompt(self, request_details):
        """Build prompt for STRIDE analysis"""
        prompt = "Perform STRIDE threat modeling on:\n\n"

        for req in request_details:
            prompt += "{} {}\n".format(req["method"], req["url"])
            prompt += "Body: {}\n\n".format(req["body"][:1000])

        return prompt

    def _extract_testcases(self, analysis_result):
        """Extract test cases from analysis result"""
        if "SECURITY TEST CASES" in analysis_result:
            lines = analysis_result.split("\n")
            testcases = []
            in_testcase_section = False

            for line in lines:
                if "SECURITY TEST CASES" in line:
                    in_testcase_section = True
                elif in_testcase_section:
                    if line.startswith("#") and "RECOMMENDATION" in line:
                        break
                    testcases.append(line)

            if testcases:
                self._testcases_area.setText("\n".join(testcases))

    def _update_history(self, request_details):
        """Update request history display"""
        history_text = "=== SELECTED REQUESTS ===\n\n"

        for i, req in enumerate(request_details, 1):
            history_text += "Request #{}\n".format(i)
            history_text += "{} {}\n".format(req["method"], req["url"])
            history_text += "-" * 60 + "\n\n"

        history_text += "Total requests: {}\n".format(len(request_details))
        history_text += "Analysis timestamp: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        history_text += "Provider: {} ({})\n".format(self.providers[self.provider]["name"], self.model)

        self._history_area.setText(history_text)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """HTTP message processor (for future enhancements)"""
        pass
