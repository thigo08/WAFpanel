# WAF Control Panel
This project presents a Control Panel, which provides the maintenance of the security settings of libraries developed by OWASP (Open Web Application Security Project), and aims to reduce the complexity of using these components to improve the integration and reuse of this in applications which use the Demoiselle Framework.

# ABOUT
- Develop a Control Panel that facilitates the maintenance of security settings OWASP WAF library.
- Modify the mode of persistence of security settings, so that they are persisted in a database.
- Allow the operation and development teams carry out the maintenance of security settings for easy and standardized way.

This project was developed based on the original library ESAPI - https://github.com/ESAPI/esapi-java-legacy. Adopting the WAF package to make major changes.

# ABSTRACT
The library contains a ESAPI WAF package that has the main rules of security for web applications. In the current model, all classes of the OWASP WAF rules are loaded through the file (waf-policy.xml), which tells what are the rules to be used in the application.

The proposal was to develop a Web Security Control Panel, allowing settings to be performed through a GUI and that information is persisted in a database.
