# Desc
* Application for analyzing .jar files.
* Performs static analysis of archive contents, detects potential threats, and displays results in a simple GUI.
  
---

# Features
* Load and analyze JAR files.
* Results table (`type, risk, class, method, description`).
* Detailed threat information view.
* JAR statistics: classes, files, errors, entry points.
  
---

# Run
```
mvn clean package
java -jar jar-analyzer.jar
```
