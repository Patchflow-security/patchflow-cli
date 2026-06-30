package spring

// TemplateExtensions lists the Spring template extensions this pack scans.
// Declared here for documentation; the canonical list is returned by Pack.
//
// Spring supports multiple template engines:
//   - Thymeleaf: .html (with th: namespace), .thymeleaf.html
//   - JSP: .jsp, .jspx
//   - FreeMarker: .ftl
//   - Velocity: .vm
var TemplateExtensions = []string{".jsp", ".jspx", ".ftl", ".vm", ".html", ".thymeleaf.html"}
