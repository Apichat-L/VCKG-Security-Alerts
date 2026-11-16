<%@ page contentType="text/html" import="javax.naming.InitialContext,javax.sql.DataSource,java.sql.*" %>
<!doctype html>
<html><head><title>HR portal (lab)</title></head><body>
<h1>HR portal</h1>
<p>Employee directory (dummy data, lab only).</p>
<table border="1"><tr><th>Name</th><th>Department</th></tr>
<%
try (Connection c = ((DataSource) new InitialContext().lookup("java:comp/env/jdbc/hr")).getConnection();
     Statement s = c.createStatement(); ResultSet r = s.executeQuery("SELECT name, department FROM employees ORDER BY id")) {
    while (r.next()) {
        out.println("<tr><td>" + r.getString(1) + "</td><td>" + r.getString(2) + "</td></tr>");
    }
} catch (Exception e) {
    response.setStatus(503);
    out.println("<tr><td colspan=2>directory unavailable</td></tr>");
}
%>
</table></body></html>
