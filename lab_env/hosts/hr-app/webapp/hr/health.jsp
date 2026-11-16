<%@ page contentType="text/plain" import="javax.naming.InitialContext,javax.sql.DataSource,java.sql.*" %><%
// lab_env/eval health check: 200 if the employees table on HR-DB can be read, 503 otherwise.
try (Connection c = ((DataSource) new InitialContext().lookup("java:comp/env/jdbc/hr")).getConnection();
     Statement s = c.createStatement(); ResultSet r = s.executeQuery("SELECT count(*) FROM employees")) {
    r.next();
    out.println("ok employees=" + r.getInt(1));
} catch (Exception e) {
    response.setStatus(503);
    out.println("hr-db unavailable: " + e.getMessage());
}
%>
