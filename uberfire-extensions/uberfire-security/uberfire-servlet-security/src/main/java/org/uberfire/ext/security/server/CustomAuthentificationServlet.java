package org.uberfire.ext.security.server;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CustomAuthentificationServlet extends HttpServlet {

	@Inject
	ServletSecurityAuthenticationService authenticationService;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String username = req.getParameter("username");
		String password = req.getParameter("password");
		if(null != username && password != null)
			authenticationService.login(username, password);
		StringBuilder redirectTarget = new StringBuilder(req.getContextPath() + "/login");
		 String extraParams = extractParameters(req);
	        if (extraParams.length() > 0) {
	            redirectTarget.append("?").append(extraParams);
	        }
		resp.sendRedirect(redirectTarget.toString());
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		super.doPost(req, resp);
	}

	@Override
	public void init() throws ServletException {
		super.init();
	}

	private String extractParameters(HttpServletRequest fromRequest) {
		try {
			StringBuilder sb = new StringBuilder();
			for (Map.Entry<String, String[]> param : (Set<Map.Entry<String, String[]>>) fromRequest.getParameterMap().entrySet()) {
				String paramName = URLEncoder.encode(param.getKey(), "UTF-8");
				if (paramName.equals("username") || paramName.equals("password")) {
					continue;
				}
				for (String value : param.getValue()) {
					if (sb.length() != 0) {
						sb.append("&");
					}
					sb.append(paramName).append("=").append(URLEncoder.encode(value, "UTF-8"));
				}
			}
			return sb.toString();
		} catch (UnsupportedEncodingException e) {
			throw new AssertionError("UTF-8 not supported on this JVM?");
		}
	}
}
