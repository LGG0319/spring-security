/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.session;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Disables encoding URLs using the {@link HttpServletResponse} to prevent including the
 * session id in URLs which is not considered URL because the session id can be leaked in
 * things like HTTP access logs.
 * （1）禁用使用 HttpServletResponse 对URL进行编码，以防止将会话id包括在不被视为URL的URL中，因为会话id可能会在HTTP访问日志中泄露
 * 原因：Session的会话持有在客户端是通过cookies来保存SessionId来实现的，每次客户端的请求都携带sessionId.
 * 		如果禁用了cookie，后端的默认响应会重写url将sessionId拼接到url后面，传递给页面，sessionId就在http访问日志中暴露了
 * @author Rob Winch
 * @since 5.7
 */
public class DisableEncodeUrlFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// 对response进行包装后直接放行
		filterChain.doFilter(request, new DisableEncodeUrlResponseWrapper(response));
	}

	/**
	 * Disables URL rewriting for the {@link HttpServletResponse} to prevent including the
	 * session id in URLs which is not considered URL because the session id can be leaked
	 * in things like HTTP access logs.
	 *
	 * @author Rob Winch
	 * @since 5.7
	 */
	private static final class DisableEncodeUrlResponseWrapper extends HttpServletResponseWrapper {

		/**
		 * Constructs a response adaptor wrapping the given response.
		 * @param response the {@link HttpServletResponse} to be wrapped.
		 * @throws IllegalArgumentException if the response is null
		 */
		private DisableEncodeUrlResponseWrapper(HttpServletResponse response) {
			super(response);
		}

		@Override
		public String encodeRedirectURL(String url) {
			return url;
		}

		@Override
		public String encodeURL(String url) {
			return url;
		}

	}

}
