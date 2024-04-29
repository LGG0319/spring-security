/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.web.header;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.FilterChain;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.OnCommittedResponseWrapper;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Filter implementation to add headers to the current response. Can be useful to add
 * certain headers which enable browser protection. Like X-Frame-Options, X-XSS-Protection
 * and X-Content-Type-Options.
 *
 * @author Marten Deinum
 * @author Josh Cummings
 * @author Ankur Pathak
 * @since 3.2
 * (4) 处理头信息加入响应中，默认程序启动就会加载
 * 作用：为当前响应添加报头的过滤器实现。可以添加某些头，启用浏览器保护。像X-Frame-Options, X-XSS-Protection和X-Content-Type-Options
 */
public class HeaderWriterFilter extends OncePerRequestFilter {

	/**
	 * The {@link HeaderWriter} to write headers to the response.
	 * {@see CompositeHeaderWriter}
	 */
	private final List<HeaderWriter> headerWriters;

	/**
	 * Indicates whether to write the headers at the beginning of the request.
	 * 默认是false 也就是在过滤器都执行完成后，回到该过滤器时向response中写入
	 */
	private boolean shouldWriteHeadersEagerly = false;

	/**
	 * Creates a new instance.
	 * @param headerWriters the {@link HeaderWriter} instances to write out headers to the
	 * {@link HttpServletResponse}.
	 * 构造方法，需要在构造该过滤器时就传入要写入ResponseHeader的头信息
	 */
	public HeaderWriterFilter(List<HeaderWriter> headerWriters) {
		Assert.notEmpty(headerWriters, "headerWriters cannot be null or empty");
		this.headerWriters = headerWriters;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (this.shouldWriteHeadersEagerly) {
			// 如果是提前写入响应头，则是直接调用了writeHeaders 方法，并继续执行过滤器
			doHeadersBefore(request, response, filterChain);
		}
		else {
			// 默认走该方法
			// 在过滤器执行完成后，再写入头信息
			doHeadersAfter(request, response, filterChain);
		}
	}

	private void doHeadersBefore(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {
		writeHeaders(request, response);
		filterChain.doFilter(request, response);
	}

	private void doHeadersAfter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {
		HeaderWriterResponse headerWriterResponse = new HeaderWriterResponse(request, response);
		HeaderWriterRequest headerWriterRequest = new HeaderWriterRequest(request, headerWriterResponse);
		try {
			filterChain.doFilter(headerWriterRequest, headerWriterResponse);
		}
		finally {
			headerWriterResponse.writeHeaders();
		}
	}

	void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		for (HeaderWriter writer : this.headerWriters) {
			writer.writeHeaders(request, response);
		}
	}

	/**
	 * Allow writing headers at the beginning of the request.
	 * @param shouldWriteHeadersEagerly boolean to allow writing headers at the beginning
	 * of the request.
	 * @since 5.2
	 */
	public void setShouldWriteHeadersEagerly(boolean shouldWriteHeadersEagerly) {
		this.shouldWriteHeadersEagerly = shouldWriteHeadersEagerly;
	}

	class HeaderWriterResponse extends OnCommittedResponseWrapper {

		private final HttpServletRequest request;

		HeaderWriterResponse(HttpServletRequest request, HttpServletResponse response) {
			super(response);
			this.request = request;
		}

		@Override
		protected void onResponseCommitted() {
			writeHeaders();
			this.disableOnResponseCommitted();
		}

		protected void writeHeaders() {
			if (isDisableOnResponseCommitted()) {
				return;
			}
			HeaderWriterFilter.this.writeHeaders(this.request, getHttpResponse());
		}

		private HttpServletResponse getHttpResponse() {
			return (HttpServletResponse) getResponse();
		}

	}

	static class HeaderWriterRequest extends HttpServletRequestWrapper {

		private final HeaderWriterResponse response;

		HeaderWriterRequest(HttpServletRequest request, HeaderWriterResponse response) {
			super(request);
			this.response = response;
		}

		@Override
		public RequestDispatcher getRequestDispatcher(String path) {
			return new HeaderWriterRequestDispatcher(super.getRequestDispatcher(path), this.response);
		}

	}

	static class HeaderWriterRequestDispatcher implements RequestDispatcher {

		private final RequestDispatcher delegate;

		private final HeaderWriterResponse response;

		HeaderWriterRequestDispatcher(RequestDispatcher delegate, HeaderWriterResponse response) {
			this.delegate = delegate;
			this.response = response;
		}

		@Override
		public void forward(ServletRequest request, ServletResponse response) throws ServletException, IOException {
			this.delegate.forward(request, response);
		}

		@Override
		public void include(ServletRequest request, ServletResponse response) throws ServletException, IOException {
			this.response.onResponseCommitted();
			this.delegate.include(request, response);
		}

	}

}
