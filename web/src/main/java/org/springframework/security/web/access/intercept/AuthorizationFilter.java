/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.access.intercept;

import java.io.IOException;
import java.util.function.Supplier;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * An authorization filter that restricts access to the URL using
 * {@link AuthorizationManager}.
 *
 * @author Evgeniy Cheban
 * @since 5.5
 * （15） 处理当前用户是否有权限访问目标资源，默认程序启动就会加载
 * 作用：判断当前的用户用没有权限可以访问目标资源。
 * 		如果用户没有权限访问当前资源 会抛出 AccessDeniedException。异常会被ExceptionTranslationFilter处理。
 */
public class AuthorizationFilter extends GenericFilterBean {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private final AuthorizationManager<HttpServletRequest> authorizationManager;

	private AuthorizationEventPublisher eventPublisher = new NoopAuthorizationEventPublisher();

	private boolean observeOncePerRequest = false;

	private boolean filterErrorDispatch = true;

	private boolean filterAsyncDispatch = true;

	/**
	 * Creates an instance.
	 * @param authorizationManager the {@link AuthorizationManager} to use
	 */
	public AuthorizationFilter(AuthorizationManager<HttpServletRequest> authorizationManager) {
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.authorizationManager = authorizationManager;
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws ServletException, IOException {

		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;
		// 判断是否 监控每一次请求 并且 当前请求已经执行过该过滤器 则跳过认证
		if (this.observeOncePerRequest && isApplied(request)) {
			chain.doFilter(request, response);
			return;
		}
		// 当请求的转发方式 为ERROR 和 ASYNC时 跳过认证
		// DispatcherType.ERROR  当容器将处理过程传递给错误处理机制(如定义的错误页)时。
		// DispatcherType.ASYNC  在以下几种情况下 AsyncContext.dispatch(), AsyncContext.dispatch(String) and AsyncContext.addListener(AsyncListener, ServletRequest, ServletResponse)
		if (skipDispatch(request)) {
			chain.doFilter(request, response);
			return;
		}
		// 获取记录已经执行过该过滤器的标记setAttribute KEY
		String alreadyFilteredAttributeName = getAlreadyFilteredAttributeName();
		// 设置为TRUE 表示已经执行了该过滤器
		request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);
		try {
			// 调用authorizationManager 判断当前用户是否有权限访问该资源
			// this::getAuthentication -> 获取用户的认证信息
			// request： 当前请求
			// AuthorizationDecision: 授权描述  decision.isGranted() 表示是否有该资源的权限
			AuthorizationResult result = this.authorizationManager.authorize(this::getAuthentication, request);
			// 发布一个认证的消息
			this.eventPublisher.publishAuthorizationEvent(this::getAuthentication, request, result);
			// 如果未授权，抛出异常AccessDeniedException
			if (result != null && !result.isGranted()) {
				throw new AuthorizationDeniedException("Access Denied", result);
			}
			// 已授权 继续向后执行
			chain.doFilter(request, response);
		}
		finally {
			// 请求执行完成后 移除掉 已执行标记
			request.removeAttribute(alreadyFilteredAttributeName);
		}
	}

	private boolean skipDispatch(HttpServletRequest request) {
		if (DispatcherType.ERROR.equals(request.getDispatcherType()) && !this.filterErrorDispatch) {
			return true;
		}

		return DispatcherType.ASYNC.equals(request.getDispatcherType()) && !this.filterAsyncDispatch;
	}

	private boolean isApplied(HttpServletRequest request) {
		return request.getAttribute(getAlreadyFilteredAttributeName()) != null;
	}

	private String getAlreadyFilteredAttributeName() {
		String name = getFilterName();
		if (name == null) {
			name = getClass().getName();
		}
		return name + ".APPLIED";
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	private Authentication getAuthentication() {
		Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
		if (authentication == null) {
			throw new AuthenticationCredentialsNotFoundException(
					"An Authentication object was not found in the SecurityContext");
		}
		return authentication;
	}

	/**
	 * Use this {@link AuthorizationEventPublisher} to publish
	 * {@link AuthorizationDeniedEvent}s and {@link AuthorizationGrantedEvent}s.
	 * @param eventPublisher the {@link ApplicationEventPublisher} to use
	 * @since 5.7
	 */
	public void setAuthorizationEventPublisher(AuthorizationEventPublisher eventPublisher) {
		Assert.notNull(eventPublisher, "eventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
	}

	/**
	 * Gets the {@link AuthorizationManager} used by this filter
	 * @return the {@link AuthorizationManager}
	 */
	public AuthorizationManager<HttpServletRequest> getAuthorizationManager() {
		return this.authorizationManager;
	}

	/**
	 * Sets whether to filter all dispatcher types.
	 * @param shouldFilterAllDispatcherTypes should filter all dispatcher types. Default
	 * is {@code true}
	 * @since 5.7
	 * @deprecated Permit access to the {@link jakarta.servlet.DispatcherType} instead.
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class SecurityConfig {
	 *
	 * 	&#064;Bean
	 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * 		http
	 * 		 	.authorizeHttpRequests((authorize) -&gt; authorize
	 * 				.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
	 * 			 	// ...
	 * 		 	);
	 * 		return http.build();
	 * 	}
	 * }
	 * </pre>
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public void setShouldFilterAllDispatcherTypes(boolean shouldFilterAllDispatcherTypes) {
		this.observeOncePerRequest = !shouldFilterAllDispatcherTypes;
		this.filterErrorDispatch = shouldFilterAllDispatcherTypes;
		this.filterAsyncDispatch = shouldFilterAllDispatcherTypes;
	}

	public boolean isObserveOncePerRequest() {
		return this.observeOncePerRequest;
	}

	/**
	 * Sets whether this filter apply only once per request. By default, this is
	 * <code>false</code>, meaning the filter will execute on every request. Sometimes
	 * users may wish it to execute more than once per request, such as when JSP forwards
	 * are being used and filter security is desired on each included fragment of the HTTP
	 * request.
	 * @param observeOncePerRequest whether the filter should only be applied once per
	 * request
	 */
	public void setObserveOncePerRequest(boolean observeOncePerRequest) {
		this.observeOncePerRequest = observeOncePerRequest;
	}

	/**
	 * If set to true, the filter will be applied to error dispatcher. Defaults to
	 * {@code true}.
	 * @param filterErrorDispatch whether the filter should be applied to error dispatcher
	 */
	public void setFilterErrorDispatch(boolean filterErrorDispatch) {
		this.filterErrorDispatch = filterErrorDispatch;
	}

	/**
	 * If set to true, the filter will be applied to the async dispatcher. Defaults to
	 * {@code true}.
	 * @param filterAsyncDispatch whether the filter should be applied to async dispatch
	 */
	public void setFilterAsyncDispatch(boolean filterAsyncDispatch) {
		this.filterAsyncDispatch = filterAsyncDispatch;
	}

	private static class NoopAuthorizationEventPublisher implements AuthorizationEventPublisher {

		@Override
		public <T> void publishAuthorizationEvent(Supplier<Authentication> authentication, T object,
				AuthorizationDecision decision) {

		}

		@Override
		public <T> void publishAuthorizationEvent(Supplier<Authentication> authentication, T object,
				AuthorizationResult result) {
		}

	}

}
