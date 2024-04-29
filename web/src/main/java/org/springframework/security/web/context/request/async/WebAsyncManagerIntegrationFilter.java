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

package org.springframework.security.web.context.request.async;

import java.io.IOException;
import java.util.concurrent.Callable;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.context.request.async.WebAsyncManager;
import org.springframework.web.context.request.async.WebAsyncUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Provides integration between the {@link SecurityContext} and Spring Web's
 * {@link WebAsyncManager} by using the
 * {@link SecurityContextCallableProcessingInterceptor#beforeConcurrentHandling(org.springframework.web.context.request.NativeWebRequest, Callable)}
 * to populate the {@link SecurityContext} on the {@link Callable}.
 *
 * @author Rob Winch
 * @see SecurityContextCallableProcessingInterceptor
 * （2）此过滤器用于集成SecurityContext到Spring异步执行机制中的WebAsyncManager。
 * 实现安全上下文从调用者线程 到被调用者线程的传播
 * 原因：默认情况下securityContextHolderStrategy的存储策略为ThreadLocal,在ThreadLocal的存储策略下，只有当前线程可以获取到securityContextHolder。
 * 		WebAsyncManagerIntegrationFilter 通过创建拦截器的形式，将securityContextHolderStrategy传递给子线程，后续子线程可以通过该拦截器获取到用户认证信息
 */
public final class WebAsyncManagerIntegrationFilter extends OncePerRequestFilter {

	private static final Object CALLABLE_INTERCEPTOR_KEY = new Object();

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// 从请求属性上获取所绑定的`WebAsyncManager`，如果尚未绑定，先做绑定
		// 相应的属性名称为 :
		// org.springframework.web.context.request.async.WebAsyncManager.WEB_ASYNC_MANAGER
		WebAsyncManager asyncManager = WebAsyncUtils.getAsyncManager(request);

		// 从 asyncManager 中获取 key 为 CALLABLE_INTERCEPTOR_KEY 的 SecurityContextCallableProcessingInterceptor,
		// 如果获取到的为 null，说明其中还没有 key 为 CALLABLE_INTERCEPTOR_KEY 的 SecurityContextCallableProcessingInterceptor,
		//  新建一个并使用该 key 注册上去
		SecurityContextCallableProcessingInterceptor securityProcessingInterceptor = (SecurityContextCallableProcessingInterceptor) asyncManager
			.getCallableInterceptor(CALLABLE_INTERCEPTOR_KEY);
		if (securityProcessingInterceptor == null) {
			SecurityContextCallableProcessingInterceptor interceptor = new SecurityContextCallableProcessingInterceptor();
			interceptor.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
			// 这里新建的 SecurityContextCallableProcessingInterceptor 实现了接口 CallableProcessingInterceptor，
			// 当它被应用于一次异步执行时，它的方法beforeConcurrentHandling() 会在调用者线程执行，
			// 该方法会相应地从当前线程获取SecurityContext,然后被调用者线程中执行设计的逻辑时，会使用这个SecurityContext，从而实现安全上下文从调用者线程到被调用者线程的传播
			asyncManager.registerCallableInterceptor(CALLABLE_INTERCEPTOR_KEY, interceptor);
		}
		filterChain.doFilter(request, response);
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

}
