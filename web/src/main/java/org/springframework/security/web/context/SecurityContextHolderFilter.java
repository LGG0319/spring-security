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

package org.springframework.security.web.context;

import java.io.IOException;
import java.util.function.Supplier;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * A {@link jakarta.servlet.Filter} that uses the {@link SecurityContextRepository} to
 * obtain the {@link SecurityContext} and set it on the {@link SecurityContextHolder}.
 * This is similar to {@link SecurityContextPersistenceFilter} except that the
 * {@link SecurityContextRepository#saveContext(SecurityContext, HttpServletRequest, HttpServletResponse)}
 * must be explicitly invoked to save the {@link SecurityContext}. This improves the
 * efficiency and provides better flexibility by allowing different authentication
 * mechanisms to choose individually if authentication should be persisted.
 *
 * @author Rob Winch
 * @author Marcus da Coregio
 * @since 5.7
 * (3) 获取安全上下文，默认程序启动就会加载
 * 该Filter是用于存储用户认证信息的，他有两个重要的属性 SecurityContextRepository 和 securityContextHolderStrategy 。
 * 该过滤器最主要的作用是：
 * 		1.如果请求上下文中存在 SecurityContext 则 SecurityContext存储到securityContextHolderStrategy默认是ThreadLocal
		2.在整个过滤器链执行完成后清除SecurityContext
 * 		3.存储到securityContextHolderStrategy可以保证后续的过滤器都可以从securityContextHolderStrategy中获取到SecurityContext。
 */
public class SecurityContextHolderFilter extends GenericFilterBean {

	private static final String FILTER_APPLIED = SecurityContextHolderFilter.class.getName() + ".APPLIED";

	// SecurityContextRepository接口 提供一种在整个请求上下文存储SecurityContext的能力
	// SecurityContextRepository接口有两个重要方法： loadContext - 获取SecurityContext loadDeferredContext-延期获取SecurityContext saveContext - 保存SecurityContext
	// 该属性默认为 DelegatingSecurityContextRepository，DelegatingSecurityContextRepository也是实现SecurityContextRepository接口的一个代理类
	// DelegatingSecurityContextRepository允许代理多个SecurityContextRepository来实现SecurityContext的存储
	// DelegatingSecurityContextRepository对 loadContext 和 saveContext 实现
	// 默认被代理的SecurityContextRepository为：HttpSessionSecurityContextRepository 和 RequestAttributeSecurityContextRepository
	// 当调用 DelegatingSecurityContextRepository 时，他会遍历被代理的SecurityContextRepository
	// saveContext时：遍历被代理的SecurityContextRepository 都调用saveContext SecurityContext进行存储
	// loadContext时: 调用自身loadDeferredContext 获取SecurityContext
	// loadDeferredContext时：遍历被代理的SecurityContextRepository 调用loadDeferredContext 获取 SecurityContext
	private final SecurityContextRepository securityContextRepository;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	/**
	 * Creates a new instance.
	 * @param securityContextRepository the repository to use. Cannot be null.
	 */
	public SecurityContextHolderFilter(SecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		if (request.getAttribute(FILTER_APPLIED) != null) {
			chain.doFilter(request, response);
			return;
		}
		// 标记改过滤器在本次请求过程中已经执行过
		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
		// 从SecurityContextRepository获取到SecurityContext
		Supplier<SecurityContext> deferredContext = this.securityContextRepository.loadDeferredContext(request);
		try {
			// 将SecurityContext存储到securityContextHolderStrategy中，也就是存储到线程中。
			this.securityContextHolderStrategy.setDeferredContext(deferredContext);
			chain.doFilter(request, response);
		}
		finally {
			// 这时应该 后续所有的Filter都已执行完后，有回到当前Filter中
			// 请求执行完成后，清除SecurityContext
			this.securityContextHolderStrategy.clearContext();
			request.removeAttribute(FILTER_APPLIED);
		}
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
