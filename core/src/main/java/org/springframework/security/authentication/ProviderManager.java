/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.authentication;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * Iterates an {@link Authentication} request through a list of
 * {@link AuthenticationProvider}s.
 *
 * <p>
 * <tt>AuthenticationProvider</tt>s are usually tried in order until one provides a
 * non-null response. A non-null response indicates the provider had authority to decide
 * on the authentication request and no further providers are tried. If a subsequent
 * provider successfully authenticates the request, the earlier authentication exception
 * is disregarded and the successful authentication will be used. If no subsequent
 * provider provides a non-null response, or a new <code>AuthenticationException</code>,
 * the last <code>AuthenticationException</code> received will be used. If no provider
 * returns a non-null response, or indicates it can even process an
 * <code>Authentication</code>, the <code>ProviderManager</code> will throw a
 * <code>ProviderNotFoundException</code>. A parent {@code AuthenticationManager} can also
 * be set, and this will also be tried if none of the configured providers can perform the
 * authentication. This is intended to support namespace configuration options though and
 * is not a feature that should normally be required.
 * <p>
 * The exception to this process is when a provider throws an
 * {@link AccountStatusException}, in which case no further providers in the list will be
 * queried.
 *
 * Post-authentication, the credentials will be cleared from the returned
 * {@code Authentication} object, if it implements the {@link CredentialsContainer}
 * interface. This behaviour can be controlled by modifying the
 * {@link #setEraseCredentialsAfterAuthentication(boolean)
 * eraseCredentialsAfterAuthentication} property.
 *
 * <h2>Event Publishing</h2>
 * <p>
 * Authentication event publishing is delegated to the configured
 * {@link AuthenticationEventPublisher} which defaults to a null implementation which
 * doesn't publish events, so if you are configuring the bean yourself you must inject a
 * publisher bean if you want to receive events. The standard implementation is
 * {@link DefaultAuthenticationEventPublisher} which maps common exceptions to events (in
 * the case of authentication failure) and publishes an
 * {@link org.springframework.security.authentication.event.AuthenticationSuccessEvent
 * AuthenticationSuccessEvent} if authentication succeeds. If you are using the namespace
 * then an instance of this bean will be used automatically by the <tt>&lt;http&gt;</tt>
 * configuration, so you will receive events from the web part of your application
 * automatically.
 * <p>
 * Note that the implementation also publishes authentication failure events when it
 * obtains an authentication result (or an exception) from the "parent"
 * {@code AuthenticationManager} if one has been set. So in this situation, the parent
 * should not generally be configured to publish events or there will be duplicates.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @see DefaultAuthenticationEventPublisher
 * 1.Spring Security提供的AuthenticationManager实现。其主要目的，也就是实现AuthenticationManager接口所定义的方法
 * 2.ProviderManager 使用一组AuthenticationProvider,也可以再附加一个双亲认证管理器AuthenticationManager来完成对一个认证请求，
 * 	也就是一个认证令牌对象authentication的认证。
 * 3.ProviderManager的认证过程也会发布相应的认证成功/异常事件
 * 4.ProviderManager的认证逻辑会遍历所有支持该认证令牌对象参数 authentication （基于类型进行匹配）的 AuthenticationProvider，
 * 	找到第一个能成功认证的并返回填充更多信息的authentication 对象：
 */
public class ProviderManager implements AuthenticationManager, MessageSourceAware, InitializingBean {

	private static final Log logger = LogFactory.getLog(ProviderManager.class);

	// 认证事件发布器，这里缺省初始化为 NullEventPublisher,表示不做认证事件的发布
	private AuthenticationEventPublisher eventPublisher = new NullEventPublisher();

	// 用于记录所要使用的各个 AuthenticationProvider， 当前 ProviderManager 的认证
	// 任务最终委托给这组 AuthenticationProvider 完成
	private List<AuthenticationProvider> providers = Collections.emptyList();

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	// 双亲认证管理器，可以设置，也可以不设置，设置的话会在当前认证管理器 ProviderManager
	// 不能认证某个用户时再尝试使用该双亲认证管理器认证用户
	private AuthenticationManager parent;

	// 认证成功时是否擦除认证令牌对象中的凭证信息(比如密码)，缺省值为 true
	private boolean eraseCredentialsAfterAuthentication = true;

	/**
	 * Construct a {@link ProviderManager} using the given {@link AuthenticationProvider}s
	 * @param providers the {@link AuthenticationProvider}s to use
	 */
	public ProviderManager(AuthenticationProvider... providers) {
		this(Arrays.asList(providers), null);
	}

	/**
	 * Construct a {@link ProviderManager} using the given {@link AuthenticationProvider}s
	 * @param providers the {@link AuthenticationProvider}s to use
	 * 构造函数，指定一组要使用的 AuthenticationProvider，并且双亲认证管理器设置为 null
	 */
	public ProviderManager(List<AuthenticationProvider> providers) {
		this(providers, null);
	}

	/**
	 * Construct a {@link ProviderManager} using the provided parameters
	 * @param providers the {@link AuthenticationProvider}s to use
	 * @param parent a parent {@link AuthenticationManager} to fall back to
	 * 构造函数，指定一组要使用的 AuthenticationProvider，并且双亲认证管理器设置为指定值
	 */
	public ProviderManager(List<AuthenticationProvider> providers, AuthenticationManager parent) {
		Assert.notNull(providers, "providers list cannot be null");
		this.providers = providers;
		this.parent = parent;
		checkState();
	}

	// InitializingBean 接口定义的bean初始化方法，会在该bean创建过程中初始化阶段被调用，
	// 这里的实现仅仅检查必要的工作组件是否被设置，如果没有被设置，则抛出异常
	// IllegalArgumentException
	@Override
	public void afterPropertiesSet() {
		checkState();
	}

	private void checkState() {
		Assert.isTrue(this.parent != null || !this.providers.isEmpty(),
				"A parent AuthenticationManager or a list of AuthenticationProviders is required");
		Assert.isTrue(!CollectionUtils.contains(this.providers.iterator(), null),
				"providers list cannot contain null values");
	}

	/**
	 * Attempts to authenticate the passed {@link Authentication} object.
	 * <p>
	 * The list of {@link AuthenticationProvider}s will be successively tried until an
	 * <code>AuthenticationProvider</code> indicates it is capable of authenticating the
	 * type of <code>Authentication</code> object passed. Authentication will then be
	 * attempted with that <code>AuthenticationProvider</code>.
	 * <p>
	 * If more than one <code>AuthenticationProvider</code> supports the passed
	 * <code>Authentication</code> object, the first one able to successfully authenticate
	 * the <code>Authentication</code> object determines the <code>result</code>,
	 * overriding any possible <code>AuthenticationException</code> thrown by earlier
	 * supporting <code>AuthenticationProvider</code>s. On successful authentication, no
	 * subsequent <code>AuthenticationProvider</code>s will be tried. If authentication
	 * was not successful by any supporting <code>AuthenticationProvider</code> the last
	 * thrown <code>AuthenticationException</code> will be rethrown.
	 * @param authentication the authentication request object.
	 * @return a fully authenticated object including credentials.
	 * @throws AuthenticationException if authentication fails.
	 * 1.尝试对认证请求对象，也就是认证令牌对象参数 authentication 进行认证
	 * 2.该方法的逻辑会遍历所有支持该认证令牌对象参数 authentication （基于类型进行匹配）
	 *  的 AuthenticationProvider，找到第一个能成功认证的并返回填充更多信息的authentication 对象：
	 * 3. 如果某个 AuthenticationProvider 宣称可以认证该 authentication，但是认证过程抛出异常 AuthenticationException，则整个认证过程不会停止,
	 *  而是尝试使用下一个 AuthenticationProvider 继续,知道认证成功，或者执行完所有的AuthenticationProvider。
	 * 4.认证成功时，该方法也会调用 eventPublisher 发布认证成功事件。
	 * 5.认证异常时，该方法回调用 eventPublisher 发布相应的认证异常事件。
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// 获取当前的Authentication的认证类型
		Class<? extends Authentication> toTest = authentication.getClass();
		AuthenticationException lastException = null;
		AuthenticationException parentException = null;
		Authentication result = null;
		Authentication parentResult = null;
		int currentPosition = 0;
		int size = this.providers.size();
		// 遍历所有的providers
		for (AuthenticationProvider provider : getProviders()) {
			// 判断该provider是否支持当前的认证类型。不支持，遍历下一个
			if (!provider.supports(toTest)) {
				continue;
			}
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Authenticating request with %s (%d/%d)",
						provider.getClass().getSimpleName(), ++currentPosition, size));
			}
			try {
				// 调用provider的authenticat方法认证
				result = provider.authenticate(authentication);
				if (result != null) {
					// 认证通过的话，将认证结果的details赋值到当前认证对象authentication。然后跳出循环
					copyDetails(authentication, result);
					break;
				}
			}
			catch (AccountStatusException ex) {
				prepareException(ex, authentication);
				logger.debug(LogMessage.format("Authentication failed for user '%s' since their account status is %s",
						authentication.getName(), ex.getMessage()), ex);
				// SEC-546: Avoid polling additional providers if auth failure is due to
				// invalid account status
				throw ex;
			}
			catch (InternalAuthenticationServiceException ex) {
				prepareException(ex, authentication);
				logger.debug(LogMessage.format("Authentication service failed internally for user '%s'",
						authentication.getName()), ex);
				// SEC-546: Avoid polling additional providers if auth failure is due to
				// invalid account status
				throw ex;
			}
			catch (AuthenticationException ex) {
				logger.debug(LogMessage.format("Authentication failed with provider %s since %s",
						provider.getClass().getSimpleName(), ex.getMessage()));
				lastException = ex;
			}
		}
		// 双亲认证管理器不为空的话继续使用认证
		if (result == null && this.parent != null) {
			// Allow the parent to try.
			try {
				parentResult = this.parent.authenticate(authentication);
				result = parentResult;
			}
			catch (ProviderNotFoundException ex) {
				// ignore as we will throw below if no other exception occurred prior to
				// calling parent and the parent
				// may throw ProviderNotFound even though a provider in the child already
				// handled the request
			}
			catch (AuthenticationException ex) {
				parentException = ex;
				lastException = ex;
			}
		}
		if (result != null) {
			if (this.eraseCredentialsAfterAuthentication && (result instanceof CredentialsContainer)) {
				// Authentication is complete. Remove credentials and other secret data
				// from authentication
				((CredentialsContainer) result).eraseCredentials();
			}
			// If the parent AuthenticationManager was attempted and successful then it
			// will publish an AuthenticationSuccessEvent
			// This check prevents a duplicate AuthenticationSuccessEvent if the parent
			// AuthenticationManager already published it
			if (parentResult == null) {
				this.eventPublisher.publishAuthenticationSuccess(result);
			}

			return result;
		}

		// Parent was null, or didn't authenticate (or throw an exception).
		if (lastException == null) {
			lastException = new ProviderNotFoundException(this.messages.getMessage("ProviderManager.providerNotFound",
					new Object[] { toTest.getName() }, "No AuthenticationProvider found for {0}"));
		}
		// If the parent AuthenticationManager was attempted and failed then it will
		// publish an AbstractAuthenticationFailureEvent
		// This check prevents a duplicate AbstractAuthenticationFailureEvent if the
		// parent AuthenticationManager already published it
		if (parentException == null) {
			prepareException(lastException, authentication);
		}

		// Ensure this message is not logged when authentication is attempted by
		// the parent provider
		if (this.parent != null) {
			logger.debug("Denying authentication since all attempted providers failed");
		}

		throw lastException;
	}

	// 发布认证异常事件
	@SuppressWarnings("deprecation")
	private void prepareException(AuthenticationException ex, Authentication auth) {
		this.eventPublisher.publishAuthenticationFailure(ex, auth);
	}

	/**
	 * Copies the authentication details from a source Authentication object to a
	 * destination one, provided the latter does not already have one set.
	 * @param source source authentication
	 * @param dest the destination authentication object
	 */
	private void copyDetails(Authentication source, Authentication dest) {
		if ((dest instanceof AbstractAuthenticationToken token) && (dest.getDetails() == null)) {
			token.setDetails(source.getDetails());
		}
	}

	public List<AuthenticationProvider> getProviders() {
		return this.providers;
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	// 指定事件发布器，用于覆盖缺省的 NullEventPublisher
	public void setAuthenticationEventPublisher(AuthenticationEventPublisher eventPublisher) {
		Assert.notNull(eventPublisher, "AuthenticationEventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
	}

	/**
	 * If set to, a resulting {@code Authentication} which implements the
	 * {@code CredentialsContainer} interface will have its
	 * {@link CredentialsContainer#eraseCredentials() eraseCredentials} method called
	 * before it is returned from the {@code authenticate()} method.
	 * @param eraseSecretData set to {@literal false} to retain the credentials data in
	 * memory. Defaults to {@literal true}.
	 */
	public void setEraseCredentialsAfterAuthentication(boolean eraseSecretData) {
		this.eraseCredentialsAfterAuthentication = eraseSecretData;
	}

	public boolean isEraseCredentialsAfterAuthentication() {
		return this.eraseCredentialsAfterAuthentication;
	}

	// 这是一个缺省使用的认证事件发布器实现类，实际上并不发布任何认证事件，只是为了避免
	// ProviderManager 的属性 eventPublisher 为 null
	private static final class NullEventPublisher implements AuthenticationEventPublisher {

		@Override
		public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
		}

		@Override
		public void publishAuthenticationSuccess(Authentication authentication) {
		}

	}

}
