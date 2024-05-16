/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation;

import java.util.ArrayList;
import java.util.List;

import org.springframework.core.GenericTypeResolver;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.util.Assert;

/**
 * A base class for {@link SecurityConfigurer} that allows subclasses to only implement
 * the methods they are interested in. It also provides a mechanism for using the
 * {@link SecurityConfigurer} and when done gaining access to the {@link SecurityBuilder}
 * that is being configured.
 *
 * @param <O> The Object being built by B
 * @param <B> The Builder that is building O and is configured by
 * {@link SecurityConfigurerAdapter}
 * @author Rob Winch
 * @author Wallace Wadge
 * SecurityConfigurer 的适配器类，它允许子类只实现他们感兴趣的方法。同时它的 and()方法也提供了一种获得对正在配置的 SecurityBuilder 的引用的机制。
 */
public abstract class SecurityConfigurerAdapter<O, B extends SecurityBuilder<O>> implements SecurityConfigurer<O, B> {

	private B securityBuilder;

	private CompositeObjectPostProcessor objectPostProcessor = new CompositeObjectPostProcessor();

	@Override
	public void init(B builder) throws Exception {
	}

	@Override
	public void configure(B builder) throws Exception {
	}

	/**
	 * Return the {@link SecurityBuilder} when done using the {@link SecurityConfigurer}.
	 * This is useful for method chaining.
	 * @return the {@link SecurityBuilder} for further customizations
	 * @deprecated For removal in 7.0. Use the lambda based configuration instead.
	 * 使用完 SecurityConfigurer 之后获取 SecurityBuilder 引用。这在链式调用方法时非常有用
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public B and() {
		return getBuilder();
	}

	/**
	 * Gets the {@link SecurityBuilder}. Cannot be null.
	 * @return the {@link SecurityBuilder}
	 * @throws IllegalStateException if {@link SecurityBuilder} is null
	 * 获取 SecurityBuilder 对象引用。不能为 null。
	 */
	protected final B getBuilder() {
		Assert.state(this.securityBuilder != null, "securityBuilder cannot be null");
		return this.securityBuilder;
	}

	/**
	 * Performs post processing of an object. The default is to delegate to the
	 * {@link ObjectPostProcessor}.
	 * @param object the Object to post process
	 * @return the possibly modified Object to use
	 * 执行对象的后置处理。默认是代理给 objectPostProcessor 对象
	 */
	@SuppressWarnings("unchecked")
	protected <T> T postProcess(T object) {
		return (T) this.objectPostProcessor.postProcess(object);
	}

	/**
	 * Adds an {@link ObjectPostProcessor} to be used for this
	 * {@link SecurityConfigurerAdapter}. The default implementation does nothing to the
	 * object.
	 * @param objectPostProcessor the {@link ObjectPostProcessor} to use
	 * 添加此对象（SecurityConfigurerAdapter）的一个后置处理器 ObjectPostProcessor 对象。默认不做任何事情
	 */
	public void addObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
		this.objectPostProcessor.addObjectPostProcessor(objectPostProcessor);
	}

	/**
	 * Sets the {@link SecurityBuilder} to be used. This is automatically set when using
	 * {@link AbstractConfiguredSecurityBuilder#apply(SecurityConfigurerAdapter)}
	 * @param builder the {@link SecurityBuilder} to set
	 * 给对象装配将要使用的 SecurityBuilder。这个过程是在调用 AbstractConfiguredSecurityBuilder#apply(SecurityConfigurerAdapter) 方法时自动执行。
	 */
	public void setBuilder(B builder) {
		this.securityBuilder = builder;
	}

	/**
	 * An {@link ObjectPostProcessor} that delegates work to numerous
	 * {@link ObjectPostProcessor} implementations.
	 *
	 * @author Rob Winch
	 * 一个代理多个 ObjectPostProcessor 实现对象的 ObjectPostProcessor 代理类
	 */
	private static final class CompositeObjectPostProcessor implements ObjectPostProcessor<Object> {

		private List<ObjectPostProcessor<?>> postProcessors = new ArrayList<>();

		@Override
		@SuppressWarnings({ "rawtypes", "unchecked" })
		public Object postProcess(Object object) {
			for (ObjectPostProcessor opp : this.postProcessors) {
				Class<?> oppClass = opp.getClass();
				Class<?> oppType = GenericTypeResolver.resolveTypeArgument(oppClass, ObjectPostProcessor.class);
				if (oppType == null || oppType.isAssignableFrom(object.getClass())) {
					object = opp.postProcess(object);
				}
			}
			return object;
		}

		/**
		 * Adds an {@link ObjectPostProcessor} to use
		 * @param objectPostProcessor the {@link ObjectPostProcessor} to add
		 * @return true if the {@link ObjectPostProcessor} was added, else false
		 * 添加一个 ObjectPostProcessor 的实现类对象
		 */
		private boolean addObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
			boolean result = this.postProcessors.add(objectPostProcessor);
			this.postProcessors.sort(AnnotationAwareOrderComparator.INSTANCE);
			return result;
		}

	}

}
