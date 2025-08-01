// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of a <code>CreateCacheParameterGroup</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CacheParameterGroup {
    /// <p>The name of the cache parameter group.</p>
    pub cache_parameter_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the cache parameter group family that this cache parameter group is compatible with.</p>
    /// <p>Valid values are: <code>memcached1.4</code> | <code>memcached1.5</code> | <code>memcached1.6</code> | <code>redis2.6</code> | <code>redis2.8</code> | <code>redis3.2</code> | <code>redis4.0</code> | <code>redis5.0</code> | <code>redis6.x</code> | <code>redis7</code></p>
    pub cache_parameter_group_family: ::std::option::Option<::std::string::String>,
    /// <p>The description for this cache parameter group.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether the parameter group is associated with a Global datastore</p>
    pub is_global: ::std::option::Option<bool>,
    /// <p>The ARN (Amazon Resource Name) of the cache parameter group.</p>
    pub arn: ::std::option::Option<::std::string::String>,
}
impl CacheParameterGroup {
    /// <p>The name of the cache parameter group.</p>
    pub fn cache_parameter_group_name(&self) -> ::std::option::Option<&str> {
        self.cache_parameter_group_name.as_deref()
    }
    /// <p>The name of the cache parameter group family that this cache parameter group is compatible with.</p>
    /// <p>Valid values are: <code>memcached1.4</code> | <code>memcached1.5</code> | <code>memcached1.6</code> | <code>redis2.6</code> | <code>redis2.8</code> | <code>redis3.2</code> | <code>redis4.0</code> | <code>redis5.0</code> | <code>redis6.x</code> | <code>redis7</code></p>
    pub fn cache_parameter_group_family(&self) -> ::std::option::Option<&str> {
        self.cache_parameter_group_family.as_deref()
    }
    /// <p>The description for this cache parameter group.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Indicates whether the parameter group is associated with a Global datastore</p>
    pub fn is_global(&self) -> ::std::option::Option<bool> {
        self.is_global
    }
    /// <p>The ARN (Amazon Resource Name) of the cache parameter group.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl CacheParameterGroup {
    /// Creates a new builder-style object to manufacture [`CacheParameterGroup`](crate::types::CacheParameterGroup).
    pub fn builder() -> crate::types::builders::CacheParameterGroupBuilder {
        crate::types::builders::CacheParameterGroupBuilder::default()
    }
}

/// A builder for [`CacheParameterGroup`](crate::types::CacheParameterGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CacheParameterGroupBuilder {
    pub(crate) cache_parameter_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) cache_parameter_group_family: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) is_global: ::std::option::Option<bool>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
}
impl CacheParameterGroupBuilder {
    /// <p>The name of the cache parameter group.</p>
    pub fn cache_parameter_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cache_parameter_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cache parameter group.</p>
    pub fn set_cache_parameter_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cache_parameter_group_name = input;
        self
    }
    /// <p>The name of the cache parameter group.</p>
    pub fn get_cache_parameter_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cache_parameter_group_name
    }
    /// <p>The name of the cache parameter group family that this cache parameter group is compatible with.</p>
    /// <p>Valid values are: <code>memcached1.4</code> | <code>memcached1.5</code> | <code>memcached1.6</code> | <code>redis2.6</code> | <code>redis2.8</code> | <code>redis3.2</code> | <code>redis4.0</code> | <code>redis5.0</code> | <code>redis6.x</code> | <code>redis7</code></p>
    pub fn cache_parameter_group_family(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cache_parameter_group_family = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cache parameter group family that this cache parameter group is compatible with.</p>
    /// <p>Valid values are: <code>memcached1.4</code> | <code>memcached1.5</code> | <code>memcached1.6</code> | <code>redis2.6</code> | <code>redis2.8</code> | <code>redis3.2</code> | <code>redis4.0</code> | <code>redis5.0</code> | <code>redis6.x</code> | <code>redis7</code></p>
    pub fn set_cache_parameter_group_family(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cache_parameter_group_family = input;
        self
    }
    /// <p>The name of the cache parameter group family that this cache parameter group is compatible with.</p>
    /// <p>Valid values are: <code>memcached1.4</code> | <code>memcached1.5</code> | <code>memcached1.6</code> | <code>redis2.6</code> | <code>redis2.8</code> | <code>redis3.2</code> | <code>redis4.0</code> | <code>redis5.0</code> | <code>redis6.x</code> | <code>redis7</code></p>
    pub fn get_cache_parameter_group_family(&self) -> &::std::option::Option<::std::string::String> {
        &self.cache_parameter_group_family
    }
    /// <p>The description for this cache parameter group.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description for this cache parameter group.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description for this cache parameter group.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Indicates whether the parameter group is associated with a Global datastore</p>
    pub fn is_global(mut self, input: bool) -> Self {
        self.is_global = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the parameter group is associated with a Global datastore</p>
    pub fn set_is_global(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_global = input;
        self
    }
    /// <p>Indicates whether the parameter group is associated with a Global datastore</p>
    pub fn get_is_global(&self) -> &::std::option::Option<bool> {
        &self.is_global
    }
    /// <p>The ARN (Amazon Resource Name) of the cache parameter group.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN (Amazon Resource Name) of the cache parameter group.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN (Amazon Resource Name) of the cache parameter group.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Consumes the builder and constructs a [`CacheParameterGroup`](crate::types::CacheParameterGroup).
    pub fn build(self) -> crate::types::CacheParameterGroup {
        crate::types::CacheParameterGroup {
            cache_parameter_group_name: self.cache_parameter_group_name,
            cache_parameter_group_family: self.cache_parameter_group_family,
            description: self.description,
            is_global: self.is_global,
            arn: self.arn,
        }
    }
}
