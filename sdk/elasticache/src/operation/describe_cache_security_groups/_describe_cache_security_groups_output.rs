// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of a <code>DescribeCacheSecurityGroups</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCacheSecurityGroupsOutput {
    /// <p>Provides an identifier to allow retrieval of paginated results.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>A list of cache security groups. Each element in the list contains detailed information about one group.</p>
    pub cache_security_groups: ::std::option::Option<::std::vec::Vec<crate::types::CacheSecurityGroup>>,
    _request_id: Option<String>,
}
impl DescribeCacheSecurityGroupsOutput {
    /// <p>Provides an identifier to allow retrieval of paginated results.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>A list of cache security groups. Each element in the list contains detailed information about one group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cache_security_groups.is_none()`.
    pub fn cache_security_groups(&self) -> &[crate::types::CacheSecurityGroup] {
        self.cache_security_groups.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeCacheSecurityGroupsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeCacheSecurityGroupsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeCacheSecurityGroupsOutput`](crate::operation::describe_cache_security_groups::DescribeCacheSecurityGroupsOutput).
    pub fn builder() -> crate::operation::describe_cache_security_groups::builders::DescribeCacheSecurityGroupsOutputBuilder {
        crate::operation::describe_cache_security_groups::builders::DescribeCacheSecurityGroupsOutputBuilder::default()
    }
}

/// A builder for [`DescribeCacheSecurityGroupsOutput`](crate::operation::describe_cache_security_groups::DescribeCacheSecurityGroupsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCacheSecurityGroupsOutputBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) cache_security_groups: ::std::option::Option<::std::vec::Vec<crate::types::CacheSecurityGroup>>,
    _request_id: Option<String>,
}
impl DescribeCacheSecurityGroupsOutputBuilder {
    /// <p>Provides an identifier to allow retrieval of paginated results.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides an identifier to allow retrieval of paginated results.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>Provides an identifier to allow retrieval of paginated results.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Appends an item to `cache_security_groups`.
    ///
    /// To override the contents of this collection use [`set_cache_security_groups`](Self::set_cache_security_groups).
    ///
    /// <p>A list of cache security groups. Each element in the list contains detailed information about one group.</p>
    pub fn cache_security_groups(mut self, input: crate::types::CacheSecurityGroup) -> Self {
        let mut v = self.cache_security_groups.unwrap_or_default();
        v.push(input);
        self.cache_security_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of cache security groups. Each element in the list contains detailed information about one group.</p>
    pub fn set_cache_security_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CacheSecurityGroup>>) -> Self {
        self.cache_security_groups = input;
        self
    }
    /// <p>A list of cache security groups. Each element in the list contains detailed information about one group.</p>
    pub fn get_cache_security_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CacheSecurityGroup>> {
        &self.cache_security_groups
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeCacheSecurityGroupsOutput`](crate::operation::describe_cache_security_groups::DescribeCacheSecurityGroupsOutput).
    pub fn build(self) -> crate::operation::describe_cache_security_groups::DescribeCacheSecurityGroupsOutput {
        crate::operation::describe_cache_security_groups::DescribeCacheSecurityGroupsOutput {
            marker: self.marker,
            cache_security_groups: self.cache_security_groups,
            _request_id: self._request_id,
        }
    }
}
