// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>List entry for one run cache.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RunCacheListItem {
    /// <p>Unique resource identifier for the run cache.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>Default cache behavior for the run cache.</p>
    pub cache_behavior: ::std::option::Option<crate::types::CacheBehavior>,
    /// <p>The S3 uri for the run cache data.</p>
    pub cache_s3_uri: ::std::option::Option<::std::string::String>,
    /// <p>The time that this run cache was created (an ISO 8601 formatted string).</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The identifier for this run cache.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the run cache.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The run cache status.</p>
    pub status: ::std::option::Option<crate::types::RunCacheStatus>,
}
impl RunCacheListItem {
    /// <p>Unique resource identifier for the run cache.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>Default cache behavior for the run cache.</p>
    pub fn cache_behavior(&self) -> ::std::option::Option<&crate::types::CacheBehavior> {
        self.cache_behavior.as_ref()
    }
    /// <p>The S3 uri for the run cache data.</p>
    pub fn cache_s3_uri(&self) -> ::std::option::Option<&str> {
        self.cache_s3_uri.as_deref()
    }
    /// <p>The time that this run cache was created (an ISO 8601 formatted string).</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The identifier for this run cache.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The name of the run cache.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The run cache status.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::RunCacheStatus> {
        self.status.as_ref()
    }
}
impl RunCacheListItem {
    /// Creates a new builder-style object to manufacture [`RunCacheListItem`](crate::types::RunCacheListItem).
    pub fn builder() -> crate::types::builders::RunCacheListItemBuilder {
        crate::types::builders::RunCacheListItemBuilder::default()
    }
}

/// A builder for [`RunCacheListItem`](crate::types::RunCacheListItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RunCacheListItemBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) cache_behavior: ::std::option::Option<crate::types::CacheBehavior>,
    pub(crate) cache_s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::RunCacheStatus>,
}
impl RunCacheListItemBuilder {
    /// <p>Unique resource identifier for the run cache.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique resource identifier for the run cache.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>Unique resource identifier for the run cache.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>Default cache behavior for the run cache.</p>
    pub fn cache_behavior(mut self, input: crate::types::CacheBehavior) -> Self {
        self.cache_behavior = ::std::option::Option::Some(input);
        self
    }
    /// <p>Default cache behavior for the run cache.</p>
    pub fn set_cache_behavior(mut self, input: ::std::option::Option<crate::types::CacheBehavior>) -> Self {
        self.cache_behavior = input;
        self
    }
    /// <p>Default cache behavior for the run cache.</p>
    pub fn get_cache_behavior(&self) -> &::std::option::Option<crate::types::CacheBehavior> {
        &self.cache_behavior
    }
    /// <p>The S3 uri for the run cache data.</p>
    pub fn cache_s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cache_s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The S3 uri for the run cache data.</p>
    pub fn set_cache_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cache_s3_uri = input;
        self
    }
    /// <p>The S3 uri for the run cache data.</p>
    pub fn get_cache_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.cache_s3_uri
    }
    /// <p>The time that this run cache was created (an ISO 8601 formatted string).</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that this run cache was created (an ISO 8601 formatted string).</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time that this run cache was created (an ISO 8601 formatted string).</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The identifier for this run cache.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for this run cache.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier for this run cache.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the run cache.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the run cache.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the run cache.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The run cache status.</p>
    pub fn status(mut self, input: crate::types::RunCacheStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The run cache status.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::RunCacheStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The run cache status.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::RunCacheStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`RunCacheListItem`](crate::types::RunCacheListItem).
    pub fn build(self) -> crate::types::RunCacheListItem {
        crate::types::RunCacheListItem {
            arn: self.arn,
            cache_behavior: self.cache_behavior,
            cache_s3_uri: self.cache_s3_uri,
            creation_time: self.creation_time,
            id: self.id,
            name: self.name,
            status: self.status,
        }
    }
}
