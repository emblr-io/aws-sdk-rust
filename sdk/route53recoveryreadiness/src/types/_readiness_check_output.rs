// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A readiness check.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReadinessCheckOutput {
    /// <p>The Amazon Resource Name (ARN) associated with a readiness check.</p>
    pub readiness_check_arn: ::std::option::Option<::std::string::String>,
    /// <p>Name of a readiness check.</p>
    pub readiness_check_name: ::std::option::Option<::std::string::String>,
    /// <p>Name of the resource set to be checked.</p>
    pub resource_set: ::std::option::Option<::std::string::String>,
    /// <p>A collection of tags associated with a resource.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ReadinessCheckOutput {
    /// <p>The Amazon Resource Name (ARN) associated with a readiness check.</p>
    pub fn readiness_check_arn(&self) -> ::std::option::Option<&str> {
        self.readiness_check_arn.as_deref()
    }
    /// <p>Name of a readiness check.</p>
    pub fn readiness_check_name(&self) -> ::std::option::Option<&str> {
        self.readiness_check_name.as_deref()
    }
    /// <p>Name of the resource set to be checked.</p>
    pub fn resource_set(&self) -> ::std::option::Option<&str> {
        self.resource_set.as_deref()
    }
    /// <p>A collection of tags associated with a resource.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ReadinessCheckOutput {
    /// Creates a new builder-style object to manufacture [`ReadinessCheckOutput`](crate::types::ReadinessCheckOutput).
    pub fn builder() -> crate::types::builders::ReadinessCheckOutputBuilder {
        crate::types::builders::ReadinessCheckOutputBuilder::default()
    }
}

/// A builder for [`ReadinessCheckOutput`](crate::types::ReadinessCheckOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReadinessCheckOutputBuilder {
    pub(crate) readiness_check_arn: ::std::option::Option<::std::string::String>,
    pub(crate) readiness_check_name: ::std::option::Option<::std::string::String>,
    pub(crate) resource_set: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ReadinessCheckOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) associated with a readiness check.</p>
    /// This field is required.
    pub fn readiness_check_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.readiness_check_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) associated with a readiness check.</p>
    pub fn set_readiness_check_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.readiness_check_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) associated with a readiness check.</p>
    pub fn get_readiness_check_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.readiness_check_arn
    }
    /// <p>Name of a readiness check.</p>
    pub fn readiness_check_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.readiness_check_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of a readiness check.</p>
    pub fn set_readiness_check_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.readiness_check_name = input;
        self
    }
    /// <p>Name of a readiness check.</p>
    pub fn get_readiness_check_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.readiness_check_name
    }
    /// <p>Name of the resource set to be checked.</p>
    /// This field is required.
    pub fn resource_set(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_set = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the resource set to be checked.</p>
    pub fn set_resource_set(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_set = input;
        self
    }
    /// <p>Name of the resource set to be checked.</p>
    pub fn get_resource_set(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_set
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A collection of tags associated with a resource.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A collection of tags associated with a resource.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A collection of tags associated with a resource.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`ReadinessCheckOutput`](crate::types::ReadinessCheckOutput).
    pub fn build(self) -> crate::types::ReadinessCheckOutput {
        crate::types::ReadinessCheckOutput {
            readiness_check_arn: self.readiness_check_arn,
            readiness_check_name: self.readiness_check_name,
            resource_set: self.resource_set,
            tags: self.tags,
        }
    }
}
