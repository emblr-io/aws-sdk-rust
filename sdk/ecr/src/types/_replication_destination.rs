// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An array of objects representing the destination for a replication rule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReplicationDestination {
    /// <p>The Region to replicate to.</p>
    pub region: ::std::string::String,
    /// <p>The Amazon Web Services account ID of the Amazon ECR private registry to replicate to. When configuring cross-Region replication within your own registry, specify your own account ID.</p>
    pub registry_id: ::std::string::String,
}
impl ReplicationDestination {
    /// <p>The Region to replicate to.</p>
    pub fn region(&self) -> &str {
        use std::ops::Deref;
        self.region.deref()
    }
    /// <p>The Amazon Web Services account ID of the Amazon ECR private registry to replicate to. When configuring cross-Region replication within your own registry, specify your own account ID.</p>
    pub fn registry_id(&self) -> &str {
        use std::ops::Deref;
        self.registry_id.deref()
    }
}
impl ReplicationDestination {
    /// Creates a new builder-style object to manufacture [`ReplicationDestination`](crate::types::ReplicationDestination).
    pub fn builder() -> crate::types::builders::ReplicationDestinationBuilder {
        crate::types::builders::ReplicationDestinationBuilder::default()
    }
}

/// A builder for [`ReplicationDestination`](crate::types::ReplicationDestination).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReplicationDestinationBuilder {
    pub(crate) region: ::std::option::Option<::std::string::String>,
    pub(crate) registry_id: ::std::option::Option<::std::string::String>,
}
impl ReplicationDestinationBuilder {
    /// <p>The Region to replicate to.</p>
    /// This field is required.
    pub fn region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Region to replicate to.</p>
    pub fn set_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.region = input;
        self
    }
    /// <p>The Region to replicate to.</p>
    pub fn get_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.region
    }
    /// <p>The Amazon Web Services account ID of the Amazon ECR private registry to replicate to. When configuring cross-Region replication within your own registry, specify your own account ID.</p>
    /// This field is required.
    pub fn registry_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.registry_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the Amazon ECR private registry to replicate to. When configuring cross-Region replication within your own registry, specify your own account ID.</p>
    pub fn set_registry_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.registry_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the Amazon ECR private registry to replicate to. When configuring cross-Region replication within your own registry, specify your own account ID.</p>
    pub fn get_registry_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.registry_id
    }
    /// Consumes the builder and constructs a [`ReplicationDestination`](crate::types::ReplicationDestination).
    /// This method will fail if any of the following fields are not set:
    /// - [`region`](crate::types::builders::ReplicationDestinationBuilder::region)
    /// - [`registry_id`](crate::types::builders::ReplicationDestinationBuilder::registry_id)
    pub fn build(self) -> ::std::result::Result<crate::types::ReplicationDestination, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ReplicationDestination {
            region: self.region.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "region",
                    "region was not specified but it is required when building ReplicationDestination",
                )
            })?,
            registry_id: self.registry_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "registry_id",
                    "registry_id was not specified but it is required when building ReplicationDestination",
                )
            })?,
        })
    }
}
