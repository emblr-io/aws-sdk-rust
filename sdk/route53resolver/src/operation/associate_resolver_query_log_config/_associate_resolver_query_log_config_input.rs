// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateResolverQueryLogConfigInput {
    /// <p>The ID of the query logging configuration that you want to associate a VPC with.</p>
    pub resolver_query_log_config_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of an Amazon VPC that you want this query logging configuration to log queries for.</p><note>
    /// <p>The VPCs and the query logging configuration must be in the same Region.</p>
    /// </note>
    pub resource_id: ::std::option::Option<::std::string::String>,
}
impl AssociateResolverQueryLogConfigInput {
    /// <p>The ID of the query logging configuration that you want to associate a VPC with.</p>
    pub fn resolver_query_log_config_id(&self) -> ::std::option::Option<&str> {
        self.resolver_query_log_config_id.as_deref()
    }
    /// <p>The ID of an Amazon VPC that you want this query logging configuration to log queries for.</p><note>
    /// <p>The VPCs and the query logging configuration must be in the same Region.</p>
    /// </note>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
}
impl AssociateResolverQueryLogConfigInput {
    /// Creates a new builder-style object to manufacture [`AssociateResolverQueryLogConfigInput`](crate::operation::associate_resolver_query_log_config::AssociateResolverQueryLogConfigInput).
    pub fn builder() -> crate::operation::associate_resolver_query_log_config::builders::AssociateResolverQueryLogConfigInputBuilder {
        crate::operation::associate_resolver_query_log_config::builders::AssociateResolverQueryLogConfigInputBuilder::default()
    }
}

/// A builder for [`AssociateResolverQueryLogConfigInput`](crate::operation::associate_resolver_query_log_config::AssociateResolverQueryLogConfigInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateResolverQueryLogConfigInputBuilder {
    pub(crate) resolver_query_log_config_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
}
impl AssociateResolverQueryLogConfigInputBuilder {
    /// <p>The ID of the query logging configuration that you want to associate a VPC with.</p>
    /// This field is required.
    pub fn resolver_query_log_config_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resolver_query_log_config_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the query logging configuration that you want to associate a VPC with.</p>
    pub fn set_resolver_query_log_config_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resolver_query_log_config_id = input;
        self
    }
    /// <p>The ID of the query logging configuration that you want to associate a VPC with.</p>
    pub fn get_resolver_query_log_config_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resolver_query_log_config_id
    }
    /// <p>The ID of an Amazon VPC that you want this query logging configuration to log queries for.</p><note>
    /// <p>The VPCs and the query logging configuration must be in the same Region.</p>
    /// </note>
    /// This field is required.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of an Amazon VPC that you want this query logging configuration to log queries for.</p><note>
    /// <p>The VPCs and the query logging configuration must be in the same Region.</p>
    /// </note>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The ID of an Amazon VPC that you want this query logging configuration to log queries for.</p><note>
    /// <p>The VPCs and the query logging configuration must be in the same Region.</p>
    /// </note>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// Consumes the builder and constructs a [`AssociateResolverQueryLogConfigInput`](crate::operation::associate_resolver_query_log_config::AssociateResolverQueryLogConfigInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::associate_resolver_query_log_config::AssociateResolverQueryLogConfigInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::associate_resolver_query_log_config::AssociateResolverQueryLogConfigInput {
                resolver_query_log_config_id: self.resolver_query_log_config_id,
                resource_id: self.resource_id,
            },
        )
    }
}
