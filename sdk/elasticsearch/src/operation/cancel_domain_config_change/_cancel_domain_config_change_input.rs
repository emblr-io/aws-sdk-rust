// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for parameters of the <code>CancelDomainConfigChange</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelDomainConfigChangeInput {
    /// <p>Name of the OpenSearch Service domain configuration request to cancel.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>When set to <b>True</b>, returns the list of change IDs and properties that will be cancelled without actually cancelling the change.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl CancelDomainConfigChangeInput {
    /// <p>Name of the OpenSearch Service domain configuration request to cancel.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>When set to <b>True</b>, returns the list of change IDs and properties that will be cancelled without actually cancelling the change.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl CancelDomainConfigChangeInput {
    /// Creates a new builder-style object to manufacture [`CancelDomainConfigChangeInput`](crate::operation::cancel_domain_config_change::CancelDomainConfigChangeInput).
    pub fn builder() -> crate::operation::cancel_domain_config_change::builders::CancelDomainConfigChangeInputBuilder {
        crate::operation::cancel_domain_config_change::builders::CancelDomainConfigChangeInputBuilder::default()
    }
}

/// A builder for [`CancelDomainConfigChangeInput`](crate::operation::cancel_domain_config_change::CancelDomainConfigChangeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelDomainConfigChangeInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl CancelDomainConfigChangeInputBuilder {
    /// <p>Name of the OpenSearch Service domain configuration request to cancel.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the OpenSearch Service domain configuration request to cancel.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>Name of the OpenSearch Service domain configuration request to cancel.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>When set to <b>True</b>, returns the list of change IDs and properties that will be cancelled without actually cancelling the change.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>When set to <b>True</b>, returns the list of change IDs and properties that will be cancelled without actually cancelling the change.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>When set to <b>True</b>, returns the list of change IDs and properties that will be cancelled without actually cancelling the change.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Consumes the builder and constructs a [`CancelDomainConfigChangeInput`](crate::operation::cancel_domain_config_change::CancelDomainConfigChangeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::cancel_domain_config_change::CancelDomainConfigChangeInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::cancel_domain_config_change::CancelDomainConfigChangeInput {
            domain_name: self.domain_name,
            dry_run: self.dry_run,
        })
    }
}
