// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PushDomainInput {
    /// <p>Name of the domain.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>New IPS tag for the domain.</p>
    pub target: ::std::option::Option<::std::string::String>,
}
impl PushDomainInput {
    /// <p>Name of the domain.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>New IPS tag for the domain.</p>
    pub fn target(&self) -> ::std::option::Option<&str> {
        self.target.as_deref()
    }
}
impl PushDomainInput {
    /// Creates a new builder-style object to manufacture [`PushDomainInput`](crate::operation::push_domain::PushDomainInput).
    pub fn builder() -> crate::operation::push_domain::builders::PushDomainInputBuilder {
        crate::operation::push_domain::builders::PushDomainInputBuilder::default()
    }
}

/// A builder for [`PushDomainInput`](crate::operation::push_domain::PushDomainInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PushDomainInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) target: ::std::option::Option<::std::string::String>,
}
impl PushDomainInputBuilder {
    /// <p>Name of the domain.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the domain.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>Name of the domain.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>New IPS tag for the domain.</p>
    /// This field is required.
    pub fn target(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>New IPS tag for the domain.</p>
    pub fn set_target(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target = input;
        self
    }
    /// <p>New IPS tag for the domain.</p>
    pub fn get_target(&self) -> &::std::option::Option<::std::string::String> {
        &self.target
    }
    /// Consumes the builder and constructs a [`PushDomainInput`](crate::operation::push_domain::PushDomainInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::push_domain::PushDomainInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::push_domain::PushDomainInput {
            domain_name: self.domain_name,
            target: self.target,
        })
    }
}
