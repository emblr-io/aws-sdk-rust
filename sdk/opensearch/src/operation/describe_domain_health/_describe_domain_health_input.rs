// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the parameters to the <code>DescribeDomainHealth</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDomainHealthInput {
    /// <p>The name of the domain.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
}
impl DescribeDomainHealthInput {
    /// <p>The name of the domain.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
}
impl DescribeDomainHealthInput {
    /// Creates a new builder-style object to manufacture [`DescribeDomainHealthInput`](crate::operation::describe_domain_health::DescribeDomainHealthInput).
    pub fn builder() -> crate::operation::describe_domain_health::builders::DescribeDomainHealthInputBuilder {
        crate::operation::describe_domain_health::builders::DescribeDomainHealthInputBuilder::default()
    }
}

/// A builder for [`DescribeDomainHealthInput`](crate::operation::describe_domain_health::DescribeDomainHealthInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDomainHealthInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
}
impl DescribeDomainHealthInputBuilder {
    /// <p>The name of the domain.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the domain.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The name of the domain.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// Consumes the builder and constructs a [`DescribeDomainHealthInput`](crate::operation::describe_domain_health::DescribeDomainHealthInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_domain_health::DescribeDomainHealthInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_domain_health::DescribeDomainHealthInput {
            domain_name: self.domain_name,
        })
    }
}
