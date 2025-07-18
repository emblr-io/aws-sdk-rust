// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the parameters to the <code><code>DescribeDomains</code></code> operation. By default shows the status of all domains. To restrict the response to particular domains, specify the names of the domains you want to describe.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDomainsInput {
    /// <p>The names of the domains you want to include in the response.</p>
    pub domain_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeDomainsInput {
    /// <p>The names of the domains you want to include in the response.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.domain_names.is_none()`.
    pub fn domain_names(&self) -> &[::std::string::String] {
        self.domain_names.as_deref().unwrap_or_default()
    }
}
impl DescribeDomainsInput {
    /// Creates a new builder-style object to manufacture [`DescribeDomainsInput`](crate::operation::describe_domains::DescribeDomainsInput).
    pub fn builder() -> crate::operation::describe_domains::builders::DescribeDomainsInputBuilder {
        crate::operation::describe_domains::builders::DescribeDomainsInputBuilder::default()
    }
}

/// A builder for [`DescribeDomainsInput`](crate::operation::describe_domains::DescribeDomainsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDomainsInputBuilder {
    pub(crate) domain_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeDomainsInputBuilder {
    /// Appends an item to `domain_names`.
    ///
    /// To override the contents of this collection use [`set_domain_names`](Self::set_domain_names).
    ///
    /// <p>The names of the domains you want to include in the response.</p>
    pub fn domain_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.domain_names.unwrap_or_default();
        v.push(input.into());
        self.domain_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The names of the domains you want to include in the response.</p>
    pub fn set_domain_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.domain_names = input;
        self
    }
    /// <p>The names of the domains you want to include in the response.</p>
    pub fn get_domain_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.domain_names
    }
    /// Consumes the builder and constructs a [`DescribeDomainsInput`](crate::operation::describe_domains::DescribeDomainsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_domains::DescribeDomainsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_domains::DescribeDomainsInput {
            domain_names: self.domain_names,
        })
    }
}
