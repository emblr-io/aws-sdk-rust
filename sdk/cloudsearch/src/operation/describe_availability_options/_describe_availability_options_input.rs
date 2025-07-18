// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the parameters to the <code><code>DescribeAvailabilityOptions</code></code> operation. Specifies the name of the domain you want to describe. To show the active configuration and exclude any pending changes, set the Deployed option to <code>true</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAvailabilityOptionsInput {
    /// <p>The name of the domain you want to describe.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>Whether to display the deployed configuration (<code>true</code>) or include any pending changes (<code>false</code>). Defaults to <code>false</code>.</p>
    pub deployed: ::std::option::Option<bool>,
}
impl DescribeAvailabilityOptionsInput {
    /// <p>The name of the domain you want to describe.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>Whether to display the deployed configuration (<code>true</code>) or include any pending changes (<code>false</code>). Defaults to <code>false</code>.</p>
    pub fn deployed(&self) -> ::std::option::Option<bool> {
        self.deployed
    }
}
impl DescribeAvailabilityOptionsInput {
    /// Creates a new builder-style object to manufacture [`DescribeAvailabilityOptionsInput`](crate::operation::describe_availability_options::DescribeAvailabilityOptionsInput).
    pub fn builder() -> crate::operation::describe_availability_options::builders::DescribeAvailabilityOptionsInputBuilder {
        crate::operation::describe_availability_options::builders::DescribeAvailabilityOptionsInputBuilder::default()
    }
}

/// A builder for [`DescribeAvailabilityOptionsInput`](crate::operation::describe_availability_options::DescribeAvailabilityOptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAvailabilityOptionsInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) deployed: ::std::option::Option<bool>,
}
impl DescribeAvailabilityOptionsInputBuilder {
    /// <p>The name of the domain you want to describe.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the domain you want to describe.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The name of the domain you want to describe.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>Whether to display the deployed configuration (<code>true</code>) or include any pending changes (<code>false</code>). Defaults to <code>false</code>.</p>
    pub fn deployed(mut self, input: bool) -> Self {
        self.deployed = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to display the deployed configuration (<code>true</code>) or include any pending changes (<code>false</code>). Defaults to <code>false</code>.</p>
    pub fn set_deployed(mut self, input: ::std::option::Option<bool>) -> Self {
        self.deployed = input;
        self
    }
    /// <p>Whether to display the deployed configuration (<code>true</code>) or include any pending changes (<code>false</code>). Defaults to <code>false</code>.</p>
    pub fn get_deployed(&self) -> &::std::option::Option<bool> {
        &self.deployed
    }
    /// Consumes the builder and constructs a [`DescribeAvailabilityOptionsInput`](crate::operation::describe_availability_options::DescribeAvailabilityOptionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_availability_options::DescribeAvailabilityOptionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_availability_options::DescribeAvailabilityOptionsInput {
            domain_name: self.domain_name,
            deployed: self.deployed,
        })
    }
}
