// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the parameters to the <code><code>UpdateAvailabilityOptions</code></code> operation. Specifies the name of the domain you want to update and the Multi-AZ availability option.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAvailabilityOptionsInput {
    /// <p>A string that represents the name of a domain. Domain names are unique across the domains owned by an account within an AWS region. Domain names start with a letter or number and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>You expand an existing search domain to a second Availability Zone by setting the Multi-AZ option to true. Similarly, you can turn off the Multi-AZ option to downgrade the domain to a single Availability Zone by setting the Multi-AZ option to <code>false</code>.</p>
    pub multi_az: ::std::option::Option<bool>,
}
impl UpdateAvailabilityOptionsInput {
    /// <p>A string that represents the name of a domain. Domain names are unique across the domains owned by an account within an AWS region. Domain names start with a letter or number and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>You expand an existing search domain to a second Availability Zone by setting the Multi-AZ option to true. Similarly, you can turn off the Multi-AZ option to downgrade the domain to a single Availability Zone by setting the Multi-AZ option to <code>false</code>.</p>
    pub fn multi_az(&self) -> ::std::option::Option<bool> {
        self.multi_az
    }
}
impl UpdateAvailabilityOptionsInput {
    /// Creates a new builder-style object to manufacture [`UpdateAvailabilityOptionsInput`](crate::operation::update_availability_options::UpdateAvailabilityOptionsInput).
    pub fn builder() -> crate::operation::update_availability_options::builders::UpdateAvailabilityOptionsInputBuilder {
        crate::operation::update_availability_options::builders::UpdateAvailabilityOptionsInputBuilder::default()
    }
}

/// A builder for [`UpdateAvailabilityOptionsInput`](crate::operation::update_availability_options::UpdateAvailabilityOptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAvailabilityOptionsInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) multi_az: ::std::option::Option<bool>,
}
impl UpdateAvailabilityOptionsInputBuilder {
    /// <p>A string that represents the name of a domain. Domain names are unique across the domains owned by an account within an AWS region. Domain names start with a letter or number and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that represents the name of a domain. Domain names are unique across the domains owned by an account within an AWS region. Domain names start with a letter or number and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>A string that represents the name of a domain. Domain names are unique across the domains owned by an account within an AWS region. Domain names start with a letter or number and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>You expand an existing search domain to a second Availability Zone by setting the Multi-AZ option to true. Similarly, you can turn off the Multi-AZ option to downgrade the domain to a single Availability Zone by setting the Multi-AZ option to <code>false</code>.</p>
    /// This field is required.
    pub fn multi_az(mut self, input: bool) -> Self {
        self.multi_az = ::std::option::Option::Some(input);
        self
    }
    /// <p>You expand an existing search domain to a second Availability Zone by setting the Multi-AZ option to true. Similarly, you can turn off the Multi-AZ option to downgrade the domain to a single Availability Zone by setting the Multi-AZ option to <code>false</code>.</p>
    pub fn set_multi_az(mut self, input: ::std::option::Option<bool>) -> Self {
        self.multi_az = input;
        self
    }
    /// <p>You expand an existing search domain to a second Availability Zone by setting the Multi-AZ option to true. Similarly, you can turn off the Multi-AZ option to downgrade the domain to a single Availability Zone by setting the Multi-AZ option to <code>false</code>.</p>
    pub fn get_multi_az(&self) -> &::std::option::Option<bool> {
        &self.multi_az
    }
    /// Consumes the builder and constructs a [`UpdateAvailabilityOptionsInput`](crate::operation::update_availability_options::UpdateAvailabilityOptionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_availability_options::UpdateAvailabilityOptionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_availability_options::UpdateAvailabilityOptionsInput {
            domain_name: self.domain_name,
            multi_az: self.multi_az,
        })
    }
}
