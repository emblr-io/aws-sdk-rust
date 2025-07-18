// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An Active Directory Domain membership record associated with a DB instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DomainMembership {
    /// <p>The identifier of the Active Directory Domain.</p>
    pub domain: ::std::option::Option<::std::string::String>,
    /// <p>The status of the DB instance's Active Directory Domain membership, such as joined, pending-join, failed etc).</p>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>The fully qualified domain name of the Active Directory Domain.</p>
    pub fqdn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the IAM role to be used when making API calls to the Directory Service.</p>
    pub iam_role_name: ::std::option::Option<::std::string::String>,
}
impl DomainMembership {
    /// <p>The identifier of the Active Directory Domain.</p>
    pub fn domain(&self) -> ::std::option::Option<&str> {
        self.domain.as_deref()
    }
    /// <p>The status of the DB instance's Active Directory Domain membership, such as joined, pending-join, failed etc).</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>The fully qualified domain name of the Active Directory Domain.</p>
    pub fn fqdn(&self) -> ::std::option::Option<&str> {
        self.fqdn.as_deref()
    }
    /// <p>The name of the IAM role to be used when making API calls to the Directory Service.</p>
    pub fn iam_role_name(&self) -> ::std::option::Option<&str> {
        self.iam_role_name.as_deref()
    }
}
impl DomainMembership {
    /// Creates a new builder-style object to manufacture [`DomainMembership`](crate::types::DomainMembership).
    pub fn builder() -> crate::types::builders::DomainMembershipBuilder {
        crate::types::builders::DomainMembershipBuilder::default()
    }
}

/// A builder for [`DomainMembership`](crate::types::DomainMembership).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DomainMembershipBuilder {
    pub(crate) domain: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) fqdn: ::std::option::Option<::std::string::String>,
    pub(crate) iam_role_name: ::std::option::Option<::std::string::String>,
}
impl DomainMembershipBuilder {
    /// <p>The identifier of the Active Directory Domain.</p>
    pub fn domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Active Directory Domain.</p>
    pub fn set_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain = input;
        self
    }
    /// <p>The identifier of the Active Directory Domain.</p>
    pub fn get_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain
    }
    /// <p>The status of the DB instance's Active Directory Domain membership, such as joined, pending-join, failed etc).</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the DB instance's Active Directory Domain membership, such as joined, pending-join, failed etc).</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the DB instance's Active Directory Domain membership, such as joined, pending-join, failed etc).</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>The fully qualified domain name of the Active Directory Domain.</p>
    pub fn fqdn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fqdn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The fully qualified domain name of the Active Directory Domain.</p>
    pub fn set_fqdn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fqdn = input;
        self
    }
    /// <p>The fully qualified domain name of the Active Directory Domain.</p>
    pub fn get_fqdn(&self) -> &::std::option::Option<::std::string::String> {
        &self.fqdn
    }
    /// <p>The name of the IAM role to be used when making API calls to the Directory Service.</p>
    pub fn iam_role_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iam_role_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the IAM role to be used when making API calls to the Directory Service.</p>
    pub fn set_iam_role_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iam_role_name = input;
        self
    }
    /// <p>The name of the IAM role to be used when making API calls to the Directory Service.</p>
    pub fn get_iam_role_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.iam_role_name
    }
    /// Consumes the builder and constructs a [`DomainMembership`](crate::types::DomainMembership).
    pub fn build(self) -> crate::types::DomainMembership {
        crate::types::DomainMembership {
            domain: self.domain,
            status: self.status,
            fqdn: self.fqdn,
            iam_role_name: self.iam_role_name,
        }
    }
}
