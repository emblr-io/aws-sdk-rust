// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteCustomDomainAssociationInput {
    /// <p>The identifier of the cluster to delete a custom domain association for.</p>
    pub cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The custom domain name for the custom domain association.</p>
    pub custom_domain_name: ::std::option::Option<::std::string::String>,
}
impl DeleteCustomDomainAssociationInput {
    /// <p>The identifier of the cluster to delete a custom domain association for.</p>
    pub fn cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.cluster_identifier.as_deref()
    }
    /// <p>The custom domain name for the custom domain association.</p>
    pub fn custom_domain_name(&self) -> ::std::option::Option<&str> {
        self.custom_domain_name.as_deref()
    }
}
impl DeleteCustomDomainAssociationInput {
    /// Creates a new builder-style object to manufacture [`DeleteCustomDomainAssociationInput`](crate::operation::delete_custom_domain_association::DeleteCustomDomainAssociationInput).
    pub fn builder() -> crate::operation::delete_custom_domain_association::builders::DeleteCustomDomainAssociationInputBuilder {
        crate::operation::delete_custom_domain_association::builders::DeleteCustomDomainAssociationInputBuilder::default()
    }
}

/// A builder for [`DeleteCustomDomainAssociationInput`](crate::operation::delete_custom_domain_association::DeleteCustomDomainAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteCustomDomainAssociationInputBuilder {
    pub(crate) cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) custom_domain_name: ::std::option::Option<::std::string::String>,
}
impl DeleteCustomDomainAssociationInputBuilder {
    /// <p>The identifier of the cluster to delete a custom domain association for.</p>
    /// This field is required.
    pub fn cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the cluster to delete a custom domain association for.</p>
    pub fn set_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_identifier = input;
        self
    }
    /// <p>The identifier of the cluster to delete a custom domain association for.</p>
    pub fn get_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_identifier
    }
    /// <p>The custom domain name for the custom domain association.</p>
    /// This field is required.
    pub fn custom_domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The custom domain name for the custom domain association.</p>
    pub fn set_custom_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_domain_name = input;
        self
    }
    /// <p>The custom domain name for the custom domain association.</p>
    pub fn get_custom_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_domain_name
    }
    /// Consumes the builder and constructs a [`DeleteCustomDomainAssociationInput`](crate::operation::delete_custom_domain_association::DeleteCustomDomainAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_custom_domain_association::DeleteCustomDomainAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_custom_domain_association::DeleteCustomDomainAssociationInput {
            cluster_identifier: self.cluster_identifier,
            custom_domain_name: self.custom_domain_name,
        })
    }
}
